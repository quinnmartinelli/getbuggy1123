"""Step 8 server behaviour: the queue at the concurrency cap, permalinks
(always ownership-gated), the "send to your web person" export, re-check
deltas, and the 30-day deletion job. Runs the real job runner against
tests/fake_crawl_worker.py — no browser."""
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import report_store
import server

REPORT_FIELDS_HIDDEN = ("Secret Key", "sk_l")


@pytest.fixture(autouse=True)
def clean_server(monkeypatch):
    monkeypatch.setattr(server, "CRAWL_WORKER_SCRIPT", "tests/fake_crawl_worker.py")
    monkeypatch.setattr(server, "validate_public_url", lambda url: None)
    monkeypatch.setattr(report_store, "MONGODB_URI", None)
    monkeypatch.setattr(report_store, "_collection", None)
    server._global_run_times.clear()
    server._ip_run_times.clear()
    server._queue.clear()
    yield
    server._queue.clear()
    server._jobs.clear()
    server._global_run_times.clear()
    server._ip_run_times.clear()


@pytest.fixture
def client():
    return TestClient(server.app)


def start(client, url="https://x.com/?mode=ok", **extra):
    resp = client.post("/api/check", json=dict({"url": url, "authorized": True}, **extra))
    assert resp.status_code == 200, resp.text
    return resp.json()


def wait_done(client, job_id, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/check-status/{job_id}").json()
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.1)
    raise AssertionError(f"job {job_id} never finished")


def fill_all_slots():
    held = 0
    while server._check_semaphore.acquire(blocking=False):
        held += 1
    return held


# --- queue ---------------------------------------------------------------------

def test_at_the_cap_a_check_is_queued_with_position_and_wait(client):
    held = fill_all_slots()
    try:
        first = start(client)
        second = start(client)
        assert first["status"] == "queued" and first["queue_position"] == 1
        assert second["queue_position"] == 2
        status = client.get(f"/api/check-status/{second['job_id']}").json()
        assert status["status"] == "queued"
        assert status["queue_position"] == 2
        assert status["estimated_wait_seconds"] > 0
        assert "You're 2nd in line" in status["queue_message"]
        assert "minute" in status["queue_message"]

        # A slot frees up: the oldest waiting check starts by itself.
        server._release_slot()
        held -= 1
        assert wait_done(client, first["job_id"])["status"] == "done"
        assert wait_done(client, second["job_id"])["status"] == "done"
    finally:
        for _ in range(held):
            server._release_slot()


def test_a_full_queue_says_so_in_plain_english(client, monkeypatch):
    monkeypatch.setattr(server, "MAX_QUEUE_LENGTH", 0)
    held = fill_all_slots()
    try:
        resp = client.post("/api/check", json={"url": "https://x.com/?mode=ok", "authorized": True})
        assert resp.status_code == 429
        assert "very busy" in resp.json()["detail"] and "try again in a few minutes" in resp.json()["detail"]
        assert not server._global_run_times  # a turned-away check isn't counted
    finally:
        for _ in range(held):
            server._release_slot()


def test_wait_estimate_uses_recent_crawl_times(monkeypatch):
    monkeypatch.setattr(server, "MAX_CONCURRENT_CHECKS", 2)
    monkeypatch.setattr(server, "_recent_crawl_seconds", __import__("collections").deque([60, 120]))
    assert server.estimate_wait_seconds(1) == 90
    assert server.estimate_wait_seconds(3) == 180


# --- permalink -------------------------------------------------------------------

def test_finished_report_has_a_permalink_that_renders(client):
    job = wait_done(client, start(client)["job_id"])
    report_id = job["result"]["report_id"]
    assert report_id != job.get("job_id") and len(report_id) >= 16
    page = client.get(f"/r/{report_id}")
    assert page.status_code == 200 and "<html" in page.text.lower()
    shared = client.get(f"/api/report/{report_id}").json()
    assert shared["status"] == "done"
    assert shared["result"]["score"]["value"] == 95
    assert shared["result"]["url"] == "https://x.com/?mode=ok"


def test_unknown_or_malformed_permalink_is_a_plain_404(client):
    for rid in ("doesnotexist1234567890", "bad.id.with.dots.1234", "x"):
        resp = client.get(f"/api/report/{rid}")
        assert resp.status_code == 404
        assert "deleted 30 days" in resp.json()["detail"]


def _plant_security_finding(job_id):
    finding = {"category": "Secret Key Exposed In Page Source", "message": "sk_l•••• in page",
               "severity": "high", "confidence": "verified", "group": "security",
               "evidence": "sk_l••••••••", "pages": ["https://x.com/"]}
    with server._jobs_lock:
        server._jobs[job_id]["result"]["unique_problems"] = [finding]


def test_permalink_and_export_are_gated_even_with_the_details_flag_on(client, monkeypatch):
    monkeypatch.setenv("GETBUGGY_SHOW_SECURITY_DETAILS", "true")
    job_id = start(client)["job_id"]
    job = wait_done(client, job_id)
    _plant_security_finding(job_id)
    report_id = job["result"]["report_id"]

    # The owner's own check-status shows details when the flag is on...
    owner = client.get(f"/api/check-status/{job_id}").json()
    assert "Secret Key" in str(owner)
    # ...but the shareable link and the export never do.
    shared = client.get(f"/api/report/{report_id}").json()
    exported = client.get(f"/api/report/{report_id}/export")
    for text in (str(shared), exported.text):
        for hidden in REPORT_FIELDS_HIDDEN:
            assert hidden not in text
    assert shared["result"]["security_summary"]["count"] == 1
    assert exported.headers["content-type"].startswith("text/markdown")
    assert f"/r/{report_id}" in exported.text
    assert "We found 1 possible security exposure" in exported.text


def test_saved_reports_are_found_by_permalink_after_leaving_memory(client, monkeypatch):
    from tests.test_report_store import FakeCollection

    collection = FakeCollection()
    monkeypatch.setattr(report_store, "_get_collection", lambda: collection)
    job_id = start(client)["job_id"]
    report_id = wait_done(client, job_id)["result"]["report_id"]
    assert collection.docs[job_id]["report_id"] == report_id
    server._jobs.clear()  # pruned / server restarted
    assert client.get(f"/api/report/{report_id}").json()["result"]["report_id"] == report_id


# --- re-check delta -------------------------------------------------------------------

def test_recheck_of_the_same_site_shows_the_score_change(client):
    first = wait_done(client, start(client)["job_id"])["result"]
    second = wait_done(client, start(client, previous_report_id=first["report_id"])["job_id"])["result"]
    change = second["score"]["change"]
    assert change["previous_value"] == first["score"]["value"] and change["delta"] == 0
    assert change["message"].startswith("No change since your last check")


def test_recheck_pointing_at_another_site_is_ignored(client):
    first = wait_done(client, start(client)["job_id"])["result"]
    other = wait_done(client, start(client, url="https://y.com/?mode=ok",
                                     previous_report_id=first["report_id"])["job_id"])["result"]
    assert "change" not in other["score"]


# --- 30-day deletion job -----------------------------------------------------------------

def test_purge_deletes_reports_older_than_30_days(monkeypatch):
    from tests.test_report_store import FakeCollection

    collection = FakeCollection()
    monkeypatch.setattr(report_store, "_get_collection", lambda: collection)
    report_store.save_report("old", "https://x.com", {"report_id": "o" * 22})
    report_store.save_report("new", "https://x.com", {"report_id": "n" * 22})
    collection.docs["old"]["created_at"] = datetime.now(timezone.utc) - timedelta(days=31)
    assert server.run_purge_once() == 1
    assert set(collection.docs) == {"new"}


def test_purge_drops_finished_jobs_from_memory_but_never_queued_ones():
    long_ago = time.time() - server.JOB_TTL_SECONDS - 60
    server._jobs.update({
        "done-old": {"status": "done", "created_at": long_ago},
        "queued-old": {"status": "queued", "created_at": long_ago},
        "done-new": {"status": "done", "created_at": time.time()},
    })
    server.run_purge_once()
    assert set(server._jobs) == {"queued-old", "done-new"}


def test_purge_is_a_no_op_without_a_database():
    assert report_store.purge_expired() == 0
