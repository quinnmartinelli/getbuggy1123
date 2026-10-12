"""A crawl that hits the time cap (or whose worker dies mid-crawl) must
come back as a partial report, never a bare error — the fix for the known
gap where a timed-out crawl returned only "took longer than N seconds."
Exercises server._run_crawl_job (real subprocess, real watchdog, real line
parsing) against tests/fake_crawl_worker.py — no browser needed."""
import threading

import pytest

import core
import server


@pytest.fixture(autouse=True)
def fake_worker(monkeypatch):
    monkeypatch.setattr(server, "CRAWL_WORKER_SCRIPT", "tests/fake_crawl_worker.py")


def run_job(mode, timeout_seconds=30):
    job_id = f"test-{mode}"
    server._check_semaphore.acquire()
    server._jobs[job_id] = {
        "status": "running", "phase": "finding_pages", "pages_checked": 0,
        "pages_total": None, "pages_found_total": None, "pages_selected": [],
        "pages_skipped": [], "pages_done": [], "result": None, "detail": None,
        "created_at": 0, "authorized": True,
    }
    server._run_crawl_job(job_id, mode, 5, timeout_seconds=timeout_seconds)
    return server._jobs.pop(job_id)


def test_time_cap_returns_partial_report_not_error():
    job = run_job("hang", timeout_seconds=3)
    assert job["status"] == "done"
    r = job["result"]
    assert r["partial"] is True
    assert r["partial_reason"] == "time_cap"
    assert r["pages_checked"] == 2 and r["pages_planned"] == 5
    assert [p["url"] for p in r["pages"]] == ["https://x.com/p0", "https://x.com/p1"]  # priority order
    assert r["pages_not_checked_in_time"] == ["https://x.com/p2", "https://x.com/p3", "https://x.com/p4"]
    assert r["pages_found_total"] == 37
    assert r["site_findings"][0]["category"] == "Sitemap Lists Missing Pages"
    assert r["summary"].startswith("Partial report — 2 of 5 pages checked before the 3-second time limit")


def test_time_cap_before_discovery_finishes_says_so():
    job = run_job("slow_discovery", timeout_seconds=2)
    assert job["status"] == "done"
    assert job["result"]["partial"] is True
    assert job["result"]["pages_checked"] == 0
    assert "ran out of time" in job["result"]["summary"]


def test_worker_dying_after_some_pages_still_returns_them():
    job = run_job("die")
    assert job["status"] == "done"
    assert job["result"]["partial"] is True
    assert job["result"]["partial_reason"] == "worker_stopped"
    assert job["result"]["pages_checked"] == 2


def test_worker_dying_with_nothing_is_a_plain_error():
    job = run_job("die_early")
    assert job["status"] == "error"
    assert "boom" in job["detail"]


def test_normal_crawl_is_not_partial_and_streams_progress():
    job = run_job("ok")
    assert job["status"] == "done"
    assert not job["result"].get("partial")
    assert job["result"]["pages_checked"] == 5
    assert job["pages_total"] == 5 and job["pages_found_total"] == 37
    assert len(job["pages_done"]) == 5
    assert job["result"]["summary"].startswith("Checked 5 of 37 page(s)")
    assert "coming with Pro" in job["result"]["summary"]


def test_worker_dying_after_site_checks_returns_them_not_an_error():
    # Step 8: "never return a bare error if any check finished" — the
    # site-wide checks run before any page, so they count.
    job = run_job("die_after_meta")
    assert job["status"] == "done"
    r = job["result"]
    assert r["partial"] is True and r["partial_reason"] == "worker_stopped"
    assert r["pages_checked"] == 0
    assert r["site_findings"][0]["category"] == "Sitemap Lists Missing Pages"
    assert "stopped unexpectedly" in r["summary"]
    assert r["score"]["value"] is None and "couldn't open any pages" in r["score"]["reason"]
    assert any("weren't checked" in item for item in r["not_completed"])


def test_unreadable_final_result_still_returns_the_pages():
    job = run_job("bad_result")
    assert job["status"] == "done"
    assert job["result"]["partial"] is True
    assert job["result"]["pages_checked"] == 5


def test_partial_report_is_scored_and_labelled():
    r = run_job("hang", timeout_seconds=3)["result"]
    assert r["score"]["partial"] is True
    assert "partial" in r["score"]["basis"]
    assert r["score"]["value"] == 95  # the one MEDIUM site-wide finding
    assert r["not_completed"] == ["3 pages weren't checked before the time limit ran out "
                                  "(listed at the bottom of the report)."]
    assert r["report_id"] and r["checked_at"] and r["url"] == "hang"


def test_the_semaphore_slot_is_always_released():
    before = server._check_semaphore._value
    run_job("hang", timeout_seconds=2)
    run_job("die_early")
    assert server._check_semaphore._value == before


def _fake_problem(category):
    return {"category": category, "message": "x", "severity": "low", "confidence": "verified"}


def test_summary_lines():
    # Two distinct (category, evidence) problems on one page, none on the
    # other — dedupe_site_problems (see core.py) counts them as 2 unique
    # problems, same as the old raw count would have here since neither
    # recurs.
    base = {
        "pages": [
            {"url": "https://x.com/", "problems": [_fake_problem("A"), _fake_problem("B")]},
            {"url": "https://x.com/2", "problems": []},
        ],
        "pages_found_total": 2, "pages_checked": 2, "site_findings": [],
    }
    assert core.summarize_site_check(base) == "Checked 2 of 2 page(s) — 2 problem(s) on 1 page(s)"
    with_site = dict(base, site_findings=[{}])
    assert core.summarize_site_check(with_site).endswith("plus 1 site-wide problem(s)")
    unopened = dict(base, pages=[
        {"url": "https://x.com/", "problems": [], "could_not_load": True},
        {"url": "https://x.com/2", "problems": []},
    ])
    assert "1 page(s) couldn't be opened" in core.summarize_site_check(unopened)
    failed = dict(unopened, partial=True, partial_reason="pages_failed", pages_planned=2)
    assert core.summarize_site_check(failed).startswith(
        "Partial report — 1 of 2 pages could be opened and checked")
