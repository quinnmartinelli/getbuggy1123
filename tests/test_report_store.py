"""Saved reports (report_store.py): off by default, never breaks a finished
report, honors the 30-day retention, and lets check-status serve a report
after the in-memory job is gone. Uses a fake collection — no database
needed; a real MongoDB run is documented in PROJECT_STATUS.md."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import report_store
import server


class FakeCollection:
    def __init__(self, fail=False):
        self.docs = {}
        self.fail = fail

    def insert_one(self, doc):
        if self.fail:
            raise ConnectionError("database unreachable")
        self.docs[doc["_id"]] = doc

    def find_one(self, query, projection=None):
        if self.fail:
            raise ConnectionError("database unreachable")
        for doc in self.docs.values():
            matches = all(doc.get(k) == v for k, v in query.items() if k != "created_at")
            if matches and doc["created_at"] >= query["created_at"]["$gte"]:
                return doc
        return None

    def delete_many(self, query):
        old = [k for k, d in self.docs.items() if d["created_at"] < query["created_at"]["$lt"]]
        for k in old:
            del self.docs[k]
        return SimpleNamespace(deleted_count=len(old))


@pytest.fixture
def store(monkeypatch):
    collection = FakeCollection()
    monkeypatch.setattr(report_store, "_get_collection", lambda: collection)
    return collection


def test_off_without_mongodb_uri(monkeypatch):
    monkeypatch.setattr(report_store, "MONGODB_URI", None)
    monkeypatch.setattr(report_store, "_collection", None)
    report_store.save_report("job1", "https://example.com", {"summary": "ok"})
    assert report_store.get_report("job1") is None


def test_saved_report_round_trips_without_visitor_details(store):
    report_store.save_report("job1", "https://example.com", {"summary": "ok"})
    assert report_store.get_report("job1") == {"summary": "ok"}
    assert set(store.docs["job1"]) == {"_id", "url", "result", "created_at"}


def test_report_older_than_30_days_is_never_served(store):
    report_store.save_report("old", "https://example.com", {"summary": "ok"})
    store.docs["old"]["created_at"] = datetime.now(timezone.utc) - timedelta(days=31)
    assert report_store.get_report("old") is None


def test_database_failure_never_raises(monkeypatch, capsys):
    monkeypatch.setattr(report_store, "_get_collection", lambda: FakeCollection(fail=True))
    report_store.save_report("job1", "https://secret-site.example", {"summary": "ok"})
    assert report_store.get_report("job1") is None
    logged = capsys.readouterr().err
    assert "save failed (ConnectionError)" in logged
    assert "secret-site" not in logged


def test_check_status_falls_back_to_saved_report(store):
    report_store.save_report("gone-from-memory", "https://example.com", {"summary": "ok"})
    client = TestClient(server.app)
    resp = client.get("/api/check-status/gone-from-memory")
    assert resp.status_code == 200
    assert resp.json() == {"status": "done", "result": {"summary": "ok"}}
    assert client.get("/api/check-status/never-existed").status_code == 404
