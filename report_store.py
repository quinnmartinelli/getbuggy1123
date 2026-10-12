"""Saved reports — the "report retention is 30 days" decision in PLAN.md,
stored in MongoDB (Atlas on the live service).

Off unless MONGODB_URI is set: with no URI, save_report() does nothing and
get_report() returns None, so local dev, CI and any deploy that hasn't
configured a database behave exactly as before (in-memory jobs only), and
nothing connects anywhere by default.

A saved report is the finished result plus the URL it was for and when it
was made — no IP address, nothing about the visitor. Deletion after 30 days
happens two ways, so it never depends on just one: MongoDB's own TTL index
on `created_at` (its sweep runs about once a minute), and purge_expired()
below, the deletion job server.py runs at startup and then every hour
(also runnable by hand: `python report_store.py purge`). Nothing past 30
days is ever served, even in the gap before either runs.

Lookup is by the job id (held only by the browser that started the check)
or by the report's permalink id (Step 8: a separate random token, so
sharing a report link never gives anyone the job id — see server.py).
There is deliberately no "list reports" or per-site history, which is a
Pro feature (PLAN.md)."""
import os
import sys
import threading
from datetime import datetime, timedelta, timezone

MONGODB_URI = os.environ.get("MONGODB_URI")
MONGODB_DB_NAME = os.environ.get("MONGODB_DB_NAME", "getbuggy")

# Not an env var on purpose: the privacy policy (legal/privacy-policy.md §5)
# promises 30 days, so changing this means changing that promise too.
REPORT_RETENTION_DAYS = 30
REPORT_RETENTION_SECONDS = REPORT_RETENTION_DAYS * 24 * 60 * 60

_collection = None
_collection_lock = threading.Lock()


def _log(message):
    # Never includes the site URL or the database URI (which holds the
    # password) — just what went wrong, by exception class.
    print(f"REPORT_STORE {message}", file=sys.stderr, flush=True)


def _get_collection():
    """The `reports` collection, connected on first use, or None when
    storage is off. A failed connection isn't cached, so the next save
    simply tries again."""
    global _collection
    if not MONGODB_URI:
        return None
    with _collection_lock:
        if _collection is None:
            from pymongo import MongoClient

            client = MongoClient(
                MONGODB_URI,
                appname="getbuggy",
                tz_aware=True,
                # Fail fast: a slow or unreachable database must never hold
                # up a finished report for long.
                serverSelectionTimeoutMS=5000,
            )
            collection = client[MONGODB_DB_NAME]["reports"]
            collection.create_index("created_at", expireAfterSeconds=REPORT_RETENTION_SECONDS)
            collection.create_index("report_id", unique=True, sparse=True)
            _collection = collection
    return _collection


def _cutoff():
    return datetime.now(timezone.utc) - timedelta(seconds=REPORT_RETENTION_SECONDS)


def save_report(job_id, url, result):
    """Stores a finished report. Never raises — a database problem must not
    turn a finished report into an error for the person waiting on it."""
    try:
        collection = _get_collection()
        if collection is None:
            return
        doc = {
            "_id": job_id,
            "url": url,
            "result": result,
            "created_at": datetime.now(timezone.utc),
        }
        if result.get("report_id"):
            doc["report_id"] = result["report_id"]
        collection.insert_one(doc)
    except Exception as e:
        _log(f"save failed ({e.__class__.__name__})")


def _find_result(query):
    try:
        collection = _get_collection()
        if collection is None:
            return None
        doc = collection.find_one(dict(query, created_at={"$gte": _cutoff()}), {"result": 1})
        return doc["result"] if doc else None
    except Exception as e:
        _log(f"read failed ({e.__class__.__name__})")
        return None


def get_report(job_id):
    """The saved result for a job id, or None if storage is off, there's no
    such report, or it's past 30 days (MongoDB's TTL sweep runs about once
    a minute, so an expired report can linger briefly — never served)."""
    return _find_result({"_id": job_id})


def get_report_by_report_id(report_id):
    """The saved result for a permalink id (same rules as get_report)."""
    return _find_result({"report_id": report_id})


def purge_expired():
    """The 30-day deletion job: deletes every saved report older than 30
    days and returns how many went (0 when storage is off). Never raises."""
    try:
        collection = _get_collection()
        if collection is None:
            return 0
        deleted = collection.delete_many({"created_at": {"$lt": _cutoff()}}).deleted_count
        if deleted:
            _log(f"purged {deleted} report(s) older than {REPORT_RETENTION_DAYS} days")
        return deleted
    except Exception as e:
        _log(f"purge failed ({e.__class__.__name__})")
        return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["purge"]:
        print("Usage: python report_store.py purge")
        sys.exit(1)
    if not MONGODB_URI:
        print("MONGODB_URI isn't set, so no reports are stored and there's nothing to purge.")
        sys.exit(0)
    print(f"Deleted {purge_expired()} report(s) older than {REPORT_RETENTION_DAYS} days.")
