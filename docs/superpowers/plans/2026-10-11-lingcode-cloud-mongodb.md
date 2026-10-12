# GetBuggy on LingCode Cloud with MongoDB — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run GetBuggy live on LingCode Cloud. The web server is a LingCode hosted app, crawls run in a LingCode container job with Chromium, and the two hand off through MongoDB Atlas.

**Architecture:** `server.py` gains `CRAWL_MODE=queue`. In that mode it enqueues a `crawl_jobs` record in MongoDB instead of starting a crawl subprocess. A new `crawl_worker.py` (a container job built from the existing `Dockerfile`) claims queued records atomically and runs each one through the same crawl code. That code is extracted from `server._run_crawl_job` into `crawl_runner.py`. With `CRAWL_MODE` unset, everything behaves exactly as today.

**Tech Stack:** Python 3.12, FastAPI, Playwright/Chromium, pymongo 4.18 (MongoDB Atlas), mongomock (tests only), Docker, LingCode Cloud (hosted apps + container compute).

**Spec:** `docs/superpowers/specs/2026-10-11-lingcode-cloud-mongodb-design.md`

## Global Constraints

- With `CRAWL_MODE` unset (or `local`), behaviour is identical to today. Local dev, CI, `regression_check.py` and `docker build .` must not change.
- `CRAWL_MODE` accepts only `local` or `queue`. Anything else fails at startup.
- Server concurrency cap: `MAX_CONCURRENT_CHECKS` (default 2) checks queued or running at once, across all workers.
- 60-second per-page timeout (`PAGE_LOAD_TIMEOUT_MS`, default 60000). 6-minute crawl cap (`CRAWL_TIMEOUT_SECONDS`, default 360) with a partial report on cap. Both unchanged.
- Report retention is 30 days, not configurable. `crawl_jobs` and `workers` records expire after 1 day.
- Never stored in MongoDB: the visitor's IP address, user agent, or any visitor identifier. Never logged: a site URL, an email address, or `MONGODB_URI`.
- Every user-facing string is plain English (the reader owns a bakery). Never a bare status code, never a guessed result.
- `ENABLE_REAL_FORM_SUBMISSION` is never set anywhere in this work.
- Every new fetch of a site-derived URL goes through the existing SSRF guard. This plan adds none; the worker runs `core` unchanged.
- Sentry stays a no-op unless `SENTRY_DSN` is set.
- Security findings are ownership-gated. Every report payload leaving the server goes through `checks_security.redact_security_details` unless `show_security_details()` is true. Today that is only `/api/check-status`, for both the in-memory and queue branches and the `report_store` fallback; any new route that returns report data must be gated too. The worker and queue never serve reports directly. `static/index.html`'s `security-card` and `security-badge` blocks stay untouched. `tests/test_checks_security.py::test_check_status_gates_details_unless_flag_is_set` must keep passing.
- Run `pytest tests/ -v` and `python regression_check.py --skip-live` before every commit that touches crawl code. Both must pass.
- Staleness thresholds, verbatim from the spec: a running job is stale after 60 s without a heartbeat (heartbeat every 10 s). A queued job is abandoned after 180 s unclaimed. A worker is healthy if seen within 90 s with `browser_ok: true`. The worker claims for `WORKER_CLAIM_WINDOW_SECONDS` (default 2100) and is scheduled `*/30 * * * *`.

## Review Focus

1. **A worker dies mid-crawl.** The visitor polling that job should get the plain "stopped unexpectedly… please try again" message within about 60 s, and the slot should free up. Covered by Task 2, `test_stale_running_job_reports_plain_error_and_frees_slot`.
2. **A worker is slow, not dead.** If its job was marked stale but it then finishes, the real report must win over the error. Covered by Task 2, `test_late_finish_after_stale_mark_still_delivers_report`.
3. **MongoDB blips while a visitor is polling.** This must not end their wait while the crawl keeps running. Covered by Task 3: a 503 with a plain message plus the frontend retry, checked by hand in Task 6.
4. **Two checks already active, or MongoDB down at submit.** The visitor gets the plain busy or down message, and no rate-limit budget is spent. Covered by Task 3, `test_third_check_is_refused_while_two_are_active` and `test_database_down_is_plain_english_and_spends_no_budget`.
5. **Security redaction in queue mode.** Queue-mode status responses must still pass through redaction, so no security detail leaks on the public report. Covered by Task 3, `test_queue_status_still_goes_through_security_redaction`.

**Deviation from the spec, recorded here:** the spec said the frontend is unchanged. Reading `static/index.html:1158-1184` showed that any non-OK status poll ends the visitor's wait. Task 3 therefore adds a small change: up to 5 consecutive 503 responses are retried before the message is shown.

---

### Task 0: Version control (prerequisite — ask the founders)

`/Users/weijiahuang/Desktop/website-checker-main` is **not a git repository**, but every task ends in a commit, and `CLAUDE.md` requires small commits.

- [ ] **Step 1: Ask which applies.** Either (a) the founders' real repository exists elsewhere, so clone it and carry out this plan there, after first copying over `docs/superpowers/`. Or (b) initialise version control here:

```bash
cd /Users/weijiahuang/Desktop/website-checker-main
git init
printf 'venv/\n__pycache__/\n*.pyc\n.env\ndist/\nearly_access.csv\n.pytest_cache/\n' > .gitignore
git add -A
git commit -m "Snapshot working copy before LingCode Cloud move

Baseline so the move to LingCode Cloud can be reviewed and undone step by step."
```

- [ ] **Step 2: Confirm the baseline is green before touching anything.**

Run: `venv/bin/pytest tests/ -q && venv/bin/python regression_check.py --skip-live`
Expected: all tests pass and the harness prints PASS for every local target. Paste the tail of the output into the task notes. If anything fails here, stop and report it: it predates this work.

---

### Task 1: Extract the crawl runner (pure refactor)

Moves the crawl subprocess, watchdog and partial-report logic out of `server.py` so the worker can share it. Behaviour does not change: the existing `tests/test_server_partial.py` must pass unmodified.

**Files:**
- Create: `crawl_runner.py`
- Create: `funnel.py`
- Modify: `server.py`: the `_log_funnel_event` definition (~line 48), the `PAGE_LOAD_TIMEOUT_MS`/`CRAWL_TIMEOUT_SECONDS` definitions (~lines 151–165), `build_partial_result` and `_run_crawl_job` (~lines 208–357), and `health` (~lines 496–545)
- Create: `tests/test_crawl_runner.py`

**Interfaces:**
- Produces:
  - `crawl_runner.CrawlOutcome(status: str, result: dict | None, detail: str | None)`, a NamedTuple. `status` is `"done"` or `"error"`.
  - `crawl_runner.run_crawl(url: str, page_cap: int, sink, *, worker_script: str, timeout_seconds: int | None = None, page_load_timeout_ms: int | None = None, cwd: str = BASE_DIR) -> CrawlOutcome`. Never raises. On `"done"`, `result["summary"]` is already set.
  - A sink is any object with `on_meta(meta: dict)`, `on_progress(completed: int, total: int)` and `on_page(index: int, page: dict)`.
  - `crawl_runner.meta_fields(meta: dict) -> dict`: the job fields a META line sets (`phase`, `pages_total`, `pages_found_total`, `pages_selected`, `pages_skipped`, `used_sitemap`). It may raise `KeyError`.
  - `crawl_runner.build_partial_result(meta, pages_done, timeout_seconds, reason) -> dict`, moved verbatim.
  - `crawl_runner.browser_launch_problem(timeout_seconds: int, cwd: str = BASE_DIR) -> str | None`. Returns `None` if Chromium launched, otherwise a plain-English reason.
  - `crawl_runner.CRAWL_TIMEOUT_SECONDS` and `crawl_runner.PAGE_LOAD_TIMEOUT_MS`, the same env vars and defaults as before.
  - `funnel.log_funnel_event(name: str, **fields) -> None`.
  - `server._run_crawl_job(job_id, url, page_cap, timeout_seconds=None)` keeps its signature. `server.build_partial_result`, `server.CRAWL_TIMEOUT_SECONDS`, `server.PAGE_LOAD_TIMEOUT_MS`, `server.CRAWL_WORKER_SCRIPT` and `server._log_funnel_event` remain importable names.

- [ ] **Step 1: Write the failing test** — `tests/test_crawl_runner.py`

```python
"""crawl_runner.run_crawl drives one crawl subprocess and streams it to a
sink — the shared path for server.py (local mode) and crawl_worker.py
(queue mode). The partial-report and time-cap cases are covered through
server._run_crawl_job in test_server_partial.py; these pin the sink
contract itself. Uses tests/fake_crawl_worker.py — no browser."""
import crawl_runner

FAKE = "tests/fake_crawl_worker.py"


class ListSink:
    def __init__(self):
        self.meta = None
        self.progress = []
        self.pages = {}

    def on_meta(self, meta):
        self.meta = meta

    def on_progress(self, completed, total):
        self.progress.append((completed, total))

    def on_page(self, index, page):
        self.pages[index] = page


def test_finished_crawl_streams_everything_and_has_a_summary():
    sink = ListSink()
    outcome = crawl_runner.run_crawl("ok", 5, sink, worker_script=FAKE, timeout_seconds=30)
    assert outcome.status == "done"
    assert outcome.detail is None
    assert outcome.result["summary"].startswith("Checked 5 of 37 page(s)")
    assert sink.meta["pages_planned"] == 5
    assert sorted(sink.pages) == [0, 1, 2, 3, 4]
    assert sink.progress[-1] == (5, 5)


def test_failure_before_any_page_is_an_error_with_the_reason():
    outcome = crawl_runner.run_crawl("die_early", 5, ListSink(), worker_script=FAKE, timeout_seconds=30)
    assert outcome.status == "error"
    assert outcome.result is None
    assert "boom" in outcome.detail


def test_meta_fields_are_what_the_progress_ui_reads():
    meta = {"pages_planned": 5, "pages_found_total": 37, "selected": ["a"],
            "pages_skipped": ["b"], "used_sitemap": True}
    assert crawl_runner.meta_fields(meta) == {
        "phase": "checking_pages", "pages_total": 5, "pages_found_total": 37,
        "pages_selected": ["a"], "pages_skipped": ["b"], "used_sitemap": True,
    }


def test_browser_problem_is_plain_english_when_the_check_cannot_start(tmp_path):
    # An empty directory has no health_check_subprocess.py, so the launch
    # check exits non-zero — the message must say so in words.
    problem = crawl_runner.browser_launch_problem(10, cwd=str(tmp_path))
    assert problem.startswith("Browser could not launch (")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `venv/bin/pytest tests/test_crawl_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawl_runner'`

- [ ] **Step 3: Create `funnel.py`.** Move `_log_funnel_event` out of `server.py` with its docstring.

```python
"""Funnel logging — the URL-pasted -> report-viewed -> email-captured
funnel, as plain, grep-able log lines. Shared by server.py and
crawl_worker.py (in queue mode the report finishes in the worker, so
that's where "report_viewed" is logged)."""
import sys


def log_funnel_event(name, **fields):
    """Plain-English, grep-able log line for the URL-pasted -> report-
    viewed -> email-captured funnel — counts, not per-visitor tracking:
    no cookies, no session/user IDs, nothing that lets one line be tied
    to another from the same visitor. `fields` is for non-identifying
    context only (a job_id, a status) — never a raw URL or email
    address, so a log line alone never identifies who did what."""
    extra = " ".join(f"{k}={v}" for k, v in fields.items())
    print(f"FUNNEL {name} {extra}".rstrip(), file=sys.stderr, flush=True)
```

- [ ] **Step 4: Create `crawl_runner.py`**

```python
"""Runs one whole-site crawl in its own OS process
(run_site_check_subprocess.py) and streams what it finds to a *sink*.

Shared by server.py (local mode: an in-memory job dict) and
crawl_worker.py (queue mode: a MongoDB job record — see job_queue.py), so
the 6-minute cap, the watchdog that kills the whole process group, and the
partial report on cap live in exactly one place.

A sink is any object with:
    on_meta(meta)                  discovery finished (a META line)
    on_progress(completed, total)  a page finished (a PROGRESS line)
    on_page(index, page)           that page's result (a PAGE line)
Sinks must not raise for ordinary failures — a failed progress write is
the sink's to log and drop."""
import json
import os
import signal
import subprocess
import sys
import threading
from typing import NamedTuple

from core import summarize_site_check, dedupe_site_problems
from checks_accessibility import accessibility_summary

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Per-page load timeout — 60s per CLAUDE.md's standing rule ("the 60-second
# timeout is per page"). Passed to the crawl subprocess as a CLI argument
# (see run_site_check_subprocess.py); core.py's own defaults (used by the
# CLI and regression harness, which don't go through this module) match.
PAGE_LOAD_TIMEOUT_MS = int(os.environ.get("PAGE_LOAD_TIMEOUT_MS", "60000"))

# A hard ceiling on how long a whole-site check is allowed to run — a flat
# 6 minutes regardless of CRAWL_PAGE_CAP. This is a promise to the person
# waiting on the report ("this won't take more than 6 minutes"), not a
# per-page time budget, so it deliberately does NOT scale with page count.
# Enforced by killing the crawl's whole process group (see run_crawl).
CRAWL_TIMEOUT_SECONDS = int(os.environ.get("CRAWL_TIMEOUT_SECONDS", "360"))


class CrawlOutcome(NamedTuple):
    status: str            # "done" or "error"
    result: dict | None    # the finished (or partial) report when "done"
    detail: str | None     # plain-English reason when "error"


def meta_fields(meta):
    """The job fields a META line updates — identical in memory (server.py)
    and in MongoDB (crawl_worker.py), since both feed the same progress UI."""
    return {
        "phase": "checking_pages",
        "pages_total": meta["pages_planned"],
        "pages_found_total": meta["pages_found_total"],
        "pages_selected": meta["selected"],
        "pages_skipped": meta["pages_skipped"],
        "used_sitemap": meta["used_sitemap"],
    }


# --- build_partial_result: MOVE VERBATIM from server.py (docstring and all) ---
# def build_partial_result(meta, pages_done, timeout_seconds, reason): ...


def run_crawl(url, page_cap, sink, *, worker_script, timeout_seconds=None,
              page_load_timeout_ms=None, cwd=BASE_DIR):
    """Runs the crawl to completion (or to the time cap) and returns a
    CrawlOutcome. Never raises."""
    timeout_seconds = timeout_seconds or CRAWL_TIMEOUT_SECONDS
    page_load_timeout_ms = page_load_timeout_ms or PAGE_LOAD_TIMEOUT_MS
    try:
        # Own OS process, own process group (start_new_session=True):
        # specifically so that if it has to be killed for running too
        # long, its Chromium child process is killed along with it rather
        # than left running as an orphan.
        proc = subprocess.Popen(
            [sys.executable, worker_script, url, str(page_cap), str(page_load_timeout_ms)],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except Exception as e:
        return CrawlOutcome("error", None, f"Could not start the checker process ({e.__class__.__name__}).")

    # Kills the process (and its process group) if it's still running
    # after the time cap, independent of whatever the main reading loop
    # below is doing — that loop just reads lines until the pipe closes,
    # which happens whether the process exits normally or gets killed here.
    timed_out = threading.Event()

    def _watchdog():
        try:
            proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out.set()
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass

    threading.Thread(target=_watchdog, daemon=True).start()

    meta = None
    pages_done = {}
    try:
        result_json = None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                if line.startswith("PROGRESS "):
                    _, completed, total = line.split(" ", 2)
                    sink.on_progress(int(completed), int(total))
                elif line.startswith("META "):
                    meta = json.loads(line[len("META "):])
                    sink.on_meta(meta)
                elif line.startswith("PAGE "):
                    _, index, page_json = line.split(" ", 2)
                    page = json.loads(page_json)
                    pages_done[int(index)] = page
                    sink.on_page(int(index), page)
                elif line.startswith("RESULT "):
                    result_json = line[len("RESULT "):]
            except (ValueError, KeyError):
                pass  # one malformed progress line must never sink the crawl

        proc.wait()
        stderr_output = proc.stderr.read()

        if timed_out.is_set():
            result = build_partial_result(meta, pages_done, timeout_seconds, "time_cap")
        elif proc.returncode != 0 or result_json is None:
            if not pages_done:
                return CrawlOutcome(
                    "error", None,
                    stderr_output.strip() or "The checker process failed unexpectedly.",
                )
            # The worker died mid-crawl (e.g. the host killed it for memory)
            # after real pages were checked — hand those back, marked partial.
            result = build_partial_result(meta, pages_done, timeout_seconds, "worker_stopped")
        else:
            try:
                result = json.loads(result_json)
            except json.JSONDecodeError:
                return CrawlOutcome("error", None, "The checker process returned an unexpected response.")

        result["summary"] = summarize_site_check(result)
        return CrawlOutcome("done", result, None)
    except Exception as e:
        return CrawlOutcome("error", None, f"Unexpected error while checking ({e.__class__.__name__}).")


def browser_launch_problem(timeout_seconds, cwd=BASE_DIR):
    """None if a real headless Chromium launched and closed; otherwise a
    plain-English reason. Runs health_check_subprocess.py in its own
    process group (same safety pattern as the crawl subprocess), so a hung
    or crashed launch can be killed outright and never affects the caller.
    Used by GET /health in local mode and by the worker's startup
    self-test in queue mode."""
    try:
        proc = subprocess.Popen(
            [sys.executable, "health_check_subprocess.py"],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except Exception as e:
        return f"Could not start the browser-launch check ({e.__class__.__name__})."

    try:
        _, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        return f"Browser launch check timed out after {timeout_seconds}s."

    if proc.returncode != 0:
        return f"Browser could not launch ({(stderr or '').strip() or 'unknown error'})."
    return None
```

Then cut `build_partial_result` (the whole function and its docstring) from `server.py` and paste it where the `MOVE VERBATIM` comment is, replacing the comment.

- [ ] **Step 5: Rewire `server.py` to use the runner**

(a) Replace the `_log_funnel_event` definition with an import (keeps the old name for existing callers):

```python
from funnel import log_funnel_event as _log_funnel_event
```

(b) Replace the `PAGE_LOAD_TIMEOUT_MS` and `CRAWL_TIMEOUT_SECONDS` definitions, and their comment blocks, with:

```python
# Per-page timeout and the 6-minute crawl cap now live in crawl_runner.py
# (shared with the queue worker); re-exported here under the same names.
import crawl_runner
from crawl_runner import build_partial_result, CRAWL_TIMEOUT_SECONDS, PAGE_LOAD_TIMEOUT_MS
```

(c) Replace the whole `_run_crawl_job` function with:

```python
class _MemorySink:
    """Streams a local-mode crawl into its in-memory _jobs entry."""

    def __init__(self, job_id):
        self.job_id = job_id

    def on_meta(self, meta):
        fields = crawl_runner.meta_fields(meta)
        with _jobs_lock:
            _jobs[self.job_id].update(fields)

    def on_progress(self, completed, total):
        with _jobs_lock:
            _jobs[self.job_id]["pages_checked"] = completed
            _jobs[self.job_id]["pages_total"] = total

    def on_page(self, index, page):
        with _jobs_lock:
            _jobs[self.job_id]["pages_done"].append(dict(page, index=index))


def _run_crawl_job(job_id, url, page_cap, timeout_seconds=None):
    try:
        outcome = crawl_runner.run_crawl(
            url, page_cap, _MemorySink(job_id),
            worker_script=CRAWL_WORKER_SCRIPT,
            timeout_seconds=timeout_seconds or CRAWL_TIMEOUT_SECONDS,
            page_load_timeout_ms=PAGE_LOAD_TIMEOUT_MS,
            cwd=BASE_DIR,
        )
        with _jobs_lock:
            _jobs[job_id]["status"] = outcome.status
            _jobs[job_id]["result"] = outcome.result
            _jobs[job_id]["detail"] = outcome.detail
        if outcome.status == "done":
            report_store.save_report(job_id, url, outcome.result)
            # Funnel stage 2 of 3 (see funnel.py): approximated server-side
            # as "the report finished and was available to be shown".
            _log_funnel_event("report_viewed", job=job_id)
    finally:
        _check_semaphore.release()
```

(d) Replace the body of `health()` after its docstring (keep the docstring) with:

```python
    problem = crawl_runner.browser_launch_problem(HEALTH_CHECK_TIMEOUT_SECONDS, cwd=BASE_DIR)
    if problem:
        raise HTTPException(status_code=503, detail=problem)
    return {"status": "ok"}
```

(e) Remove imports that are now unused. Check each one first: run `grep -n "signal\.\|dedupe_site_problems\|accessibility_summary\|summarize_site_check" server.py` and delete only the import names with no remaining use. `subprocess` stays, because `_get_git_commit` uses it.

- [ ] **Step 6: Run the new and the existing tests**

Run: `venv/bin/pytest tests/test_crawl_runner.py tests/test_server_partial.py tests/test_report_store.py tests/test_rate_limiting.py -v`
Expected: all PASS. `test_server_partial.py` is unmodified and still passes, which proves the refactor kept behaviour.

- [ ] **Step 7: Full suite and harness** (this touches crawl code)

Run: `venv/bin/pytest tests/ -q && venv/bin/python regression_check.py --skip-live`
Expected: all pass, with every local target PASS and no baseline changes.

- [ ] **Step 8: Commit**

```bash
git add crawl_runner.py funnel.py server.py tests/test_crawl_runner.py
git commit -m "Extract crawl runner from server.py

The crawl subprocess, 6-minute watchdog and partial report move to
crawl_runner.py so a queue worker can share them. No behaviour change;
harness baselines unchanged."
```

---

### Task 2: MongoDB job queue

**Files:**
- Create: `job_queue.py`
- Create: `tests/test_job_queue.py`
- Modify: `requirements-dev.txt` (add `mongomock`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces (all raise `job_queue.QueueUnavailable` when MongoDB is off or unreachable; `now` is a float `time.time()` value, defaulting to the current time):
  - `QUEUED`, `RUNNING`, `DONE`, `ERROR`: the status strings `"queued"`, `"running"`, `"done"`, `"error"`.
  - `STALE_MESSAGE`, `UNCLAIMED_MESSAGE`: plain-English strings.
  - `HEARTBEAT_STALE_SECONDS = 60`, `UNCLAIMED_TIMEOUT_SECONDS = 180`, `WORKER_FRESH_SECONDS = 90`.
  - `enqueue(job_id: str, url: str, page_cap: int, authorized: bool = True, now=None) -> None`
  - `active_count(now=None) -> int`: queued but not abandoned, plus running and not stale.
  - `claim_next(worker_id: str, now=None) -> dict | None`: the claimed job document (with `_id`, `url`, `page_cap`), or None.
  - `heartbeat(worker_id: str, now=None) -> None`
  - `update_job(job_id: str, worker_id: str, fields: dict) -> None`
  - `add_page(job_id: str, worker_id: str, page: dict) -> None`
  - `finish(job_id: str, worker_id: str, result: dict) -> None`
  - `fail(job_id: str, worker_id: str, detail: str) -> None`
  - `expire_overdue(now=None) -> int`
  - `get_status_payload(job_id: str, now=None) -> dict | None`. This is today's `/api/check-status` shape; a queued job is reported as `status: "running"`.
  - `worker_seen(worker_id: str, browser_ok: bool, browser_detail: str | None, now=None) -> None`
  - `healthy_worker_exists(now=None) -> bool`
  - `_get_db()` and `_ensure_indexes(db)`: tests monkeypatch `_get_db`.

- [ ] **Step 1: Add the test dependency.** Append to `requirements-dev.txt`:

```
# In-memory stand-in for MongoDB, for job_queue.py's unit tests — CI never
# talks to a real database.
mongomock==4.3.0
```

Run: `venv/bin/pip install -r requirements-dev.txt && venv/bin/python -c "import mongomock, pymongo; print(mongomock.__version__, pymongo.version)"`
Expected: prints both versions. If `mongomock` fails to import against pymongo 4.18, pin the newest mongomock release that imports cleanly and record the version in the commit message.

- [ ] **Step 2: Write the failing tests** — `tests/test_job_queue.py`

```python
"""job_queue.py: the MongoDB hand-off between the web server and the crawl
worker (CRAWL_MODE=queue). Runs against mongomock — no real database."""
import mongomock
import pytest
from pymongo.errors import ServerSelectionTimeoutError

import job_queue

NOW = 1_000_000.0


@pytest.fixture
def db(monkeypatch):
    database = mongomock.MongoClient()["getbuggy_test"]
    job_queue._ensure_indexes(database)
    monkeypatch.setattr(job_queue, "_get_db", lambda: database)
    return database


def test_queued_job_status_looks_like_todays_running_job(db):
    job_queue.enqueue("j1", "https://example.com", 5, now=NOW)
    p = job_queue.get_status_payload("j1", now=NOW + 1)
    assert p["status"] == "running"
    assert p["phase"] == "finding_pages"
    assert p["pages_checked"] == 0 and p["pages_done"] == []
    assert p["result"] is None and p["detail"] is None
    assert p["authorized"] is True
    for internal in ("_id", "url", "page_cap", "created_at", "enqueued_ts",
                     "claimed_ts", "heartbeat_ts", "worker_id"):
        assert internal not in p


def test_unknown_job_is_none(db):
    assert job_queue.get_status_payload("nope", now=NOW) is None


def test_claim_is_oldest_first_and_only_once(db):
    job_queue.enqueue("a", "https://a.example", 5, now=NOW)
    job_queue.enqueue("b", "https://b.example", 5, now=NOW + 1)
    first = job_queue.claim_next("w1", now=NOW + 2)
    second = job_queue.claim_next("w2", now=NOW + 2)
    assert (first["_id"], first["status"], first["worker_id"]) == ("a", "running", "w1")
    assert first["url"] == "https://a.example" and first["page_cap"] == 5
    assert second["_id"] == "b"
    assert job_queue.claim_next("w3", now=NOW + 2) is None


def test_active_count_ignores_finished_stale_and_abandoned(db):
    job_queue.enqueue("dead", "https://d.example", 5, now=NOW - 100)
    job_queue.claim_next("w0", now=NOW - 90)            # heartbeat NOW-90 -> stale at NOW
    job_queue.enqueue("live", "https://l.example", 5, now=NOW - 10)
    job_queue.claim_next("w1", now=NOW - 5)             # heartbeat NOW-5 -> live
    job_queue.enqueue("abandoned", "https://x.example", 5, now=NOW - 500)
    job_queue.enqueue("fresh", "https://f.example", 5, now=NOW)
    job_queue.enqueue("finished", "https://z.example", 5, now=NOW - 1)
    assert job_queue.claim_next("w2", now=NOW - 1)["_id"] == "finished"
    job_queue.finish("finished", "w2", {"summary": "ok"})
    assert job_queue.active_count(now=NOW) == 2         # live + fresh


def test_stale_running_job_reports_plain_error_and_frees_slot(db):
    job_queue.enqueue("j", "https://example.com", 5, now=NOW)
    job_queue.claim_next("w1", now=NOW)
    p = job_queue.get_status_payload("j", now=NOW + 61)
    assert p["status"] == "error"
    assert p["detail"] == job_queue.STALE_MESSAGE
    assert "Nothing is wrong with your site" in p["detail"]
    assert job_queue.active_count(now=NOW + 61) == 0


def test_heartbeat_keeps_a_long_crawl_alive(db):
    job_queue.enqueue("j", "https://example.com", 5, now=NOW)
    job_queue.claim_next("w1", now=NOW)
    job_queue.heartbeat("w1", now=NOW + 50)
    assert job_queue.get_status_payload("j", now=NOW + 100)["status"] == "running"


def test_unclaimed_job_times_out_with_plain_message_and_is_never_claimed(db, capsys):
    job_queue.enqueue("j", "https://secret-site.example", 5, now=NOW)
    p = job_queue.get_status_payload("j", now=NOW + 181)
    assert p["status"] == "error"
    assert p["detail"] == job_queue.UNCLAIMED_MESSAGE
    assert job_queue.claim_next("w1", now=NOW + 181) is None
    logged = capsys.readouterr().err
    assert "WORKER_MISSING" in logged
    assert "secret-site" not in logged


def test_late_finish_after_stale_mark_still_delivers_report(db):
    job_queue.enqueue("j", "https://example.com", 5, now=NOW)
    job_queue.claim_next("w1", now=NOW)
    assert job_queue.get_status_payload("j", now=NOW + 61)["status"] == "error"
    job_queue.finish("j", "w1", {"summary": "ok"})
    p = job_queue.get_status_payload("j", now=NOW + 62)
    assert p["status"] == "done" and p["result"] == {"summary": "ok"} and p["detail"] is None


def test_progress_writes_only_touch_the_claiming_workers_job(db):
    job_queue.enqueue("j", "https://example.com", 5, now=NOW)
    job_queue.claim_next("w1", now=NOW)
    job_queue.update_job("j", "someone-else", {"pages_checked": 3})
    assert job_queue.get_status_payload("j", now=NOW)["pages_checked"] == 0
    job_queue.update_job("j", "w1", {"pages_checked": 3, "pages_total": 5})
    job_queue.add_page("j", "w1", {"url": "https://example.com/", "index": 0})
    p = job_queue.get_status_payload("j", now=NOW)
    assert p["pages_checked"] == 3 and p["pages_total"] == 5
    assert p["pages_done"] == [{"url": "https://example.com/", "index": 0}]


def test_fail_records_the_plain_reason(db):
    job_queue.enqueue("j", "https://example.com", 5, now=NOW)
    job_queue.claim_next("w1", now=NOW)
    job_queue.fail("j", "w1", "The checker process failed unexpectedly.")
    p = job_queue.get_status_payload("j", now=NOW)
    assert p["status"] == "error" and p["detail"] == "The checker process failed unexpectedly."


def test_expire_overdue_sweeps_everything_stale(db):
    job_queue.enqueue("j", "https://example.com", 5, now=NOW)
    job_queue.claim_next("w1", now=NOW)
    job_queue.enqueue("q", "https://example.com", 5, now=NOW)
    assert job_queue.expire_overdue(now=NOW + 200) == 2
    assert db.crawl_jobs.count_documents({"status": "error"}) == 2


def test_worker_health(db):
    assert job_queue.healthy_worker_exists(now=NOW) is False
    job_queue.worker_seen("w", True, None, now=NOW)
    assert job_queue.healthy_worker_exists(now=NOW + 30) is True
    assert job_queue.healthy_worker_exists(now=NOW + 91) is False
    job_queue.worker_seen("broken", False, "Browser could not launch (x).", now=NOW + 91)
    assert job_queue.healthy_worker_exists(now=NOW + 91) is False


def test_off_without_mongodb_uri(monkeypatch):
    monkeypatch.setattr(job_queue, "MONGODB_URI", None)
    monkeypatch.setattr(job_queue, "_db", None)
    with pytest.raises(job_queue.QueueUnavailable):
        job_queue.enqueue("j", "https://example.com", 5)


def test_database_errors_become_queue_unavailable(monkeypatch):
    class Broken:
        def __getattr__(self, name):
            raise ServerSelectionTimeoutError("no servers")

    monkeypatch.setattr(job_queue, "_get_db", lambda: Broken())
    with pytest.raises(job_queue.QueueUnavailable):
        job_queue.active_count()
    with pytest.raises(job_queue.QueueUnavailable):
        job_queue.get_status_payload("j")
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `venv/bin/pytest tests/test_job_queue.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'job_queue'`

- [ ] **Step 4: Write `job_queue.py`**

```python
"""The hand-off between the web server and the crawl worker, through
MongoDB — used only when CRAWL_MODE=queue (see
docs/superpowers/specs/2026-10-11-lingcode-cloud-mongodb-design.md).

The web server enqueues a check; a worker (crawl_worker.py, a LingCode
container job with Chromium) claims it atomically, streams progress into
the same record, and finishes it. Status reads turn a crawl whose worker
stopped heartbeating, or a check no worker ever picked up, into a plain-
English error instead of an endless "checking…".

Off unless MONGODB_URI is set — every call then raises QueueUnavailable,
so a misconfigured deploy fails loudly with a plain message rather than
queueing checks nobody will run. Stores no IP address or anything else
about the visitor; never logs a site URL or the database URI."""
import os
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from pymongo import ReturnDocument
from pymongo.errors import PyMongoError

MONGODB_URI = os.environ.get("MONGODB_URI")
MONGODB_DB_NAME = os.environ.get("MONGODB_DB_NAME", "getbuggy")

QUEUED, RUNNING, DONE, ERROR = "queued", "running", "done", "error"

HEARTBEAT_STALE_SECONDS = 60     # a worker heartbeats every 10 s
UNCLAIMED_TIMEOUT_SECONDS = 180
WORKER_FRESH_SECONDS = 90
# Job state is not the saved report (that's report_store.py, 30 days) —
# a day is plenty for anyone still polling.
STATE_TTL_SECONDS = 24 * 60 * 60

STALE_MESSAGE = (
    "This check stopped unexpectedly on our side before it finished. "
    "Nothing is wrong with your site — please try again."
)
UNCLAIMED_MESSAGE = (
    "Our checking service didn't pick this up in time. "
    "Please try again in a few minutes."
)

# Queue bookkeeping — never sent to the visitor's browser.
_INTERNAL_FIELDS = ("_id", "url", "page_cap", "created_at", "enqueued_ts",
                    "claimed_ts", "heartbeat_ts", "worker_id")


class QueueUnavailable(Exception):
    """MongoDB is off (no MONGODB_URI) or couldn't be reached."""


_db = None
_db_lock = threading.Lock()


def _log(message):
    print(f"JOB_QUEUE {message}", file=sys.stderr, flush=True)


def _now(now):
    return time.time() if now is None else now


def _ensure_indexes(db):
    db.crawl_jobs.create_index("created_at", expireAfterSeconds=STATE_TTL_SECONDS)
    db.crawl_jobs.create_index([("status", 1), ("enqueued_ts", 1)])
    db.crawl_jobs.create_index([("worker_id", 1), ("status", 1)])
    db.workers.create_index("last_seen_at", expireAfterSeconds=STATE_TTL_SECONDS)


def _get_db():
    global _db
    if not MONGODB_URI:
        raise QueueUnavailable("MONGODB_URI is not set")
    with _db_lock:
        if _db is None:
            from pymongo import MongoClient

            db = MongoClient(
                MONGODB_URI, appname="getbuggy", serverSelectionTimeoutMS=5000,
            )[MONGODB_DB_NAME]
            _ensure_indexes(db)
            _db = db
    return _db


@contextmanager
def _guard():
    """Any database failure surfaces as QueueUnavailable, by class name
    only — never the URI (it holds the password)."""
    try:
        yield
    except QueueUnavailable:
        raise
    except (PyMongoError, OSError) as e:
        raise QueueUnavailable(e.__class__.__name__) from e


def _report_worker_missing(count):
    _log(f"WORKER_MISSING {count} check(s) were never picked up by a worker")
    if os.environ.get("SENTRY_DSN"):
        import sentry_sdk

        sentry_sdk.capture_message(
            f"GetBuggy: {count} check(s) were never picked up by a crawl worker"
        )


def enqueue(job_id, url, page_cap, authorized=True, now=None):
    now = _now(now)
    with _guard():
        _get_db().crawl_jobs.insert_one({
            "_id": job_id,
            "url": url,
            "page_cap": page_cap,
            "status": QUEUED,
            "created_at": datetime.now(timezone.utc),
            "enqueued_ts": now,
            # The same fields the in-memory job starts with (server.py), so
            # the status payload — and the frontend — look identical.
            "phase": "finding_pages",
            "pages_checked": 0,
            "pages_total": None,
            "pages_found_total": None,
            "pages_selected": [],
            "pages_skipped": [],
            "pages_done": [],
            "result": None,
            "detail": None,
            "authorized": authorized,
        })


def _active_filter(now):
    return {"$or": [
        {"status": QUEUED, "enqueued_ts": {"$gte": now - UNCLAIMED_TIMEOUT_SECONDS}},
        {"status": RUNNING, "heartbeat_ts": {"$gte": now - HEARTBEAT_STALE_SECONDS}},
    ]}


def active_count(now=None):
    now = _now(now)
    with _guard():
        return _get_db().crawl_jobs.count_documents(_active_filter(now))


def claim_next(worker_id, now=None):
    """Atomically takes the oldest queued check — two workers can never
    get the same one. A check queued too long ago is left alone: its
    visitor has already been told to try again."""
    now = _now(now)
    with _guard():
        return _get_db().crawl_jobs.find_one_and_update(
            {"status": QUEUED, "enqueued_ts": {"$gte": now - UNCLAIMED_TIMEOUT_SECONDS}},
            {"$set": {"status": RUNNING, "worker_id": worker_id,
                      "claimed_ts": now, "heartbeat_ts": now}},
            sort=[("enqueued_ts", 1)],
            return_document=ReturnDocument.AFTER,
        )


def heartbeat(worker_id, now=None):
    now = _now(now)
    with _guard():
        _get_db().crawl_jobs.update_many(
            {"worker_id": worker_id, "status": RUNNING},
            {"$set": {"heartbeat_ts": now}},
        )


def update_job(job_id, worker_id, fields):
    with _guard():
        _get_db().crawl_jobs.update_one({"_id": job_id, "worker_id": worker_id}, {"$set": fields})


def add_page(job_id, worker_id, page):
    with _guard():
        _get_db().crawl_jobs.update_one(
            {"_id": job_id, "worker_id": worker_id}, {"$push": {"pages_done": page}},
        )


def finish(job_id, worker_id, result):
    # Deliberately not conditional on status: a slow worker whose job was
    # already marked stale still delivers the real report, which beats an error.
    with _guard():
        _get_db().crawl_jobs.update_one(
            {"_id": job_id, "worker_id": worker_id},
            {"$set": {"status": DONE, "result": result, "detail": None}},
        )


def fail(job_id, worker_id, detail):
    with _guard():
        _get_db().crawl_jobs.update_one(
            {"_id": job_id, "worker_id": worker_id},
            {"$set": {"status": ERROR, "detail": detail}},
        )


def _expire(jobs, match, now):
    stale = jobs.update_many(
        {**match, "status": RUNNING, "heartbeat_ts": {"$lt": now - HEARTBEAT_STALE_SECONDS}},
        {"$set": {"status": ERROR, "detail": STALE_MESSAGE}},
    ).modified_count
    unclaimed = jobs.update_many(
        {**match, "status": QUEUED, "enqueued_ts": {"$lt": now - UNCLAIMED_TIMEOUT_SECONDS}},
        {"$set": {"status": ERROR, "detail": UNCLAIMED_MESSAGE}},
    ).modified_count
    if stale:
        _log(f"STALE_JOB {stale} check(s) lost their worker mid-crawl")
    if unclaimed:
        _report_worker_missing(unclaimed)
    return stale + unclaimed


def expire_overdue(now=None):
    """Marks every stale or abandoned check as an error. The worker runs
    this at startup; status reads do the same per job."""
    now = _now(now)
    with _guard():
        return _expire(_get_db().crawl_jobs, {}, now)


def get_status_payload(job_id, now=None):
    now = _now(now)
    with _guard():
        jobs = _get_db().crawl_jobs
        doc = jobs.find_one({"_id": job_id})
        if doc is None:
            return None
        if _expire(jobs, {"_id": job_id}, now):
            doc = jobs.find_one({"_id": job_id})
    payload = {k: v for k, v in doc.items() if k not in _INTERNAL_FIELDS}
    # The frontend keeps polling while status is "running" (static/index.html);
    # waiting for a worker is still "running" from the visitor's side.
    if payload["status"] == QUEUED:
        payload["status"] = RUNNING
    return payload


def worker_seen(worker_id, browser_ok, browser_detail, now=None):
    now = _now(now)
    with _guard():
        _get_db().workers.update_one(
            {"_id": worker_id},
            {"$set": {"last_seen_ts": now, "last_seen_at": datetime.now(timezone.utc),
                      "browser_ok": browser_ok, "browser_detail": browser_detail}},
            upsert=True,
        )


def healthy_worker_exists(now=None):
    now = _now(now)
    with _guard():
        return _get_db().workers.count_documents(
            {"browser_ok": True, "last_seen_ts": {"$gte": now - WORKER_FRESH_SECONDS}}
        ) > 0
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `venv/bin/pytest tests/test_job_queue.py -v`
Expected: all 14 PASS.

- [ ] **Step 6: Commit**

```bash
git add job_queue.py tests/test_job_queue.py requirements-dev.txt
git commit -m "Add MongoDB job queue for crawl hand-off

Atomic claims, heartbeats, and plain-English errors for a crawl whose
worker died or that no worker picked up. Used only in CRAWL_MODE=queue."
```

---

### Task 3: Queue mode in the web server (+ `/version` file, frontend retry)

**Files:**
- Modify: `server.py`: module settings near `MAX_CONCURRENT_CHECKS` (~line 64), `check()`, `check_status()`, `health()`, `_get_git_commit()`
- Modify: `static/index.html:1158-1170` (the status polling loop)
- Create: `tests/test_server_queue.py`

**Interfaces:**
- Consumes: from Task 2, `job_queue.enqueue`, `active_count`, `get_status_payload`, `healthy_worker_exists`, `QueueUnavailable` and `WORKER_FRESH_SECONDS`. From Task 1, `crawl_runner.browser_launch_problem`.
- Produces: `server.CRAWL_MODE` (`"local"` | `"queue"`), plus `server.BUSY_MESSAGE`, `server.QUEUE_DOWN_MESSAGE` and `server.STATUS_DOWN_MESSAGE`.

- [ ] **Step 1: Write the failing tests** — `tests/test_server_queue.py`

```python
"""server.py in CRAWL_MODE=queue: /api/check enqueues instead of crawling
here, check-status and /health read MongoDB, and every failure is plain
English. mongomock stands in for MongoDB."""
import mongomock
import pytest
from fastapi.testclient import TestClient

import job_queue
import report_store
import server


@pytest.fixture
def queue_db(monkeypatch):
    db = mongomock.MongoClient()["getbuggy_test"]
    job_queue._ensure_indexes(db)
    monkeypatch.setattr(job_queue, "_get_db", lambda: db)
    monkeypatch.setattr(server, "CRAWL_MODE", "queue")
    # Skips DNS so the tests run offline; URL validation has its own tests.
    monkeypatch.setattr(server, "validate_public_url", lambda url: None)
    server._global_run_times.clear()
    server._ip_run_times.clear()
    yield db
    server._global_run_times.clear()
    server._ip_run_times.clear()


@pytest.fixture
def client(queue_db):
    return TestClient(server.app)


def post(client, url="https://example.com", **extra):
    return client.post("/api/check", json={"url": url, "authorized": True, **extra})


def _break_database(monkeypatch):
    def down():
        raise job_queue.QueueUnavailable("down")
    monkeypatch.setattr(job_queue, "_get_db", down)


def test_check_is_queued_not_run_here(client, queue_db):
    resp = post(client)
    assert resp.status_code == 200
    doc = queue_db.crawl_jobs.find_one({"_id": resp.json()["job_id"]})
    assert doc["status"] == "queued"
    assert doc["url"] == "https://example.com"
    assert doc["page_cap"] == server.CRAWL_PAGE_CAP
    assert "testclient" not in str(doc)  # the visitor's address is never stored
    assert server._check_semaphore._value == server.MAX_CONCURRENT_CHECKS


def test_page_cap_only_narrows(client, queue_db):
    small = post(client, page_cap=1).json()["job_id"]
    big = post(client, page_cap=999).json()["job_id"]
    assert queue_db.crawl_jobs.find_one({"_id": small})["page_cap"] == min(1, server.CRAWL_PAGE_CAP)
    assert queue_db.crawl_jobs.find_one({"_id": big})["page_cap"] == server.CRAWL_PAGE_CAP


def test_third_check_is_refused_while_two_are_active(client):
    assert post(client).status_code == 200
    assert post(client).status_code == 200
    third = post(client)
    assert third.status_code == 429
    assert third.json()["detail"] == server.BUSY_MESSAGE
    assert len(server._global_run_times) == 2  # the refused one spent no budget


def test_database_down_is_plain_english_and_spends_no_budget(client, monkeypatch):
    _break_database(monkeypatch)
    resp = post(client)
    assert resp.status_code == 503
    assert resp.json()["detail"] == server.QUEUE_DOWN_MESSAGE
    assert len(server._global_run_times) == 0


def test_status_of_queued_job_matches_todays_running_shape(client):
    job_id = post(client).json()["job_id"]
    body = client.get(f"/api/check-status/{job_id}").json()
    assert body["status"] == "running"
    assert body["phase"] == "finding_pages"
    assert "url" not in body and "worker_id" not in body


def test_status_when_database_down_is_503_plain_english(client, monkeypatch):
    job_id = post(client).json()["job_id"]
    _break_database(monkeypatch)
    resp = client.get(f"/api/check-status/{job_id}")
    assert resp.status_code == 503
    assert resp.json()["detail"] == server.STATUS_DOWN_MESSAGE


def test_finished_job_falls_back_to_saved_report(client, monkeypatch):
    monkeypatch.setattr(report_store, "get_report",
                        lambda job_id: {"summary": "ok"} if job_id == "old" else None)
    assert client.get("/api/check-status/old").json() == {"status": "done", "result": {"summary": "ok"}}
    assert client.get("/api/check-status/never-existed").status_code == 404


def test_queue_status_still_goes_through_security_redaction(client, monkeypatch):
    # Real finding, real redaction — mirrors test_checks_security's
    # test_check_status_gates_details_unless_flag_is_set, but for a report
    # a worker finished in MongoDB.
    import checks_security as cs
    finding = cs._finding("Exposed Sensitive File", "detail with /.env path", cs.HIGH,
                          cs.WHO_WEB_PERSON, evidence="/.env")
    job_id = post(client).json()["job_id"]
    job_queue.claim_next("w1")
    job_queue.finish(job_id, "w1", {"unique_problems": [finding], "site_findings": [], "pages": []})

    monkeypatch.delenv(cs.SHOW_DETAILS_ENV_VAR, raising=False)
    hidden = client.get(f"/api/check-status/{job_id}").json()["result"]
    assert hidden["unique_problems"] == [] and hidden["security_summary"]["count"] == 1
    assert "/.env" not in str(hidden)

    monkeypatch.setenv(cs.SHOW_DETAILS_ENV_VAR, "true")
    shown = client.get(f"/api/check-status/{job_id}").json()["result"]
    assert shown["unique_problems"][0]["category"] == "Exposed Sensitive File"


def test_health_needs_a_worker_with_a_working_browser(client):
    resp = client.get("/health")
    assert resp.status_code == 503
    assert f"{job_queue.WORKER_FRESH_SECONDS} seconds" in resp.json()["detail"]
    job_queue.worker_seen("w1", True, None)
    assert client.get("/health").json() == {"status": "ok"}


def test_health_when_database_down(client, monkeypatch):
    _break_database(monkeypatch)
    resp = client.get("/health")
    assert resp.status_code == 503
    assert "database" in resp.json()["detail"]


def test_version_file_is_used_when_no_render_commit(tmp_path, monkeypatch):
    (tmp_path / "VERSION").write_text("abc123\n")
    monkeypatch.delenv("RENDER_GIT_COMMIT", raising=False)
    monkeypatch.setattr(server, "BASE_DIR", str(tmp_path))
    assert server._get_git_commit() == "abc123"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `venv/bin/pytest tests/test_server_queue.py -v`
Expected: FAIL. `post()` still runs the local path and spawns a subprocess; `server.BUSY_MESSAGE` raises AttributeError, and so on.

- [ ] **Step 3: Add the mode setting and messages.** Put this directly below `_check_semaphore = ...`:

```python
# Where crawls run. "local" (default): in a subprocess of this server, as
# always — local dev, CI, the Docker image. "queue": this server only
# enqueues the check in MongoDB and a separate crawl worker (crawl_worker.py,
# a LingCode container job with Chromium) runs it — see job_queue.py.
CRAWL_MODE = os.environ.get("CRAWL_MODE", "local")
if CRAWL_MODE not in ("local", "queue"):
    raise RuntimeError(f"CRAWL_MODE must be 'local' or 'queue', not {CRAWL_MODE!r}")

# Serialises "is there room?" + "enqueue" in queue mode, so two requests
# arriving together can't both take the last slot.
_enqueue_lock = threading.Lock()

BUSY_MESSAGE = "Too many checks are running right now — please try again in a moment."
QUEUE_DOWN_MESSAGE = "We can't start a check right now — please try again in a few minutes."
STATUS_DOWN_MESSAGE = "We lost track of this check for a moment — refresh in a few seconds."
```

Add `import job_queue` beside `import report_store`.

- [ ] **Step 4: Branch `check()`.** Add a helper above `check()`:

```python
def _effective_page_cap(req):
    # Only ever narrows the crawl below the server's own policy cap, never
    # widens it — a caller asking for more pages than CRAWL_PAGE_CAP just
    # gets CRAWL_PAGE_CAP, same as if they hadn't passed page_cap at all.
    if req.page_cap is not None and req.page_cap > 0:
        return min(req.page_cap, CRAWL_PAGE_CAP)
    return CRAWL_PAGE_CAP


def _enqueue_check(req, url, client_ip):
    """Queue mode: hand the check to a crawl worker through MongoDB. The
    cap of MAX_CONCURRENT_CHECKS applies across every worker, because it's
    counted in the database. Budget is only spent once the check is queued."""
    job_id = uuid.uuid4().hex
    with _enqueue_lock:
        try:
            if job_queue.active_count() >= MAX_CONCURRENT_CHECKS:
                raise HTTPException(status_code=429, detail=BUSY_MESSAGE)
            job_queue.enqueue(job_id, url, _effective_page_cap(req), authorized=req.authorized)
        except job_queue.QueueUnavailable:
            raise HTTPException(status_code=503, detail=QUEUE_DOWN_MESSAGE)
    record_run(client_ip)
    return {"job_id": job_id}
```

In `check()`, directly after the rate-limit block (`if rate_limit_message: raise ...`), insert:

```python
    if CRAWL_MODE == "queue":
        return _enqueue_check(req, url, client_ip)
```

Change the local semaphore message to use the constant: `detail=BUSY_MESSAGE`. Then replace the old `effective_page_cap` block at the bottom of `check()` with `effective_page_cap = _effective_page_cap(req)`.

- [ ] **Step 5: Branch `check_status()`.** Replace its first five lines (from `with _jobs_lock:` through the `payload = None if job ...` line) with:

```python
    if CRAWL_MODE == "queue":
        try:
            payload = job_queue.get_status_payload(job_id)
        except job_queue.QueueUnavailable:
            raise HTTPException(status_code=503, detail=STATUS_DOWN_MESSAGE)
    else:
        with _jobs_lock:
            job = _jobs.get(job_id)
            payload = None if job is None else {k: v for k, v in job.items() if k != "created_at"}
```

Leave the rest unchanged: the `report_store` fallback, the 404, and the redaction.

- [ ] **Step 6: Branch `health()`.** At the top of its body, after the docstring, add:

```python
    if CRAWL_MODE == "queue":
        # This server has no browser in queue mode — the worker launches a
        # real one at startup and reports in; "healthy" means one has, recently.
        try:
            ok = job_queue.healthy_worker_exists()
        except job_queue.QueueUnavailable:
            raise HTTPException(
                status_code=503,
                detail="Can't reach the database that hands checks to the checking service.",
            )
        if not ok:
            raise HTTPException(
                status_code=503,
                detail=(
                    "No checking service has reported in with a working browser in the "
                    f"last {job_queue.WORKER_FRESH_SECONDS} seconds, so checks can't run right now."
                ),
            )
        return {"status": "ok"}
```

- [ ] **Step 7: `/version` from a `VERSION` file.** In `_get_git_commit()`, between the `RENDER_GIT_COMMIT` check and the `git` fallback, insert:

```python
    # LingCode's hosted-app bundle has no .git — deploy/build_web_bundle.py
    # writes the deployed commit into a VERSION file instead.
    try:
        with open(os.path.join(BASE_DIR, "VERSION")) as f:
            version_from_file = f.read().strip()
        if version_from_file:
            return version_from_file
    except OSError:
        pass
```

- [ ] **Step 8: Frontend retry on 503.** In `static/index.html`, change the polling loop. Insert `let statusFailures = 0;` directly before `while (true) {`. Then replace:

```js
        const statusResp = await fetch(`/api/check-status/${jobId}`);
        const job = await statusResp.json();

        if (!statusResp.ok) {
```

with:

```js
        const statusResp = await fetch(`/api/check-status/${jobId}`);
        const job = await statusResp.json();

        // A 503 means we briefly couldn't read this check's progress — the
        // check itself keeps running, so keep waiting a few polls before
        // giving up instead of ending the wait on a blip.
        if (statusResp.status === 503 && ++statusFailures <= 5) {
          continue;
        }
        if (statusResp.ok) {
          statusFailures = 0;
        }

        if (!statusResp.ok) {
```

- [ ] **Step 9: Run the tests**

Run: `venv/bin/pytest tests/test_server_queue.py -v`
Expected: all 11 PASS.

- [ ] **Step 10: Full suite and harness**

Run: `venv/bin/pytest tests/ -q && venv/bin/python regression_check.py --skip-live`
Expected: all pass, with local mode untouched.

- [ ] **Step 11: Commit**

```bash
git add server.py static/index.html tests/test_server_queue.py
git commit -m "Add queue mode to the web server

CRAWL_MODE=queue enqueues checks in MongoDB for a separate crawl worker;
check-status and /health read the queue. /version reads a VERSION file
when there's no git. The frontend now retries a few 503 polls instead of
ending the wait on a database blip."
```

---

### Task 4: The crawl worker

**Files:**
- Create: `crawl_worker.py`
- Create: `tests/test_crawl_worker.py`

**Interfaces:**
- Consumes: from Task 1, `crawl_runner.run_crawl`, `meta_fields` and `browser_launch_problem`, plus `funnel.log_funnel_event`. From Task 2, all `job_queue` functions. `report_store.save_report(job_id, url, result)` already exists.
- Produces: `crawl_worker.main(claim_window_seconds: int | None = None) -> int` (exit code), `crawl_worker.run_one(job: dict, worker_id: str) -> None`, `crawl_worker.MongoSink`, and `crawl_worker.CRAWL_WORKER_SCRIPT`.

- [ ] **Step 1: Write the failing tests** — `tests/test_crawl_worker.py`

```python
"""crawl_worker.py: claims queued checks, runs them through the shared
crawl runner, and leaves every job done or with a plain error. Uses
mongomock and tests/fake_crawl_worker.py (the URL slot picks its mode) —
no browser, no real database."""
import mongomock
import pytest

import crawl_runner
import crawl_worker
import job_queue
import report_store


@pytest.fixture
def env(monkeypatch):
    db = mongomock.MongoClient()["getbuggy_test"]
    job_queue._ensure_indexes(db)
    monkeypatch.setattr(job_queue, "_get_db", lambda: db)
    monkeypatch.setattr(crawl_worker, "CRAWL_WORKER_SCRIPT", "tests/fake_crawl_worker.py")
    monkeypatch.setattr(crawl_worker, "POLL_SECONDS", 0.2)
    monkeypatch.setattr(crawl_worker, "DB_RETRY_SECONDS", 0)
    monkeypatch.setattr(crawl_runner, "browser_launch_problem", lambda *a, **k: None)
    saved = {}
    monkeypatch.setattr(report_store, "save_report",
                        lambda job_id, url, result: saved.update({job_id: result}))
    return db, saved


def test_run_one_streams_progress_and_saves_the_report(env):
    db, saved = env
    job_queue.enqueue("j1", "ok", 5)
    crawl_worker.run_one(job_queue.claim_next("w1"), "w1")
    doc = db.crawl_jobs.find_one({"_id": "j1"})
    assert doc["status"] == "done"
    assert doc["pages_total"] == 5 and doc["pages_found_total"] == 37
    assert len(doc["pages_done"]) == 5
    assert doc["result"]["summary"].startswith("Checked 5 of 37 page(s)")
    assert saved["j1"] == doc["result"]


def test_run_one_records_a_plain_error(env):
    db, saved = env
    job_queue.enqueue("j1", "die_early", 5)
    crawl_worker.run_one(job_queue.claim_next("w1"), "w1")
    doc = db.crawl_jobs.find_one({"_id": "j1"})
    assert doc["status"] == "error" and "boom" in doc["detail"]
    assert "j1" not in saved


def test_a_crash_inside_the_worker_still_ends_the_job(env, monkeypatch):
    db, _ = env
    job_queue.enqueue("j1", "ok", 5)
    job = job_queue.claim_next("w1")

    def explode(job, worker_id):
        raise RuntimeError("bug")

    monkeypatch.setattr(crawl_worker, "run_one", explode)
    slots = crawl_worker.threading.BoundedSemaphore(1)
    slots.acquire()
    crawl_worker._run_and_release(job, "w1", slots)
    doc = db.crawl_jobs.find_one({"_id": "j1"})
    assert doc["status"] == "error"
    assert doc["detail"] == job_queue.STALE_MESSAGE
    assert slots.acquire(blocking=False)  # the slot came back


def test_main_claims_runs_and_exits_after_its_window(env):
    db, saved = env
    job_queue.enqueue("a", "ok", 5)
    job_queue.enqueue("b", "ok", 5)
    assert crawl_worker.main(claim_window_seconds=3) == 0
    assert {d["status"] for d in db.crawl_jobs.find()} == {"done"}
    assert set(saved) == {"a", "b"}
    assert db.workers.find_one()["browser_ok"] is True


def test_main_claims_nothing_when_the_browser_cannot_launch(env, monkeypatch):
    db, _ = env
    monkeypatch.setattr(crawl_runner, "browser_launch_problem",
                        lambda *a, **k: "Browser could not launch (missing libraries).")
    job_queue.enqueue("a", "ok", 5)
    assert crawl_worker.main(claim_window_seconds=1) == 1
    assert db.crawl_jobs.find_one({"_id": "a"})["status"] == "queued"
    worker = db.workers.find_one()
    assert worker["browser_ok"] is False and "missing libraries" in worker["browser_detail"]


def test_main_exits_when_the_database_is_unreachable(env, monkeypatch):
    def down():
        raise job_queue.QueueUnavailable("down")
    monkeypatch.setattr(job_queue, "_get_db", down)
    assert crawl_worker.main(claim_window_seconds=1) == 1
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `venv/bin/pytest tests/test_crawl_worker.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawl_worker'`

- [ ] **Step 3: Write `crawl_worker.py`**

```python
"""The crawl worker — a LingCode container job (CRAWL_MODE=queue; see
docs/superpowers/specs/2026-10-11-lingcode-cloud-mongodb-design.md).

Scheduled every 30 minutes. Each run:
  1. launches a real headless Chromium once and records whether it worked,
     so the web server's /health means "a worker that can actually check";
  2. claims queued checks from MongoDB for WORKER_CLAIM_WINDOW_SECONDS, at
     most MAX_CONCURRENT_CHECKS at a time, each through the same
     crawl_runner.run_crawl() the web server uses locally (same 60-second
     page timeout, same 6-minute cap, same partial report);
  3. stops claiming, finishes what it has, and exits.
Runs overlap by design, so there's never a moment with nobody claiming."""
import os
import sys
import threading
import time
import uuid

import crawl_runner
import job_queue
import report_store
from funnel import log_funnel_event

WORKER_CLAIM_WINDOW_SECONDS = int(os.environ.get("WORKER_CLAIM_WINDOW_SECONDS", "2100"))
MAX_CONCURRENT_CHECKS = int(os.environ.get("MAX_CONCURRENT_CHECKS", "2"))
BROWSER_CHECK_TIMEOUT_SECONDS = 60
POLL_SECONDS = 2
HEARTBEAT_SECONDS = 10
DB_RETRY_SECONDS = 5
FINAL_WRITE_ATTEMPTS = 3
# Module-level so tests can swap in tests/fake_crawl_worker.py.
CRAWL_WORKER_SCRIPT = "run_site_check_subprocess.py"


def _log(message):
    # Job ids only — never a site URL or the database URI.
    print(f"CRAWL_WORKER {message}", file=sys.stderr, flush=True)


class MongoSink:
    """Streams one crawl's progress into its crawl_jobs record. A failed
    write is logged and dropped: a lagging progress bar beats a failed crawl."""

    def __init__(self, job_id, worker_id):
        self.job_id = job_id
        self.worker_id = worker_id

    def _write(self, write, *args):
        try:
            write(self.job_id, self.worker_id, *args)
        except job_queue.QueueUnavailable as e:
            _log(f"job={self.job_id} progress write failed ({e})")

    def on_meta(self, meta):
        self._write(job_queue.update_job, crawl_runner.meta_fields(meta))

    def on_progress(self, completed, total):
        self._write(job_queue.update_job, {"pages_checked": completed, "pages_total": total})

    def on_page(self, index, page):
        self._write(job_queue.add_page, dict(page, index=index))


def _write_final(job_id, write):
    for attempt in range(1, FINAL_WRITE_ATTEMPTS + 1):
        try:
            write()
            return True
        except job_queue.QueueUnavailable as e:
            _log(f"job={job_id} final write failed, attempt {attempt} ({e})")
            if attempt < FINAL_WRITE_ATTEMPTS:
                time.sleep(DB_RETRY_SECONDS)
    # Out of attempts: the job's heartbeat stops with this worker and the
    # visitor gets the plain "stopped unexpectedly" message.
    return False


def run_one(job, worker_id):
    job_id, url = job["_id"], job["url"]
    outcome = crawl_runner.run_crawl(
        url, job["page_cap"], MongoSink(job_id, worker_id), worker_script=CRAWL_WORKER_SCRIPT,
    )
    if outcome.status == "done":
        _write_final(job_id, lambda: job_queue.finish(job_id, worker_id, outcome.result))
        report_store.save_report(job_id, url, outcome.result)
        # Funnel stage 2 of 3 — logged here because in queue mode this is
        # where the report finishes (see funnel.py).
        log_funnel_event("report_viewed", job=job_id)
    else:
        _write_final(job_id, lambda: job_queue.fail(job_id, worker_id, outcome.detail))
    _log(f"job={job_id} {outcome.status}")


def _run_and_release(job, worker_id, slots):
    try:
        run_one(job, worker_id)
    except Exception as e:
        # A bug here must not leave the job "running" forever: this worker
        # keeps heartbeating, so it would never go stale on its own.
        _log(f"job={job['_id']} crashed ({e.__class__.__name__})")
        _write_final(job["_id"], lambda: job_queue.fail(job["_id"], worker_id, job_queue.STALE_MESSAGE))
    finally:
        slots.release()


def _heartbeat_loop(worker_id, stop):
    while not stop.wait(HEARTBEAT_SECONDS):
        try:
            job_queue.heartbeat(worker_id)
            job_queue.worker_seen(worker_id, True, None)
        except job_queue.QueueUnavailable as e:
            _log(f"heartbeat failed ({e})")


def main(claim_window_seconds=None):
    if claim_window_seconds is None:
        claim_window_seconds = WORKER_CLAIM_WINDOW_SECONDS
    worker_id = uuid.uuid4().hex
    problem = crawl_runner.browser_launch_problem(BROWSER_CHECK_TIMEOUT_SECONDS)
    try:
        job_queue.worker_seen(worker_id, problem is None, problem)
        job_queue.expire_overdue()
    except job_queue.QueueUnavailable as e:
        _log(f"can't reach the database at startup ({e}) — exiting")
        return 1
    if problem:
        _log(f"browser self-test failed, claiming nothing: {problem}")
        return 1

    stop = threading.Event()
    threading.Thread(target=_heartbeat_loop, args=(worker_id, stop), daemon=True).start()
    slots = threading.BoundedSemaphore(MAX_CONCURRENT_CHECKS)
    running = []
    deadline = time.monotonic() + claim_window_seconds
    _log(f"worker={worker_id} claiming for {claim_window_seconds}s")
    while time.monotonic() < deadline:
        if not slots.acquire(timeout=POLL_SECONDS):
            continue
        try:
            job = job_queue.claim_next(worker_id)
        except job_queue.QueueUnavailable as e:
            slots.release()
            _log(f"claim failed ({e})")
            time.sleep(DB_RETRY_SECONDS)
            continue
        if job is None:
            slots.release()
            time.sleep(POLL_SECONDS)
            continue
        _log(f"job={job['_id']} claimed")
        thread = threading.Thread(target=_run_and_release, args=(job, worker_id, slots))
        thread.start()
        running.append(thread)

    _log("claim window over — finishing in-flight checks")
    for thread in running:
        thread.join()  # each crawl is capped by crawl_runner's watchdog
    stop.set()
    _log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests**

Run: `venv/bin/pytest tests/test_crawl_worker.py -v`
Expected: all 6 PASS.

- [ ] **Step 5: Full suite and harness**

Run: `venv/bin/pytest tests/ -q && venv/bin/python regression_check.py --skip-live`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crawl_worker.py tests/test_crawl_worker.py
git commit -m "Add crawl worker for LingCode container jobs

Self-tests the browser, claims queued checks for a fixed window, runs
them through the shared crawl runner, heartbeats, then drains and exits."
```

---

### Task 5: Deploy artifacts

**Files:**
- Create: `deploy/build_web_bundle.py`
- Create: `deploy/lingcode.compute.json`
- Modify: `Dockerfile` (add named stages; the default target stays the web server)
- Modify: `.dockerignore`
- Create: `tests/test_web_bundle.py`

**Interfaces:**
- Consumes: the module names from Tasks 1–4 (they must be in the bundle).
- Produces: `deploy.build_web_bundle.build_bundle(out_path: str, version: str, root: str = ROOT) -> int` (file count), and a CLI: `python deploy/build_web_bundle.py --out PATH --version SHA`. The Docker target `worker`.

- [ ] **Step 1: Write the failing test** — `tests/test_web_bundle.py`

```python
"""deploy/build_web_bundle.py: the source tarball for LingCode's hosted-app
tier has what the server needs, nothing private, and fits the platform caps."""
import tarfile

from deploy import build_web_bundle


def test_bundle_has_the_server_and_nothing_private(tmp_path):
    out = tmp_path / "web.tar.gz"
    count = build_web_bundle.build_bundle(str(out), "test-version")
    with tarfile.open(out) as tar:
        names = tar.getnames()
        version = tar.extractfile("VERSION").read().decode().strip()
    assert version == "test-version"
    for needed in ("server.py", "core.py", "crawl_runner.py", "job_queue.py", "funnel.py",
                   "report_store.py", "requirements.txt", "Procfile", "static/index.html"):
        assert needed in names, needed
    for name in names:
        assert not name.startswith(("venv/", "tests/", "test_site", "test_page", "docs/",
                                    ".git/", "dist/", ".env")), name
        assert "__pycache__" not in name and not name.endswith(".pyc"), name
    assert count == len(names) <= build_web_bundle.MAX_FILES
```

- [ ] **Step 2: Run it to verify it fails**

Run: `venv/bin/pytest tests/test_web_bundle.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'deploy'` (or `cannot import name`).

- [ ] **Step 3: Write `deploy/build_web_bundle.py`**

```python
"""Builds the source tarball for GetBuggy's web server on LingCode's
hosted-app tier (a gzipped tar the platform builds with its Python
buildpack; the server runs with CRAWL_MODE=queue and has no Chromium).

Keeps it to what the server needs — no venv, tests, fixtures, docs or
local secrets — and checks the platform's caps (500 files, 100 MB). Writes
a VERSION file into the tarball so /version reports what's deployed
(there's no .git in the bundle).

    python deploy/build_web_bundle.py --out dist/getbuggy-web.tar.gz --version "$(git rev-parse HEAD)"
"""
import argparse
import io
import os
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_FILES = 500
MAX_BYTES = 100 * 1024 * 1024

EXCLUDED_DIRS = {"venv", ".venv", "__pycache__", ".git", ".github", ".pytest_cache",
                 "tests", "docs", "reviews", "dist", "deploy"}
EXCLUDED_DIR_PREFIXES = ("test_site",)
EXCLUDED_FILE_PREFIXES = ("test_page", ".env")
EXCLUDED_FILES = {"early_access.csv", "sample_image.png", "VERSION", ".DS_Store"}


def collect_files(root=ROOT):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in EXCLUDED_DIRS and not d.startswith(EXCLUDED_DIR_PREFIXES)
        )
        for name in sorted(filenames):
            if (name in EXCLUDED_FILES or name.startswith(EXCLUDED_FILE_PREFIXES)
                    or name.endswith(".pyc")):
                continue
            files.append(os.path.relpath(os.path.join(dirpath, name), root))
    return files


def build_bundle(out_path, version, root=ROOT):
    files = collect_files(root)
    total_bytes = sum(os.path.getsize(os.path.join(root, f)) for f in files)
    if len(files) + 1 > MAX_FILES:
        raise SystemExit(f"Bundle has {len(files) + 1} files; LingCode allows {MAX_FILES}.")
    if total_bytes > MAX_BYTES:
        raise SystemExit(f"Bundle is {total_bytes} bytes; LingCode allows {MAX_BYTES}.")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with tarfile.open(out_path, "w:gz") as tar:
        for rel in files:
            tar.add(os.path.join(root, rel), arcname=rel)
        data = (version.strip() + "\n").encode()
        info = tarfile.TarInfo("VERSION")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return len(files) + 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--version", required=True, help="the commit being deployed")
    args = parser.parse_args(argv)
    count = build_bundle(args.out, args.version)
    print(f"Wrote {args.out} ({count} files)")


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the test**

Run: `venv/bin/pytest tests/test_web_bundle.py -v`
Expected: PASS.

- [ ] **Step 5: Prove the bundle imports on its own.** The server must start without anything the bundle left out.

```bash
venv/bin/python deploy/build_web_bundle.py --out dist/getbuggy-web.tar.gz --version local-test
rm -rf /tmp/gb-bundle && mkdir /tmp/gb-bundle && tar -xzf dist/getbuggy-web.tar.gz -C /tmp/gb-bundle
cd /tmp/gb-bundle && CRAWL_MODE=queue /Users/weijiahuang/Desktop/website-checker-main/venv/bin/python -c "import server; print('ok', server.GIT_COMMIT)"
cd /Users/weijiahuang/Desktop/website-checker-main
```

Expected: `ok local-test`. A `ModuleNotFoundError` or a missing data file means a needed file was excluded; fix the exclusion list, not the import.

- [ ] **Step 6: Add a `worker` target to the `Dockerfile`, keeping the web server as the default.** Replace the whole file with:

```dockerfile
FROM python:3.12-slim AS base

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Installs Chromium plus the OS-level libraries it needs to actually run
# (fonts, graphics libs, etc.) — "--with-deps" is what makes this work on a
# bare slim image instead of Playwright's own preloaded image.
RUN playwright install --with-deps chromium

COPY . .

# The crawl worker for LingCode container jobs (CRAWL_MODE=queue — see
# crawl_worker.py). Same image, Chromium included; build with
# `docker build --target worker`.
FROM base AS worker
CMD ["python", "crawl_worker.py"]

# Default target: the web server, unchanged — `docker build .` still
# produces exactly what it did before.
FROM base AS web
ENV PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT}"]
```

- [ ] **Step 7: Keep secrets and build output out of images.** Append to `.dockerignore`:

```
.env
.env.*
dist/
docs/
```

- [ ] **Step 8: Write `deploy/lingcode.compute.json`.** This holds the intended values. Field names are unverified (the LingCode docs were unreachable on 2026-10-11), so confirm them in Task 8, Step 1 before applying.

```json
{
  "jobs": [
    {
      "name": "getbuggy-crawl-worker",
      "image": "custom",
      "schedule": "*/30 * * * *",
      "overlap": "allow",
      "timeoutSec": 3600,
      "memoryMb": 4096,
      "retries": 2,
      "env": {
        "CRAWL_CONCURRENCY": "2",
        "MAX_CONCURRENT_CHECKS": "2",
        "WORKER_CLAIM_WINDOW_SECONDS": "2100"
      }
    }
  ]
}
```

(`retries: 2`: a worker that crashes at startup would otherwise leave up to about 25 minutes with nobody claiming. Retrying a worker is safe, because claims are atomic.)

- [ ] **Step 9: Full suite, then commit**

Run: `venv/bin/pytest tests/ -q`
Expected: all pass.

```bash
git add deploy/build_web_bundle.py deploy/lingcode.compute.json Dockerfile .dockerignore tests/test_web_bundle.py
git commit -m "Add LingCode deploy artifacts

Web source bundle builder (with VERSION file), a worker target in the
Dockerfile (default target is still the web server), and the compute
job definition. Field names in lingcode.compute.json still need checking
against LingCode's docs."
```

---

### Task 6: Local end-to-end against real Atlas (manual verification)

Uses the `getbuggy_dev` database, never `getbuggy`. The connection string is entered at the prompt, never written to a file.

- [ ] **Step 1: Start the web server in queue mode and confirm `/health` is red with no worker**

```bash
cd /Users/weijiahuang/Desktop/website-checker-main
read -s MONGODB_URI && export MONGODB_URI   # paste the Atlas connection string
export MONGODB_DB_NAME=getbuggy_dev
CRAWL_MODE=queue venv/bin/uvicorn server:app --host 127.0.0.1 --port 8000 &
sleep 3; curl -s -w ' %{http_code}\n' http://127.0.0.1:8000/health
```

Expected: `503` with the "No checking service has reported in…" detail.

- [ ] **Step 2: Start a worker and confirm `/health` goes green**

```bash
WORKER_CLAIM_WINDOW_SECONDS=900 venv/bin/python crawl_worker.py &
sleep 15; curl -s -w ' %{http_code}\n' http://127.0.0.1:8000/health
```

Expected: `{"status":"ok"} 200`.

- [ ] **Step 3: Run the post-deploy check end to end**

Run: `venv/bin/python post_deploy_check.py --url http://127.0.0.1:8000`
Expected: PASS (`/version`, `/health`, and a real crawl of `https://example.com`). Paste the output.

- [ ] **Step 4: Check the UI by hand.** Open `http://127.0.0.1:8000`, tick the checkbox, and check `https://example.com`. You should see the "Checking page N of M" progress, then the report.

- [ ] **Step 5: Kill a worker mid-crawl.** Start a check of `http://medvi.org` from the UI. Once progress shows a page or two:

```bash
pkill -9 -f crawl_worker.py; pkill -9 -f run_site_check_subprocess.py
```

Expected: within about 70 seconds the UI shows "This check stopped unexpectedly on our side… please try again." Then `/health` goes back to 503 within 90 seconds.

- [ ] **Step 6: The capacity cap.** Restart a worker, then start 3 checks quickly with `curl -s -X POST localhost:8000/api/check -H 'content-type: application/json' -d '{"url":"https://example.com","authorized":true}'` three times. Expected: 2 return a `job_id` and the third returns the plain busy message.

- [ ] **Step 7: Stop everything.** Run `kill %1 %2` and `pkill -f crawl_worker.py`. Record the results of Steps 1–6 for Task 9.

---

### Task 7: Local Docker run of the worker image (required by CLAUDE.md)

This changes where and how the browser launches, so it needs a Linux container run that matches LingCode's job environment: amd64, a read-only root, a tmpfs at `/tmp`, and 4 GB.

- [ ] **Step 1: Build both targets for linux/amd64**

```bash
docker build --platform linux/amd64 --target worker -t getbuggy-worker .
docker build --platform linux/amd64 -t getbuggy-web .
```

Expected: both build. This Mac is arm64, so the amd64 build runs under emulation and is slow.

- [ ] **Step 2: Confirm the default (Render) image is unchanged in behaviour**

```bash
docker run -d --rm --platform linux/amd64 -p 8001:8000 --name gb-web getbuggy-web
sleep 20; curl -s -w ' %{http_code}\n' http://127.0.0.1:8001/health; docker stop gb-web
```

Expected: `{"status":"ok"} 200` (local mode, real browser launch).

- [ ] **Step 3: Run the worker the way LingCode will**

```bash
docker run -d --rm --platform linux/amd64 --memory=4g --read-only --tmpfs /tmp \
  -e MONGODB_URI -e MONGODB_DB_NAME=getbuggy_dev -e WORKER_CLAIM_WINDOW_SECONDS=900 \
  --name gb-worker getbuggy-worker
docker logs -f gb-worker   # expect "CRAWL_WORKER worker=… claiming for 900s"
```

Expected: no "browser self-test failed" line. If Chromium fails because `/dev/shm` is too small (the Docker default is 64 MB), that is a real finding about LingCode's runtime. Record it, and fix it in the launch args only with a fresh Docker run to prove the fix.

- [ ] **Step 4: Run a real crawl through it and measure memory.** With the queue-mode web server from Task 6, Step 1 running locally against `getbuggy_dev`, start a check of `http://medvi.org`:

```bash
curl -s -X POST localhost:8000/api/check -H 'content-type: application/json' -d '{"url":"http://medvi.org","authorized":true}'
while docker stats gb-worker --no-stream --format '{{.MemUsage}}' 2>/dev/null; do sleep 5; done | tee /tmp/gb-worker-mem.txt
```

Expected: the job ends `done`, either a full report or a partial report at the 6-minute cap. It must not be an error or a container crash. Record the peak memory from `/tmp/gb-worker-mem.txt`. If emulation makes the crawl unrepresentatively slow, also run a native arm64 build and record both, labelled.

- [ ] **Step 5: Stop and record.** Run `docker stop gb-worker`. Record the peak memory, the duration, and whether the report was full or partial, for Task 9.

---

### Task 8: Deploy to LingCode Cloud

Needs one of: (a) a LingCode account token, provided for this session only (export it as `LINGCODE_TOKEN`; never write it to a file), or (b) the founder running the uploads in the LingCode IDE. Every value below comes from `describe_backend` (2026-10-11).

- [ ] **Step 1: Confirm the API shapes.** Use `lingcode_docs` (or the IDE) to confirm the hosted-app create/source/deploy request bodies, the `lingcode.compute.json` field names, the job-image upload format (a `docker save` tarball), the API base URL, and this project's backend id. Correct `deploy/lingcode.compute.json` field names if needed; the values stay the same. Commit any correction.

- [ ] **Step 2: Atlas prerequisites (founder).** In Atlas → Network Access, remove the **1 WEEK** expiry from `0.0.0.0/0`.

- [ ] **Step 3: Secrets.** In the LingCode backend vault, set `MONGODB_URI` (production database name `getbuggy`, the default). Set `CRAWL_MODE=queue` on the hosted app's environment. If the app has no separate environment settings, use the vault; the worker ignores `CRAWL_MODE`.

- [ ] **Step 4: Web app.** Build the bundle, then create, upload and deploy it:

```bash
venv/bin/python deploy/build_web_bundle.py --out dist/getbuggy-web.tar.gz --version "$(git rev-parse HEAD)"
# POST   /api/cloud/account/backends/$BACKEND_ID/apps                (create; note the app id)
# PUT    /api/cloud/account/backends/$BACKEND_ID/apps/$APP_ID/source (body: dist/getbuggy-web.tar.gz)
# POST   /api/cloud/account/backends/$BACKEND_ID/apps/$APP_ID/deploy
```

Set the start command to `uvicorn server:app --host 0.0.0.0 --port $PORT` if the buildpack doesn't take it from the `Procfile`. Watch `GET .../apps/$APP_ID/logs` until uvicorn reports it is listening.

- [ ] **Step 5: Worker job**

```bash
docker build --platform linux/amd64 --target worker -t getbuggy-worker .
docker save getbuggy-worker | gzip > dist/getbuggy-worker.tar.gz   # must be ≤ 2 GB
# POST /api/account/cloud-compute/$BACKEND_ID/apply              (body: deploy/lingcode.compute.json)
# PUT  /api/account/cloud-compute/$BACKEND_ID/jobs/$JOB_ID/image (body: dist/getbuggy-worker.tar.gz)
```

Then start the first worker now instead of waiting for the schedule, using the `run_job` tool with `name: "getbuggy-crawl-worker"`. Check it with `get_job_run`: the log tail must show `claiming for 2100s` and no self-test failure.

- [ ] **Step 6: Live verification**

```bash
curl -s https://<slug>.apps.lingcode.app/version   # must equal the deployed commit
curl -s https://<slug>.apps.lingcode.app/health    # must be {"status":"ok"}
venv/bin/python post_deploy_check.py --url https://<slug>.apps.lingcode.app
```

Expected: all pass. Then run one real check through the live UI. Paste all output.

- [ ] **Step 7: Confirm the overlap works.** After 35 minutes or more, use `list_job_runs` with `name: "getbuggy-crawl-worker"`. Runs should start every 30 minutes and overlap, and `/health` should stay 200 across the hand-over.

- [ ] **Step 8: Rotate the Atlas password (founder).** Do it in Atlas → Database Access, then update `MONGODB_URI` in the vault and redeploy both parts (secrets are injected at deploy). Re-run Step 6.

---

### Task 9: Docs and standing rules

**Files:**
- Modify: `PROJECT_STATUS.md` (architecture, configuration, Deploy Log row, Progress Log entry)
- Modify: `PLAN.md` (decisions)
- Modify: `CLAUDE.md` (**only** with the founders' explicit sign-off on the wording below)

- [ ] **Step 1: `PROJECT_STATUS.md`.** Add a Progress Log entry dated the deploy day, covering:
  - the architecture (web hosted app + worker job + MongoDB queue);
  - the config table from the spec;
  - the Task 6 and Task 7 results (peak worker memory, the medvi.org outcome);
  - the live URL;
  - a Deploy Log row with the commit, `/version` output and the `post_deploy_check.py` result.

  Update the Deployment section's live URL. Note that Render stays suspended until retired.

- [ ] **Step 2: `PLAN.md`.** Record these decisions:
  - split hosting (why: 512 MB, no Chromium on the app tier);
  - option C, the always-on worker (why: no LingCode token inside the public app);
  - the Atlas `0.0.0.0/0` allow-list (why: no published LingCode egress IPs);
  - the frontend 503 retry deviation.

- [ ] **Step 3: `CLAUDE.md` (founder sign-off first).** Proposed replacement for the Render bullet:

> - Live hosting is LingCode Cloud: the web server is a hosted app (`CRAWL_MODE=queue`) and crawls run in the `getbuggy-crawl-worker` container job (see `PROJECT_STATUS.md` → Deployment). Deploys are run by hand: `deploy/build_web_bundle.py` for the web app, `docker build --target worker` for the worker. After every deploy, run `post_deploy_check.py --url <live URL>` and confirm `/version` and `/health` both check out. Log each deploy in `PROJECT_STATUS.md`.

- [ ] **Step 4: Commit**

```bash
git add PROJECT_STATUS.md PLAN.md CLAUDE.md
git commit -m "Document the move to LingCode Cloud with MongoDB

Architecture, configuration, deploy log, and the decisions behind the
split hosting and the always-on worker."
```
