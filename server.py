import contextlib
import csv
import json
import math
import os
import re
import secrets
import signal
import smtplib
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from email.message import EmailMessage

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core import (
    validate_public_url,
    UnsafeURLError,
    summarize_site_check,
    dedupe_site_problems,
    DEFAULT_CRAWL_PAGE_CAP,
)
from render_markdown import render_markdown
from checks_security import redact_security_details, show_security_details
from checks_accessibility import accessibility_summary
from checks_cookies import DEFAULT_JURISDICTION, normalize_jurisdiction
import report
import report_store

# Error tracking: no-op unless SENTRY_DSN is actually set (local dev,
# and any deploy that hasn't configured it, both just skip this
# entirely — no network calls, no overhead). Set SENTRY_DSN in Render's
# environment variables to turn this on for the live service.
SENTRY_DSN = os.environ.get("SENTRY_DSN")
if SENTRY_DSN:
    import sentry_sdk

    sentry_sdk.init(dsn=SENTRY_DSN)

@contextlib.asynccontextmanager
async def _lifespan(_app):
    # The 30-day deletion job (Step 8): once at startup, then every
    # REPORT_PURGE_INTERVAL_SECONDS, for as long as the server runs.
    stop = threading.Event()
    threading.Thread(target=_purge_loop, args=(stop,), daemon=True).start()
    yield
    stop.set()


app = FastAPI(title="Website Checker", lifespan=_lifespan)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LEGAL_DIR = os.path.join(BASE_DIR, "legal")


def _log_funnel_event(name, **fields):
    """Plain-English, grep-able log line for the URL-pasted -> report-
    viewed -> email-captured funnel — counts, not per-visitor tracking:
    no cookies, no session/user IDs, nothing that lets one line be tied
    to another from the same visitor. `fields` is for non-identifying
    context only (a job_id, a status) — never a raw URL or email
    address, so a log line alone never identifies who did what."""
    extra = " ".join(f"{k}={v}" for k, v in fields.items())
    print(f"FUNNEL {name} {extra}".rstrip(), file=sys.stderr, flush=True)

# Each check launches its own headless Chromium instance, which is
# expensive (real CPU + a few hundred MB of RAM apiece). This caps how
# many whole-site checks can run at once so a burst of traffic can't
# exhaust the box's memory before anything else does. One "check" here
# means one whole-site crawl (however many pages that covers), not one
# page — a crawl still only occupies a single slot.
MAX_CONCURRENT_CHECKS = int(os.environ.get("MAX_CONCURRENT_CHECKS", "2"))
_check_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_CHECKS)

# Rate limiting — a cost guard, not a fairness/security feature (see
# PROJECT_STATUS.md, GetBuggy Step 3): the site is public with no login,
# and every check launches real Chromium instances that cost real money.
# Per-IP limit stops one visitor from hammering the service; the daily
# global cap bounds worst-case total spend regardless of how the traffic
# is distributed across IPs. Both are in-memory (matching every other
# piece of state in this file — no database yet), so they reset on a
# restart/redeploy; that's an acceptable gap for a cost guard, not a
# security control.
RATE_LIMIT_PER_IP_PER_HOUR = int(os.environ.get("RATE_LIMIT_PER_IP_PER_HOUR", "5"))
RATE_LIMIT_WINDOW_SECONDS = 60 * 60

DAILY_GLOBAL_RUN_CAP = int(os.environ.get("DAILY_GLOBAL_RUN_CAP", "200"))
DAILY_WINDOW_SECONDS = 24 * 60 * 60

_rate_limit_lock = threading.Lock()
_ip_run_times = defaultdict(deque)
_global_run_times = deque()


def _prune_older_than(timestamps, window_seconds, now):
    """Drops entries older than the window from the left of a deque of
    ascending timestamps (oldest first, since entries are always
    appended in time order) — a rolling window, not a fixed-bucket
    counter, so "5 per hour" really means "5 in the trailing 60
    minutes," not "5 since the top of the clock hour.\""""
    cutoff = now - window_seconds
    while timestamps and timestamps[0] < cutoff:
        timestamps.popleft()


def check_rate_limits(client_ip):
    """Returns a friendly message string if this request should be
    rejected (global daily cap first, since it protects everyone;
    per-IP second), or None if it's allowed. Doesn't record anything by
    itself — call record_run() separately, only once a request has also
    passed every other gate (authorization, concurrency slot), so a
    request that was going to be rejected for some other reason doesn't
    also eat into either budget."""
    now = time.time()
    with _rate_limit_lock:
        _prune_older_than(_global_run_times, DAILY_WINDOW_SECONDS, now)
        if len(_global_run_times) >= DAILY_GLOBAL_RUN_CAP:
            return (
                "GetBuggy has hit its limit of site checks for today — "
                "sorry about that. Please try again tomorrow."
            )

        ip_times = _ip_run_times[client_ip]
        _prune_older_than(ip_times, RATE_LIMIT_WINDOW_SECONDS, now)
        if len(ip_times) >= RATE_LIMIT_PER_IP_PER_HOUR:
            return (
                f"You've checked {RATE_LIMIT_PER_IP_PER_HOUR} site(s) in the "
                "last hour, which is the limit for now — please try again "
                "in a bit."
            )
    return None


def record_run(client_ip):
    now = time.time()
    with _rate_limit_lock:
        _global_run_times.append(now)
        _ip_run_times[client_ip].append(now)


def get_client_ip(request: Request):
    """Render (like most PaaS platforms) terminates TLS and proxies the
    actual request, so request.client.host would otherwise be the
    proxy's own address for every visitor — X-Forwarded-For carries the
    real chain, with the original client first. Falls back to
    request.client.host for local dev, where there's no proxy in front
    at all."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# How many pages a whole-site check covers by default — a config value,
# not hardcoded, so it can be raised for a future Pro tier (see PLAN.md)
# without a code change, just this env var.
CRAWL_PAGE_CAP = int(os.environ.get("CRAWL_PAGE_CAP", str(DEFAULT_CRAWL_PAGE_CAP)))

# Per-page load timeout — 60s per CLAUDE.md's standing rule ("the 60-second
# timeout is per page"). Passed to the crawl subprocess as a CLI argument
# (see run_site_check_subprocess.py); core.py's own defaults (used by the
# CLI and regression harness, which don't go through this server) match.
PAGE_LOAD_TIMEOUT_MS = int(os.environ.get("PAGE_LOAD_TIMEOUT_MS", "60000"))

# A hard ceiling on how long a whole-site check is allowed to run — a flat
# 6 minutes regardless of CRAWL_PAGE_CAP. This is a promise to the person
# waiting on the report ("this won't take more than 6 minutes"), not a
# per-page time budget, so it deliberately does NOT scale with page count
# the way an earlier version of this did (45s/page). Reuses the same
# *mechanism* the single-page timeout used to (a subprocess in its own
# process group, killed outright via SIGKILL if it overruns — see
# _run_with_timeout below).
CRAWL_TIMEOUT_SECONDS = int(os.environ.get("CRAWL_TIMEOUT_SECONDS", "360"))


class CheckRequest(BaseModel):
    url: str
    # Required — the frontend's authorization checkbox ("I own this site
    # or have permission to check it") must be checked before the form
    # will even submit (see static/index.html), and the server enforces
    # it again independently here, since a browser's client-side
    # validation is trivially bypassed by anyone calling the API
    # directly. Defaults to False specifically so an old/bypassed client
    # that never sends this field is rejected, not silently allowed.
    authorized: bool = False
    # Optional, and never sent by the public frontend (static/index.html
    # always omits it, so real users always get the full CRAWL_PAGE_CAP).
    # Exists so internal tooling — post_deploy_check.py's capacity check —
    # can request a smaller, cheaper crawl without a full CRAWL_PAGE_CAP
    # run against the live site after every single deploy. Only ever
    # narrows the crawl, never widens it — see the min() below.
    page_cap: int | None = None
    # Step 7: whose cookie rules the cookie/consent findings are written
    # for — "us" (default), "eu_uk" or "both" (see checks_cookies.py).
    jurisdiction: str | None = None
    # Step 8: the permalink id of the report this is a re-check of (the
    # frontend sends the last report it showed). Used only to work out the
    # score change, and only when that report is for the same site.
    previous_report_id: str | None = None


# A crawl can take minutes, far too long for a single blocking HTTP
# request/response — so POST /api/check kicks off a background job and
# returns a job_id immediately; the frontend polls GET
# /api/check-status/{job_id} for progress ("checking page 4 of 10") and
# the final result. In-memory while running — fine for one server process,
# lost on restart, and pruned after JOB_TTL_SECONDS so this dict can't grow
# unbounded. Finished reports are also saved for 30 days when MONGODB_URI is
# set (see report_store.py), and check-status falls back to that copy.
_jobs = {}
_jobs_lock = threading.Lock()
JOB_TTL_SECONDS = 30 * 60


def _prune_old_jobs():
    # Only finished jobs: a queued or running one is still owed a report.
    cutoff = time.time() - JOB_TTL_SECONDS
    for job_id in [
        jid for jid, job in _jobs.items()
        if job["created_at"] < cutoff and job["status"] in ("done", "error")
    ]:
        del _jobs[job_id]


# The worker process a crawl runs in. A module-level setting (not inlined)
# so the tests can swap in a fake worker that streams a few pages and then
# hangs, to prove a crawl that hits the time cap returns a partial report.
CRAWL_WORKER_SCRIPT = "run_site_check_subprocess.py"


# The queue (Step 8). When all MAX_CONCURRENT_CHECKS slots are busy, a new
# check waits its turn instead of being turned away: it gets a job id at
# once, reports "queued" with its place in line and a rough wait, and
# starts by itself the moment a slot frees up. Bounded, so a burst can't
# pile up unbounded work; past MAX_QUEUE_LENGTH the visitor is asked to
# come back in a few minutes.
MAX_QUEUE_LENGTH = int(os.environ.get("MAX_QUEUE_LENGTH", "10"))
# Used for the wait estimate until real crawls have been timed.
DEFAULT_CRAWL_ESTIMATE_SECONDS = 120
_queue = deque()  # (job_id, url, page_cap, kwargs), oldest first
_queue_lock = threading.Lock()
_recent_crawl_seconds = deque(maxlen=20)


def _launch(job_id, url, page_cap, kwargs):
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id]["status"] = "running"
    threading.Thread(
        target=_run_crawl_job, args=(job_id, url, page_cap), kwargs=kwargs, daemon=True
    ).start()


def _admit_or_queue(job_id, url, page_cap, kwargs):
    """Starts the crawl now if a slot is free and nobody is waiting, else
    puts it at the back of the queue. Returns "running", "queued", or None
    when the queue is full."""
    with _queue_lock:
        if not _queue and _check_semaphore.acquire(blocking=False):
            state = "running"
        elif len(_queue) >= MAX_QUEUE_LENGTH:
            return None
        else:
            _queue.append((job_id, url, page_cap, kwargs))
            state = "queued"
    if state == "running":
        _launch(job_id, url, page_cap, kwargs)
    return state


def _release_slot():
    """A crawl finished (or never started): free its slot and start
    whoever has waited longest."""
    _check_semaphore.release()
    while True:
        with _queue_lock:
            if not _queue or not _check_semaphore.acquire(blocking=False):
                return
            job_id, url, page_cap, kwargs = _queue.popleft()
        _launch(job_id, url, page_cap, kwargs)


def _queue_position(job_id):
    with _queue_lock:
        for i, entry in enumerate(_queue):
            if entry[0] == job_id:
                return i + 1
    return None


def _ordinal(n):
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def estimate_wait_seconds(position):
    """Rough: how many "rounds" of MAX_CONCURRENT_CHECKS crawls stand ahead,
    times how long a crawl has been taking lately."""
    recent = list(_recent_crawl_seconds)
    typical = sum(recent) / len(recent) if recent else DEFAULT_CRAWL_ESTIMATE_SECONDS
    return int(math.ceil(position / max(MAX_CONCURRENT_CHECKS, 1)) * typical)


def queue_message(position, wait_seconds):
    minutes = max(1, int(round(wait_seconds / 60)))
    return (
        f"Lots of people are checking their sites right now. You're {_ordinal(position)} in line — "
        f"your check should start in about {minutes} minute{'' if minutes == 1 else 's'}. "
        "Keep this page open; it will start by itself."
    )


# Permalinks (Step 8): /r/<report_id>. The report id is its own random
# token, separate from the job id, so a shared link can only ever reach the
# ownership-gated report (GET /api/report/...), never /api/check-status,
# which shows security details when the server flag is on.
_REPORT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
REPORT_NOT_FOUND_MESSAGE = (
    "We couldn't find that report. Reports are deleted 30 days after they're made, so it may "
    "have expired — or the link may be incomplete. You can run a new check from the home page."
)


def _find_report(report_id):
    """A finished report by permalink id: in memory first, then the 30-day
    store. None if it doesn't exist (or has expired)."""
    if not report_id or not _REPORT_ID_RE.match(report_id):
        return None
    with _jobs_lock:
        for job in _jobs.values():
            if job.get("report_id") == report_id and job["status"] == "done":
                return job["result"]
    return report_store.get_report_by_report_id(report_id)


# The 30-day deletion job (Step 8) — see report_store.purge_expired. Also
# drops finished in-memory jobs past their 30 minutes, so nothing lingers
# in memory between checks either.
REPORT_PURGE_INTERVAL_SECONDS = int(os.environ.get("REPORT_PURGE_INTERVAL_SECONDS", "3600"))


def run_purge_once():
    with _jobs_lock:
        _prune_old_jobs()
    return report_store.purge_expired()


def _purge_loop(stop):
    while True:
        run_purge_once()
        if stop.wait(REPORT_PURGE_INTERVAL_SECONDS):
            return


def build_partial_result(meta, pages_done, timeout_seconds, reason):
    """What a crawl gathered before it was stopped (time cap, or the
    worker dying), as a normal result marked `partial`. `meta` is the
    worker's META payload (None if it was stopped before discovery
    finished); `pages_done` maps page index -> finished page result.

    This is the fix for the old behavior, where a crawl that hit the cap
    came back as a bare error and threw away every page already checked."""
    meta = meta or {}
    selected = meta.get("selected", [])
    ordered = [pages_done[i] for i in sorted(pages_done)]
    unique_problems = dedupe_site_problems(ordered)
    return {
        "pages_found_total": meta.get("pages_found_total", 0),
        "pages_planned": meta.get("pages_planned", 0),
        "pages_checked": len(ordered),
        "used_sitemap": meta.get("used_sitemap", False),
        "sitemap_source": meta.get("sitemap_source"),
        "pages": ordered,
        "pages_skipped": meta.get("pages_skipped", []),
        "pages_not_checked_in_time": [u for i, u in enumerate(selected) if i not in pages_done],
        "site_findings": meta.get("site_findings", []),
        "site_could_not_check": meta.get("site_could_not_check", []),
        "unique_problems": unique_problems,
        "accessibility": accessibility_summary(unique_problems, meta.get("site_findings", [])),
        "platform": meta.get("platform"),
        "jurisdiction": meta.get("jurisdiction"),
        # The homepage's cookie list — the other pages' snapshots are only
        # merged in when the crawl finishes.
        "cookies": meta.get("cookies"),
        "partial": True,
        "partial_reason": reason,
        "time_cap_seconds": timeout_seconds,
    }


def _run_crawl_job(job_id, url, page_cap, timeout_seconds=None, jurisdiction=DEFAULT_JURISDICTION,
                   previous=None):
    timeout_seconds = timeout_seconds or CRAWL_TIMEOUT_SECONDS
    started = time.monotonic()

    def fail(detail):
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["detail"] = detail

    try:
        # Own OS process, own process group (start_new_session=True):
        # specifically so that if it has to be killed for running too
        # long, its Chromium child process is killed along with it rather
        # than left running as an orphan.
        proc = subprocess.Popen(
            [
                sys.executable, CRAWL_WORKER_SCRIPT, url, str(page_cap),
                str(PAGE_LOAD_TIMEOUT_MS), jurisdiction,
            ],
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except Exception as e:
        fail(f"Could not start the checker process ({e.__class__.__name__}).")
        _release_slot()
        return

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
                    with _jobs_lock:
                        _jobs[job_id]["pages_checked"] = int(completed)
                        _jobs[job_id]["pages_total"] = int(total)
                elif line.startswith("META "):
                    meta = json.loads(line[len("META "):])
                    with _jobs_lock:
                        job = _jobs[job_id]
                        job["phase"] = "checking_pages"
                        job["pages_total"] = meta["pages_planned"]
                        job["pages_found_total"] = meta["pages_found_total"]
                        job["pages_selected"] = meta["selected"]
                        job["pages_skipped"] = meta["pages_skipped"]
                        job["used_sitemap"] = meta["used_sitemap"]
                elif line.startswith("PAGE "):
                    _, index, page_json = line.split(" ", 2)
                    page = json.loads(page_json)
                    pages_done[int(index)] = page
                    with _jobs_lock:
                        _jobs[job_id]["pages_done"].append(dict(page, index=int(index)))
                elif line.startswith("RESULT "):
                    result_json = line[len("RESULT "):]
            except (ValueError, KeyError):
                pass  # one malformed progress line must never sink the crawl

        proc.wait()
        stderr_output = proc.stderr.read()

        result = None
        if timed_out.is_set():
            result = build_partial_result(meta, pages_done, timeout_seconds, "time_cap")
        elif proc.returncode == 0 and result_json is not None:
            try:
                result = json.loads(result_json)
            except json.JSONDecodeError:
                result = None
        if result is None:
            # The worker died mid-crawl (e.g. the host killed it for memory)
            # or its final line was unreadable. If anything finished — a
            # page, or the site-wide checks that run before any page — hand
            # that back, marked partial (Step 8: never a bare error once a
            # check has finished). Only a crawl that produced nothing at all
            # is an error.
            if not pages_done and not meta:
                fail(stderr_output.strip() or "The checker process failed unexpectedly.")
                return
            result = build_partial_result(meta, pages_done, timeout_seconds, "worker_stopped")

        _finish(job_id, url, result, previous)
        # Funnel stage 2 of 3 (see _log_funnel_event): approximated here,
        # server-side, as "the report finished and was available to be
        # shown" rather than a frontend "the DOM actually rendered it"
        # beacon — more robust (no dependency on the visitor's tab still
        # being open, ad blockers, etc.) and needs no new public endpoint.
        _log_funnel_event("report_viewed", job=job_id)
        _recent_crawl_seconds.append(time.monotonic() - started)
    except Exception as e:
        # Same rule as above: pages already gathered still come back.
        try:
            if pages_done or meta:
                _finish(job_id, url, build_partial_result(meta, pages_done, timeout_seconds,
                                                          "worker_stopped"), previous)
            else:
                fail(f"Unexpected error while checking ({e.__class__.__name__}).")
        except Exception as e2:
            fail(f"Unexpected error while checking ({e2.__class__.__name__}).")
    finally:
        _release_slot()


def _finish(job_id, url, result, previous):
    """Score, standardise and label the result (report.finalize_report),
    hand it to the waiting browser, and save it for its 30 days."""
    with _jobs_lock:
        report_id = _jobs[job_id].get("report_id") or secrets.token_urlsafe(16)
        _jobs[job_id]["report_id"] = report_id
    report.finalize_report(result, url=url, report_id=report_id, previous=previous)
    with _jobs_lock:
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = result
    report_store.save_report(job_id, url, result)


@app.post("/api/check")
def check(req: CheckRequest, request: Request):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Please enter a URL.")

    try:
        validate_public_url(url)
    except UnsafeURLError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Funnel stage 1 of 3 — a well-formed, safety-checked URL is genuine
    # top-of-funnel intent, logged here regardless of whether the gates
    # below end up allowing the run, same as any other funnel: not every
    # visitor who starts converts.
    _log_funnel_event("url_pasted")

    if not req.authorized:
        raise HTTPException(
            status_code=400,
            detail=(
                "Please confirm you own this site or have permission to "
                "check it before running a check."
            ),
        )

    try:
        jurisdiction = normalize_jurisdiction(req.jurisdiction)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=(
                "Please choose where your visitors are — the US, the EU and UK, "
                "or both — so we know which cookie rules to describe."
            ),
        )

    client_ip = get_client_ip(request)

    rate_limit_message = check_rate_limits(client_ip)
    if rate_limit_message:
        raise HTTPException(status_code=429, detail=rate_limit_message)

    # Re-check: the report this one follows, for the score change — only
    # if it's for the same site (anything else is silently ignored).
    previous = None
    if req.previous_report_id:
        prev_result = _find_report(req.previous_report_id)
        if prev_result and report.same_site(prev_result.get("url") or "", url):
            previous = report.previous_summary(prev_result)

    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _prune_old_jobs()
        _jobs[job_id] = {
            # "queued" until a slot is free (see _admit_or_queue), then
            # "running", then "done"/"error".
            "status": "queued",
            # The report's permalink id (/r/<report_id>) — see _find_report.
            "report_id": secrets.token_urlsafe(16),
            # "finding_pages" until the worker reports what it found, then
            # "checking_pages" — drives the UI's "Checking page 3 of 5".
            "phase": "finding_pages",
            "pages_checked": 0,
            "pages_total": None,
            "pages_found_total": None,
            "pages_selected": [],
            "pages_skipped": [],
            "pages_done": [],
            "result": None,
            "detail": None,
            "created_at": time.time(),
            # Recorded with the run, per the standing rule this checkbox
            # exists for — always True at this point (the request would
            # already have been rejected above otherwise), kept on the
            # record itself rather than only in the one-time gate check.
            "authorized": req.authorized,
            "jurisdiction": jurisdiction,
        }

    # Only ever narrows the crawl below the server's own policy cap, never
    # widens it — a caller asking for more pages than CRAWL_PAGE_CAP just
    # gets CRAWL_PAGE_CAP, same as if they hadn't passed page_cap at all.
    effective_page_cap = CRAWL_PAGE_CAP
    if req.page_cap is not None and req.page_cap > 0:
        effective_page_cap = min(req.page_cap, CRAWL_PAGE_CAP)

    state = _admit_or_queue(
        job_id, url, effective_page_cap, {"jurisdiction": jurisdiction, "previous": previous}
    )
    if state is None:
        with _jobs_lock:
            _jobs.pop(job_id, None)
        raise HTTPException(
            status_code=429,
            detail=(
                f"GetBuggy is very busy right now — {MAX_QUEUE_LENGTH} checks are already waiting "
                "in line. Please try again in a few minutes."
            ),
        )
    # Counted only once the check is actually accepted (running or queued).
    record_run(client_ip)
    if state == "running":
        return {"job_id": job_id, "status": "running"}
    position = _queue_position(job_id) or 1
    return {"job_id": job_id, "status": "queued", "queue_position": position}


@app.get("/api/check-status/{job_id}")
def check_status(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        payload = None if job is None else {k: v for k, v in job.items() if k != "created_at"}
    if payload is None:
        # Gone from memory (pruned after 30 minutes, or the server restarted) —
        # a finished report may still be saved for up to 30 days.
        saved = report_store.get_report(job_id)
        if saved is None:
            raise HTTPException(status_code=404, detail="Unknown job id.")
        payload = {"status": "done", "result": saved}
    if payload["status"] == "queued":
        position = _queue_position(job_id)
        if position is not None:
            wait = estimate_wait_seconds(position)
            payload.update(
                queue_position=position,
                estimated_wait_seconds=wait,
                queue_message=queue_message(position, wait),
            )
    # Security findings are ownership-gated (CLAUDE.md): the public report
    # gets a category-level count only, unless the server operator has
    # explicitly turned details on. Every report — live, in progress, or a
    # saved one reopened by its id — leaves the server through here.
    if not show_security_details():
        payload = redact_security_details(payload)
    return payload


# Shareable report endpoints (Step 8). Always ownership-gated — security
# details never appear on a permalink or in an export, whatever the server
# flag says (CLAUDE.md).

@app.get("/api/report/{report_id}")
def shared_report(report_id: str):
    result = _find_report(report_id)
    if result is None:
        raise HTTPException(status_code=404, detail=REPORT_NOT_FOUND_MESSAGE)
    return redact_security_details({"status": "done", "result": result})


@app.get("/api/report/{report_id}/export", response_class=PlainTextResponse)
def export_report(report_id: str, request: Request):
    """"Send to your web person": the report as plain text / markdown."""
    result = _find_report(report_id)
    if result is None:
        raise HTTPException(status_code=404, detail=REPORT_NOT_FOUND_MESSAGE)
    permalink = str(request.base_url).rstrip("/") + f"/r/{report_id}"
    return PlainTextResponse(
        report.render_export(result, permalink=permalink),
        media_type="text/markdown; charset=utf-8",
    )


@app.get("/r/{report_id}")
def report_page(report_id: str):
    # The normal page; its script sees /r/<id> and loads the shared report
    # (or says plainly that it has expired).
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"), media_type="text/html")


def _get_git_commit():
    # Render sets this automatically for git-connected deploys — trust it
    # first, since it reflects the actually-deployed commit. The `git`
    # fallback below is for local dev only (the Docker image doesn't ship
    # a .git directory — see .dockerignore).
    render_commit = os.environ.get("RENDER_GIT_COMMIT")
    if render_commit:
        return render_commit
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


GIT_COMMIT = _get_git_commit()


@app.get("/version")
def version():
    return {"commit": GIT_COMMIT}


# How long GET /health waits for the browser-launch subprocess before
# giving up. Generous — a healthy launch is normally well under a
# second — since a slow-but-eventually-successful launch under load
# shouldn't itself be reported as unhealthy.
HEALTH_CHECK_TIMEOUT_SECONDS = int(os.environ.get("HEALTH_CHECK_TIMEOUT_SECONDS", "20"))


@app.get("/health")
def health():
    """Actually launches (and immediately closes) a real headless
    Chromium instance — not just "is the server process alive," which
    /version already answers just by responding at all. Point an
    external uptime monitor here specifically to catch the failure mode
    /version can't see: the server is up, but a bad deploy/environment
    (missing Chromium deps, a broken Docker image) means it can't
    actually check anything. Runs as its own subprocess, own process
    group (see health_check_subprocess.py), same safety pattern as the
    crawl subprocess — a hung or crashed browser launch can never affect
    this endpoint's own request-handling process."""
    try:
        proc = subprocess.Popen(
            [sys.executable, "health_check_subprocess.py"],
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Could not start the browser-launch check ({e.__class__.__name__}).",
        )

    try:
        _, stderr = proc.communicate(timeout=HEALTH_CHECK_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        raise HTTPException(
            status_code=503,
            detail=f"Browser launch check timed out after {HEALTH_CHECK_TIMEOUT_SECONDS}s.",
        )

    if proc.returncode != 0:
        raise HTTPException(
            status_code=503,
            detail=f"Browser could not launch ({(stderr or '').strip() or 'unknown error'}).",
        )

    return {"status": "ok"}


# Deliberately simple (not full RFC 5322) — good enough to catch obvious
# typos/junk without rejecting real addresses over edge-case formatting.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_EMAIL_LENGTH = 254  # RFC 5321's own limit on a mailbox address

EARLY_ACCESS_CSV = os.path.join(BASE_DIR, "early_access.csv")
# Guards the CSV append so two simultaneous signups (server.py routes run
# in a threadpool) can't interleave their writes into one corrupted line.
_early_access_lock = threading.Lock()

# Render's disk is ephemeral — early_access.csv gets wiped on every deploy,
# so it can't be the only record of a signup. Emailing each one out is the
# durable channel; the CSV is kept too, as a convenient local/between-
# deploys record, but is not load-bearing once this is deployed. If SMTP
# isn't configured (e.g. local dev), sending is skipped rather than
# treated as an error — see _notify_early_access_signup.
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
EARLY_ACCESS_NOTIFY_EMAIL = os.environ.get(
    "EARLY_ACCESS_NOTIFY_EMAIL", "info@getbuggy.ai"
)


def _notify_early_access_signup(email, timestamp):
    if not (SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD):
        return

    msg = EmailMessage()
    msg["Subject"] = "GetBuggy early access signup"
    msg["From"] = SMTP_USERNAME
    msg["To"] = EARLY_ACCESS_NOTIFY_EMAIL
    msg.set_content(f"New early access signup: {email}\nAt: {timestamp}")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        # Don't fail the signup over a flaky SMTP relay — the CSV write
        # (which already happened by the time this runs) still has it.
        print(f"early-access notification email failed: {e}", file=sys.stderr)


class EarlyAccessRequest(BaseModel):
    email: str


@app.post("/api/early-access")
def early_access(req: EarlyAccessRequest):
    email = req.email.strip()
    if not email or len(email) > MAX_EMAIL_LENGTH or not EMAIL_RE.match(email):
        raise HTTPException(
            status_code=400, detail="Please enter a valid email address."
        )

    timestamp = datetime.now(timezone.utc).isoformat()
    with _early_access_lock:
        is_new_file = not os.path.exists(EARLY_ACCESS_CSV)
        with open(EARLY_ACCESS_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if is_new_file:
                writer.writerow(["email", "timestamp"])
            writer.writerow([email, timestamp])

    _notify_early_access_signup(email, timestamp)

    # Funnel stage 3 of 3 — deliberately no email address in the log line
    # itself (see _log_funnel_event): the CSV row above is the record of
    # *who*, kept separately; this is only a count.
    _log_funnel_event("email_captured")

    return {"ok": True}


_LEGAL_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ — GetBuggy</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%90%9B%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  :root { --bg: #ffffff; --text: #17181a; --muted: #8a8f98; --border: #e6e6e9; --accent: #17181a; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: 'Nunito', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
  }
  .topbar { display: flex; align-items: center; gap: 8px; padding: 28px 40px; width: fit-content; text-decoration: none; color: inherit; }
  .logo-icon { width: 34px; height: 34px; flex-shrink: 0; }
  .logo-text { font-size: 20px; font-weight: 700; }
  main { max-width: 680px; margin: 0 auto; padding: 16px 24px 80px; line-height: 1.65; }
  .back-link { display: inline-block; margin-bottom: 24px; color: var(--muted); font-size: 14px; text-decoration: none; }
  main h1 { font-size: 30px; margin-top: 0; }
  main h2 { font-size: 19px; margin-top: 36px; }
  main h3 { font-size: 16px; margin-top: 24px; }
  main blockquote {
    background: #fdf6e3;
    border: 1px solid #f0dfa0;
    border-radius: 10px;
    padding: 14px 18px;
    color: #6b5a12;
    font-size: 14px;
    margin: 0 0 24px;
  }
  main p, main li { color: #3a3c40; font-size: 15px; }
  main a { color: var(--accent); }
  main ul { padding-left: 20px; }
</style>
</head>
<body>
  <a class="topbar" href="/" aria-label="GetBuggy home">
    <svg class="logo-icon" viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <path d="M12 12 L8 6" stroke="#17181a" stroke-width="2" stroke-linecap="round"/>
      <path d="M28 12 L32 6" stroke="#17181a" stroke-width="2" stroke-linecap="round"/>
      <circle cx="20" cy="22" r="14" fill="#17181a"/>
      <circle cx="15" cy="21" r="3" fill="white"/>
      <circle cx="25" cy="21" r="3" fill="white"/>
      <circle cx="15" cy="21.5" r="1.3" fill="#17181a"/>
      <circle cx="25" cy="21.5" r="1.3" fill="#17181a"/>
      <path d="M15 28 Q20 32 25 28" stroke="white" stroke-width="2" fill="none" stroke-linecap="round"/>
    </svg>
    <span class="logo-text">GetBuggy</span>
  </a>
  <main>
    <a class="back-link" href="/">&larr; Back to GetBuggy</a>
    __CONTENT__
  </main>
</body>
</html>
"""


def _render_legal_page(md_filename, title):
    path = os.path.join(LEGAL_DIR, md_filename)
    with open(path, "r", encoding="utf-8") as f:
        md_text = f.read()
    content_html = render_markdown(md_text)
    return _LEGAL_PAGE_TEMPLATE.replace("__TITLE__", title).replace(
        "__CONTENT__", content_html
    )


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page():
    return _render_legal_page("privacy-policy.md", "Privacy Policy")


@app.get("/terms", response_class=HTMLResponse)
def terms_page():
    return _render_legal_page("terms-of-service.md", "Terms of Service")


# Serves the frontend (static/index.html and friends). Mounted last so it
# doesn't shadow the /api/check and /version routes above.
app.mount("/", StaticFiles(directory="static", html=True), name="static")


if __name__ == "__main__":
    # Local entry point (`python server.py`). Production runs the same app via
    # the Dockerfile's uvicorn command; PORT matches its default.
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
