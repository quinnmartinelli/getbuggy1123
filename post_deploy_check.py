"""Run after every deploy to confirm the live server actually picked up
the commit that was just pushed, and that a real check completes
successfully end-to-end — not just that the process answers requests.

Checks, in order: /version (deployed commit matches), /health (the
browser can actually launch — see server.py), then two real checks
against the live service:
1. A single trivial page (https://example.com) — a fast, cheap smoke test
   that the API works at all.
2. A real 3-page crawl of a real multi-page site (medvi.org, the same
   site the regression harness already treats as a known-good live
   baseline) — added 2026-09-17, after a real 10-page live crawl of the
   same site crashed the deployed Render container three times in a row
   (see PROJECT_STATUS.md Known Issues). A single trivial page never
   exercises real multi-page concurrent crawling, so it never would have
   caught that. This deliberately asks for only 3 pages (via the
   page_cap request field server.py added for exactly this — see
   server.py's CheckRequest), not a full CRAWL_PAGE_CAP crawl, so this
   runs after every deploy without being an expensive, wasteful check.

4. With --timed-crawl (added GetBuggy Step 4): a full-size crawl of
   medvi.org exactly as a visitor would get it (the server's own page cap,
   no page_cap override), which must finish — as a complete, not partial,
   report — in under TIMED_CRAWL_LIMIT_SECONDS (2 minutes).

Usage:
    python post_deploy_check.py https://getbuggy.onrender.com [--timed-crawl]
    python post_deploy_check.py --url http://localhost:8000 [--timed-crawl]

--url is for pointing this at a local dev server (e.g. while Render is
intentionally left suspended for local testing, see PROJECT_STATUS.md) —
the positional form above still works and both do the same thing.
"""
import sys
import subprocess
import time

import requests

POLL_INTERVAL_SECONDS = 2
POLL_TIMEOUT_SECONDS = 90

CAPACITY_CHECK_URL = "http://medvi.org"
CAPACITY_CHECK_PAGE_CAP = 3
# CRAWL_CONCURRENCY was dropped to 1 on 2026-09-18 (see PROJECT_STATUS.md
# Known Issues) after concurrency 2 still crashed the live container —
# checking pages one at a time instead of in parallel is slower by
# design, so this check needs a longer window than the single-page smoke
# test above.
CAPACITY_CHECK_TIMEOUT_SECONDS = 240

TIMED_CRAWL_LIMIT_SECONDS = 120


def get_local_commit():
    """The commit checked out here, or None when this folder isn't a git
    checkout (then /version can't be matched to a commit — said so below)."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return result.stdout.strip()


def check_report_features(base_url, job):
    """Step 8: the finished report carries a score, a permalink that opens
    without login and never shows security details, and the "send to your
    web person" export."""
    result = job["result"]
    score = result.get("score") or {}
    if "value" not in score:
        print("FAIL: the report has no score.")
        sys.exit(1)
    if score["value"] is None:
        print(f"NOTE: no score for this run — {score.get('reason')}")
    else:
        print(f"OK: score {score['value']}/100 — {score.get('band')} "
              f"({score.get('timing_sensitive_points', 0)} timing-sensitive points)")
    report_id = result.get("report_id")
    if not report_id:
        print("FAIL: the report has no permalink id.")
        sys.exit(1)
    page = requests.get(f"{base_url}/r/{report_id}", timeout=15)
    shared = requests.get(f"{base_url}/api/report/{report_id}", timeout=15)
    export = requests.get(f"{base_url}/api/report/{report_id}/export", timeout=15)
    if not (page.ok and shared.ok and export.ok):
        print(f"FAIL: permalink/export answered {page.status_code}/{shared.status_code}/{export.status_code}.")
        sys.exit(1)
    shared_result = shared.json()["result"]
    if any(p.get("group") == "security" for p in
           (shared_result.get("unique_problems") or []) + (shared_result.get("site_findings") or [])):
        print("FAIL: the shared report shows security details — it must always be gated.")
        sys.exit(1)
    if not export.text.startswith("# Website check for"):
        print("FAIL: the export doesn't look like a report.")
        sys.exit(1)
    print(f"OK: permalink {base_url}/r/{report_id} opens, security gated; export is "
          f"{len(export.text.splitlines())} lines.")
    return score


def run_check_and_wait(base_url, url, label, page_cap=None, timeout_seconds=None):
    """POSTs /api/check for `url` and polls /api/check-status until it's
    done or errored. Exits the whole script on failure — every check run
    here is a required pass, not an optional/best-effort one. Returns the
    finished job dict on success."""
    timeout_seconds = timeout_seconds or POLL_TIMEOUT_SECONDS
    print(f"Running a real check against {url} ({label}) ...")
    # authorized: True — this script is checking a site GetBuggy's own
    # founders operate (medvi.org, example.com), standing in for the
    # authorization checkbox real visitors must check before /api/check
    # will accept a request at all (see server.py's CheckRequest).
    payload = {"url": url, "authorized": True}
    if page_cap is not None:
        payload["page_cap"] = page_cap
    resp = requests.post(f"{base_url}/api/check", json=payload, timeout=15)
    resp.raise_for_status()
    job_id = resp.json()["job_id"]

    # /api/check kicks off a background job and returns immediately (a
    # crawl can take minutes) — poll /api/check-status until it's done.
    started = time.monotonic()
    deadline = started + timeout_seconds
    while True:
        if time.monotonic() > deadline:
            print(f"FAIL: {label} did not finish within {timeout_seconds}s.")
            sys.exit(1)

        time.sleep(POLL_INTERVAL_SECONDS)
        try:
            resp = requests.get(f"{base_url}/api/check-status/{job_id}", timeout=15)
            resp.raise_for_status()
            job = resp.json()
        except requests.exceptions.RequestException as e:
            # A transient network blip on this end (this script's own
            # connection, not the server) shouldn't fail the whole check —
            # just try again on the next poll, same as any other still-
            # running iteration. A genuine server-side problem shows up as
            # a real "error"/"done" status once connectivity recovers, or
            # this loop still hits its own timeout above if it doesn't.
            print(f"  (transient: {e.__class__.__name__} — retrying)")
            continue

        if job["status"] == "error":
            print(f"FAIL: {label} errored — {job['detail']}")
            sys.exit(1)
        if job["status"] == "done":
            elapsed = time.monotonic() - started
            job["elapsed_seconds"] = elapsed
            print(f"OK: {label} — {job['result']['summary']} (took {elapsed:.0f}s)")
            return job


def main():
    raw_args = sys.argv[1:]
    timed_crawl = "--timed-crawl" in raw_args
    url_flag = None
    if "--url" in raw_args:
        i = raw_args.index("--url")
        if i + 1 >= len(raw_args):
            print("Usage: --url requires a value, e.g. --url http://localhost:8000")
            sys.exit(1)
        url_flag = raw_args[i + 1]
    positional = [a for a in raw_args if not a.startswith("--") and a != url_flag]

    if url_flag and positional:
        print("Usage: pass either a positional base URL or --url, not both.")
        sys.exit(1)
    base_url = url_flag or (positional[0] if positional else None)
    if not base_url:
        print("Usage: python post_deploy_check.py <base-url> [--timed-crawl]")
        print("       python post_deploy_check.py --url <base-url> [--timed-crawl]")
        print("Example: python post_deploy_check.py https://getbuggy.onrender.com")
        sys.exit(1)
    base_url = base_url.rstrip("/")
    local_commit = get_local_commit()

    print(f"Checking {base_url} ...")

    resp = requests.get(f"{base_url}/version", timeout=15)
    resp.raise_for_status()
    live_commit = resp.json().get("commit")

    if local_commit is None:
        # Not a git checkout: nothing to compare against. Say so rather
        # than pretend the commit was confirmed.
        print(f"NOTE: this folder isn't a git checkout, so /version ({live_commit!r}) can't be "
              "matched to a commit.")
    elif live_commit != local_commit:
        print(
            f"FAIL: live server is running commit {live_commit}, expected "
            f"{local_commit}. The deploy may still be in progress — wait a "
            "bit and retry, or check the Render dashboard."
        )
        sys.exit(1)
    else:
        print(f"OK: live server is running the expected commit ({live_commit[:8]}).")

    # /health actually launches a real browser (see server.py) — a
    # different, more specific failure signal than /version (which only
    # proves the server process itself is up): a bad deploy/environment
    # (missing Chromium deps, a broken Docker image) would still answer
    # /version but fail this.
    health_resp = requests.get(f"{base_url}/health", timeout=30)
    if not health_resp.ok:
        print(
            f"FAIL: /health returned {health_resp.status_code} — "
            f"{health_resp.text.strip()}"
        )
        sys.exit(1)
    print(f"OK: /health — {health_resp.json()}")

    run_check_and_wait(base_url, "https://example.com", "single-page smoke test")

    job = run_check_and_wait(
        base_url,
        CAPACITY_CHECK_URL,
        f"{CAPACITY_CHECK_PAGE_CAP}-page live capacity check",
        page_cap=CAPACITY_CHECK_PAGE_CAP,
        timeout_seconds=CAPACITY_CHECK_TIMEOUT_SECONDS,
    )
    pages_checked = job["result"]["pages_checked"]
    if pages_checked != CAPACITY_CHECK_PAGE_CAP:
        print(
            f"FAIL: capacity check only completed {pages_checked} of "
            f"{CAPACITY_CHECK_PAGE_CAP} requested pages."
        )
        sys.exit(1)

    if job["result"].get("partial"):
        print(f"FAIL: the capacity check came back as a partial report "
              f"({job['result'].get('partial_reason')}): {job['result'].get('not_completed')}")
        sys.exit(1)

    check_report_features(base_url, job)

    if timed_crawl:
        job = run_check_and_wait(
            base_url,
            CAPACITY_CHECK_URL,
            "full-size timed crawl",
            timeout_seconds=TIMED_CRAWL_LIMIT_SECONDS + 60,
        )
        result = job["result"]
        if result.get("partial") or result["pages_checked"] != result["pages_planned"]:
            print("FAIL: the timed crawl was partial — it did not finish every page it planned.")
            sys.exit(1)
        if job["elapsed_seconds"] > TIMED_CRAWL_LIMIT_SECONDS:
            print(
                f"FAIL: the timed crawl took {job['elapsed_seconds']:.0f}s, over the "
                f"{TIMED_CRAWL_LIMIT_SECONDS}s target."
            )
            sys.exit(1)
        print(
            f"OK: {result['pages_checked']}-page crawl finished in "
            f"{job['elapsed_seconds']:.0f}s (target: under {TIMED_CRAWL_LIMIT_SECONDS}s)."
        )

    print("Post-deploy check passed.")


if __name__ == "__main__":
    main()
