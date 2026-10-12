"""Runs core.run_site_check() (whole-site crawl) in a standalone process
and prints progress + the final result as lines on stdout. Invoked by
server.py as a subprocess (not imported directly), so a crawl that runs
too long can be killed outright — Chromium child process included — via
the OS. A thread-based timeout can't do that; the thread would just keep
running in the background, leaking the browser process's memory.

Output format (one per line, so the parent can read incrementally rather
than waiting for the whole process to exit):
    META <json>                    (once, after discovery: pages found/selected/skipped,
                                    site-wide findings)
    PAGE <index> <json>            (one per page, the moment it finishes)
    PROGRESS <completed> <total>   (one per page as it finishes)
    RESULT <json>                  (once, at the end)
META and PAGE exist so that if the parent has to kill this process at the
6-minute cap, it already holds everything gathered so far and can return a
partial report instead of a bare error (GetBuggy Step 4).

Memory ceiling (added 2026-09-17, after a real live-server crawl of
medvi.org crashed the whole deployed Render container three times in a
row — see PROJECT_STATUS.md Known Issues): this process's own address
space is capped via `resource.setrlimit(RLIMIT_AS, ...)`, set as the
very first thing in main(), before Playwright/Chromium ever launches.
POSIX child processes inherit their parent's rlimits at fork time, so
every Chromium process this subprocess spawns (one full browser per
concurrently-checked page — see core.py's _check_page_standalone) is
ALSO capped at the same ceiling individually. This is deliberately not
a true aggregate cap across the whole process tree (RLIMIT_AS is
per-process, not per-cgroup) — a true aggregate cap would need cgroup
delegation, which isn't something to assume a PaaS container grants —
but it's a real, meaningful, and locally-testable safety net: no single
runaway page (a memory leak, a pathological huge-inline-data-URI page)
can balloon past the ceiling on its own, and combined with a lower
CRAWL_CONCURRENCY (see core.py), it keeps the realistic aggregate well
under the container's total memory rather than letting one bad page (or
the accumulation of several) approach it.

If a Chromium child process hits its inherited limit, Playwright
surfaces that as an ordinary exception from whichever page-check was in
flight — already handled per-page by run_site_check's existing
per-future try/except (see core.py), which degrades that one page to a
`could_not_check` note rather than failing the whole crawl. If this
process's OWN allocation hits the limit (rarer — most of the memory use
here is the browsers, not this thin Python driver), that raises
MemoryError, caught below and reported as a clean one-line message
instead of a raw traceback.
"""
import os
import resource
import sys
import json

from core import run_site_check, sort_problems

# 0 (disabled) by default — see the 2026-09-18 note above.
SUBPROCESS_MEMORY_LIMIT_MB = int(
    os.environ.get("CRAWL_SUBPROCESS_MEMORY_LIMIT_MB", "0")
)


def _apply_memory_ceiling():
    """Best-effort — some platforms/environments don't allow lowering
    RLIMIT_AS (or don't support it at all), and this is a safety net, not
    a correctness requirement, so a failure here is logged and swallowed
    rather than crashing the crawl before it even starts.

    DISABLED BY DEFAULT (2026-09-18): setting this ANY value on Render's
    real Linux container broke every check outright — Playwright's own
    Node.js driver process (which the Python client launches to talk to
    Chromium) hit the ceiling during its own startup and crashed with a
    V8 "JavaScript heap out of memory" error, before a single page was
    ever checked. RLIMIT_AS caps *virtual address space*, and V8
    reserves a large amount of that speculatively regardless of actual
    physical memory use — a well-documented RLIMIT_AS/V8 incompatibility,
    not something tunable by picking a different number (any limit large
    enough for V8's reservation to succeed is too loose to meaningfully
    cap real usage). Left here, disabled, as a documented dead end rather
    than deleted — see PROJECT_STATUS.md Known Issues for what's next."""
    if SUBPROCESS_MEMORY_LIMIT_MB <= 0:
        return  # explicit opt-out: 0 or negative disables the ceiling
    limit_bytes = SUBPROCESS_MEMORY_LIMIT_MB * 1024 * 1024
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
    except (ValueError, OSError, resource.error) as e:
        print(
            f"warning: could not set a {SUBPROCESS_MEMORY_LIMIT_MB}MB memory "
            f"ceiling ({e.__class__.__name__}: {e}) — continuing without one",
            file=sys.stderr,
        )


def main():
    _apply_memory_ceiling()

    target = sys.argv[1]
    page_cap = int(sys.argv[2])
    timeout_ms = int(sys.argv[3])
    # Step 7: optional, so an older caller without it still gets "us".
    jurisdiction = sys.argv[4] if len(sys.argv) > 4 else "us"

    def on_progress(completed, total):
        print(f"PROGRESS {completed} {total}", flush=True)

    def on_meta(meta):
        print("META " + json.dumps(meta), flush=True)

    def on_page(index, page):
        page = dict(page, problems=sort_problems(page["problems"]))
        print(f"PAGE {index} " + json.dumps(page), flush=True)

    try:
        result = run_site_check(
            target,
            page_cap=page_cap,
            timeout_ms=timeout_ms,
            on_progress=on_progress,
            on_meta=on_meta,
            on_page=on_page,
            jurisdiction=jurisdiction,
        )
    except MemoryError:
        print(
            f"This check ran out of memory (over its {SUBPROCESS_MEMORY_LIMIT_MB}MB "
            "limit) before it could finish.",
            file=sys.stderr,
        )
        sys.exit(1)

    for page in result["pages"]:
        page["problems"] = sort_problems(page["problems"])

    print("RESULT " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
