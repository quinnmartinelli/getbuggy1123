"""Stand-in for run_site_check_subprocess.py, used by
tests/test_server_partial.py. The first argument (normally the URL) picks
the behavior, so the server's real job runner, watchdog and line parser
can be exercised with no browser:

  hang   - discovery done, 2 of 5 pages finished, then never finishes
  slow_discovery - never gets past discovery
  die    - 2 pages finished, then exits non-zero (host killed it)
  die_early - exits non-zero before anything
  die_after_meta - site-wide checks done, then exits non-zero before any page
  bad_result - every page finished, but the final RESULT line is garbage
  ok     - finishes normally
  slow_ok - like ok, but takes a few seconds (to hold a slot busy)

A real-looking URL (https://x.com/?mode=ok) carries the mode in its query
string, so tests that need a genuine URL (re-checks of the same site) work.
"""
import json
import sys
import time
from urllib.parse import parse_qs, urlparse

mode = sys.argv[1]
if mode.startswith("http"):
    mode = parse_qs(urlparse(mode).query).get("mode", ["ok"])[0]
SELECTED = [f"https://x.com/p{i}" for i in range(5)]
META = {
    "pages_found_total": 37, "pages_planned": 5, "selected": SELECTED,
    "pages_skipped": ["https://x.com/skipped"], "used_sitemap": True,
    "sitemap_source": "https://x.com/sitemap.xml",
    "site_findings": [{"category": "Sitemap Lists Missing Pages", "message": "m", "severity": "medium", "confidence": "verified"}],
    "site_could_not_check": [],
}


def page(i):
    return {"url": SELECTED[i], "problems": [], "could_not_check": []}


def emit(line):
    print(line, flush=True)


if mode == "die_early":
    print("boom", file=sys.stderr)
    sys.exit(1)
if mode == "slow_discovery":
    time.sleep(600)

emit("META " + json.dumps(META))
if mode == "die_after_meta":
    sys.exit(137)
if mode == "slow_ok":
    time.sleep(3)
if mode in ("hang", "die"):
    for i in (1, 0):  # out of order on purpose: pages finish in any order
        emit(f"PAGE {i} " + json.dumps(page(i)))
        emit(f"PROGRESS {2 if i == 0 else 1} 5")
    if mode == "die":
        sys.exit(137)
    time.sleep(600)
else:
    for i in range(5):
        emit(f"PAGE {i} " + json.dumps(page(i)))
        emit(f"PROGRESS {i + 1} 5")
    result = dict(META, pages_checked=5, pages=[page(i) for i in range(5)], partial=False)
    emit("RESULT {not json" if mode == "bad_result" else "RESULT " + json.dumps(result))
