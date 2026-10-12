"""Core Web Vitals check: measures LCP and CLS on a fresh page load.

Follows the same shape as core.py's check_mobile_responsiveness: opens a
fresh browser.new_page(), navigates, evaluates some JS, and appends problem
dicts ({"category", "message", "severity", "confidence"}) to the shared
problems list.

CLS (layout shift) is reported against Google's fixed published
thresholds, since it measures visual instability, not timing — it doesn't
care how fast or slow the checking environment is, so it's
`confidence: verified`.

LCP (a *timing* metric — how long until the main content is visibly
painted) is judged against Google's own published absolute thresholds
(LCP_GOOD_MAX_MS/LCP_POOR_MIN_MS below), same as CLS — not as a multiple
of a reference page's load time (a ratio like "94.8x slower than a 0.1s
page" is alarming and meaningless; see core.py's page-load-time check for
the same fix, made the same day testing heavenmayhem.com). The reference
page (`baseline_ms`) is still measured and still used, just as an internal
sanity check (REFERENCE_PAGE_UNRELIABLE_MS): if this checker's own
environment is currently loading pages slowly, an absolute LCP reading
can't be trusted to reflect the target site rather than us, so the
finding is skipped rather than risk blaming the site. This still measures
*our* Chromium instance's rendering, on *our* host, not a real visitor's
device and connection — so LCP is always `confidence: needs_look`, never
treated as a confirmed defect on its own (CLS, a pure visual-stability
measurement unaffected by rendering speed, is `verified`). Self-contained
module (its own HIGH/MEDIUM/LOW, not imported from core.py) to avoid a
circular import, since core.py imports from here.
"""

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

VERIFIED = "verified"
NEEDS_LOOK = "needs_look"

# Google's published Core Web Vitals threshold for CLS (not time-based, so
# unaffected by the checking environment's own speed).
# https://web.dev/articles/cls
CLS_GOOD_MAX = 0.1
CLS_POOR_MIN = 0.25

# Google's published Core Web Vitals thresholds for LCP.
# https://web.dev/articles/lcp
# Same absolute-threshold-over-ratio reasoning as core.py's
# PAGE_LOAD_LOW_MIN_SECONDS/PAGE_LOAD_MEDIUM_MIN_SECONDS (found testing
# heavenmayhem.com: "5.0s — about 94.8x slower than a 0.1s reference
# page" is alarming and meaningless) — LCP gets Google's own thresholds
# rather than reusing the page-load ones, since 2.5s is a genuinely
# different bar for "main content visible" than it is for "whole page
# loaded." `baseline_ms` is still measured and still used, just as an
# internal sanity check that this checker's own environment is fast
# enough right now to trust (same as core.py's
# REFERENCE_PAGE_UNRELIABLE_MS), never shown in the message.
LCP_GOOD_MAX_MS = 2500
LCP_POOR_MIN_MS = 4000
REFERENCE_PAGE_UNRELIABLE_MS = 2000

# LCP/CLS can still receive updates for a short while after the "load"
# event fires (late-arriving large elements, layout shifts from
# still-loading web fonts or images, etc). Waiting a couple more seconds
# after goto() before reading the metrics back gives them a chance to
# settle without dragging out every check by too much.
POST_LOAD_SETTLE_MS = 2500

# Installed via add_init_script so it's in place *before* navigation starts.
# A plain post-load page.evaluate() would be too late: LCP in particular is
# reported once and can finish firing well before a post-load evaluate()
# ever gets a chance to attach an observer, silently producing no data (or
# stale data from a previous unrelated paint) instead of a real reading.
_VITALS_INIT_SCRIPT = """
(() => {
  window.__gbVitals = { lcp: 0, cls: 0 };

  try {
    new PerformanceObserver((list) => {
      const entries = list.getEntries();
      const last = entries[entries.length - 1];
      if (last) {
        window.__gbVitals.lcp = last.renderTime || last.startTime;
      }
    }).observe({ type: 'largest-contentful-paint', buffered: true });
  } catch (e) {
    // Browser doesn't support this entry type; leave lcp at 0.
  }

  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (!entry.hadRecentInput) {
          window.__gbVitals.cls += entry.value;
        }
      }
    }).observe({ type: 'layout-shift', buffered: true });
  } catch (e) {
    // Browser doesn't support this entry type; leave cls at 0.
  }
})();
"""


def _cls_rating(score):
    if score <= CLS_GOOD_MAX:
        return "good"
    if score <= CLS_POOR_MIN:
        return "needs improvement"
    return "poor"


def check_core_web_vitals(browser, url, timeout_ms, problems, baseline_ms=None, could_not_check=None):
    """Load the page fresh (with performance observers wired up before
    navigation) and report LCP relative to `baseline_ms` (see
    core._measure_reference_baseline) and CLS against Google's fixed
    thresholds. Only reports metrics that are actually degraded, matching
    the rest of the project's checks.

    If the check itself can't complete (most commonly: this fresh
    navigation times out on an unusually slow/heavy page), that's an
    expensive check we couldn't finish, not a "problem" with the page —
    recorded in `could_not_check` instead of `problems` if a list is
    given."""
    vitals_page = browser.new_page()
    try:
        vitals_page.add_init_script(_VITALS_INIT_SCRIPT)
        vitals_page.goto(url, wait_until="load", timeout=timeout_ms)
        vitals_page.wait_for_timeout(POST_LOAD_SETTLE_MS)

        result = vitals_page.evaluate("() => window.__gbVitals")
        lcp_ms = result.get("lcp") or 0
        cls_score = result.get("cls") or 0

        # baseline_ms gates whether this checker's own environment is
        # currently fast enough to trust an absolute reading at all — see
        # REFERENCE_PAGE_UNRELIABLE_MS above. Never shown in the message.
        if baseline_ms and baseline_ms <= REFERENCE_PAGE_UNRELIABLE_MS and lcp_ms > LCP_GOOD_MAX_MS:
            severity = MEDIUM if lcp_ms >= LCP_POOR_MIN_MS else LOW
            problems.append(
                {
                    "category": "Largest Contentful Paint",
                    "message": (
                        f"The main content of the page took {lcp_ms / 1000:.1f}s "
                        "to visibly appear. This could mean visitors are left "
                        "staring at a mostly blank page before the important "
                        "part shows up. Needs a look: measured from our "
                        "servers; your visitors may see different numbers — "
                        "worth a second look (e.g. with Google PageSpeed "
                        "Insights) before treating it as confirmed."
                    ),
                    "severity": severity,
                    "confidence": NEEDS_LOOK,
                }
            )

        cls_rating = _cls_rating(cls_score)
        if cls_rating != "good":
            severity = MEDIUM if cls_rating == "poor" else LOW
            problems.append(
                {
                    "category": "Layout Shifts While Loading",
                    "message": (
                        f"Page content jumps around while loading (layout shift "
                        f"score {cls_score:.2f}, rated {cls_rating}) — text, "
                        "images, or buttons visibly move after the page appears "
                        "to be ready, which can cause visitors to misclick or "
                        f"lose their place. Google considers anything over "
                        f"{CLS_GOOD_MAX:.2f} a problem, and over {CLS_POOR_MIN:.2f} "
                        "poor."
                    ),
                    "severity": severity,
                    "confidence": VERIFIED,
                }
            )
    except Exception as e:
        note = (
            f"Couldn't finish the page speed / stability check on this page "
            f"({e.__class__.__name__}) — often means the page was too slow "
            "or heavy to finish loading within our time budget."
        )
        if could_not_check is not None:
            could_not_check.append(note)
        else:
            problems.append(
                {
                    "category": "Core Web Vitals Check Failed",
                    "message": note,
                    "severity": LOW,
                    "confidence": NEEDS_LOOK,
                }
            )
    finally:
        vitals_page.close()
