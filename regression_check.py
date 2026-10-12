"""Regression check for GetBuggy's core.py.

Runs core.run_check() against a fixed list of targets and compares the
*set of problem categories* it reports (and how many times each category
appears) against a known-good expected result for that target. Meant to be
run before every deploy, as a quick "did this change break anything" sanity
check.

Usage (from inside website-checker/, with the venv activated):

    source venv/bin/activate
    python regression_check.py

Exit code is 0 only if every target matches its expected result, non-zero
otherwise (so it's CI/pre-deploy-hook friendly).

What's compared: for each target, how many times each problem category
appears in the actual result vs. the expected result. Exact message text
is intentionally NOT compared (messages can legitimately vary run to run,
e.g. "7 element(s)..." vs "8 element(s)..." as content shifts slightly),
and severity/confidence/ordering are not compared either (severity and
confidence are determined entirely by category, which IS compared). A
target passes only when its actual category counts exactly match its
expected category counts — EXCEPT for the timing/perf categories listed
in TIMING_TOLERANT_CATEGORIES below (load time, LCP, CLS, TTFB, and the
other "primary" speed signals), which drift run to run even on a fixed
local fixture (network jitter, host load) and are compared within a
per-category tolerance band instead of exactly, and never fail the
harness on their own. `could_not_check` entries aren't compared at all —
they're plain-English notes, not categorized findings.

This script deliberately does NOT set ENABLE_REAL_FORM_SUBMISSION — it
unsets it defensively (see below) so this check always runs in the same
"default"/safe mode (no real form submissions sent anywhere) that the
publicly deployed app uses, regardless of what's set in the calling
shell's environment.
"""

import os
import sys
import time
from collections import Counter
from urllib.parse import urlparse

# Make sure "import core" works regardless of the caller's cwd, and force
# the default (safe) environment for this check: real form submission must
# stay off, since that's the mode the deployed app runs in and the mode
# these expected results were captured against. Popping it here (rather
# than just relying on the docstring/instructions above) means this script
# can't accidentally produce a false pass/fail just because someone had
# that var set in their shell.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.pop("ENABLE_REAL_FORM_SUBMISSION", None)
# The crawl fixtures below check pages two at a time (what production runs
# at) rather than core's conservative default of 1 — keeps the harness
# fast. Must be set before core is imported (it reads this at import).
os.environ.setdefault("CRAWL_CONCURRENCY", "2")

from core import run_check, run_site_check, _is_utility_page  # noqa: E402
from fixture_server import serve as _serve_fixture_site  # noqa: E402
from embedded_form_providers import TEST_PROVIDER_HOST_ENV_VAR  # noqa: E402

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_SITE_DIR = os.path.join(SCRIPT_DIR, "test_site")
TEST_SITE_PORT = 8977
EMBEDDED_TEST_SITE_DIR = os.path.join(SCRIPT_DIR, "test_site_embedded")
EMBEDDED_TEST_SITE_PORT = 8978


# ---------------------------------------------------------------------------
# Targets. Add new ones here as the project grows — each entry just needs a
# name, a target (URL or local file path; local paths are resolved relative
# to this script's directory), and the expected problem categories as a
# dict of {category: expected_count}.
# ---------------------------------------------------------------------------
TARGETS = [
    {
        "name": "test_page.html (local fixture with planted bugs)",
        "target": os.path.join(SCRIPT_DIR, "test_page.html"),
        "expected_categories": {
            "Failed Network Request": 1,
            "JavaScript Crash": 1,
            "Broken Form": 1,
            "Broken Link": 1,
            "Mobile Horizontal Scroll": 1,
            "Missing Alt Text": 1,
            "Form Not Fully Verified": 1,
            # Genuinely missing on this fixture (it has a <title> and an
            # <h1>, but no meta description or favicon link) — added
            # 2026-09-16 when checks_seo.py was wired into core.py.
            "Missing Meta Description": 1,
            "Missing Favicon": 1,
        },
    },
    {
        # Case 1 (multi-step/wizard forms) — see reviews/2026-09-16-form-
        # check-review.md finding #1. #wizard-form advances through a
        # real 2-step wizard whose step-2 heading contains "confirm" (the
        # exact false-positive trap) but whose real final submit is
        # intentionally broken — this must resolve to a genuine "Broken
        # Form", not a false "working" verdict from the step-1 click
        # alone. #stuck-wizard-form's "Next" control is broken (does
        # nothing), so it must resolve to "Form Needs A Look", not
        # "Broken Form".
        "name": "test_page_wizard.html (multi-step form fixture)",
        "target": os.path.join(SCRIPT_DIR, "test_page_wizard.html"),
        "expected_categories": {
            "Broken Form": 1,
            "Form Needs A Look": 1,
        },
    },
    {
        # Case 3 (non-button submit triggers) — see review finding #3.
        # #role-button-form's real trigger is a styled div[role=button]
        # with a click listener (no <form>.submit()/requestSubmit() call
        # at all) — only a real click finds this. #enter-form has no
        # button of any kind, relying on Enter-to-submit. #mystery-form
        # has no button, no role=button, no click-handler-looking
        # element, and no fillable text field either — there's genuinely
        # no way to submit it, so it must resolve to "Form Needs A Look".
        "name": "test_page_form_triggers.html (non-button submit trigger fixture)",
        "target": os.path.join(SCRIPT_DIR, "test_page_form_triggers.html"),
        "expected_categories": {
            "Form Needs A Look": 1,
        },
    },
    {
        # Case 4 (HTML5 validation) — see review finding #4. #phone-form's
        # required tel field has a dashed pattern the old generic
        # "5555555555" fill fails, which used to silently block the
        # submit and produce a false HIGH "Broken Form"; the fix must
        # generate a matching value ("555-555-5555") so this resolves
        # clean. #coupon-form's pattern can't be satisfied by any
        # reasonable generic guess, so it must resolve to "Form Needs A
        # Look" naming the field, not a submit attempt.
        "name": "test_page_form_validation.html (HTML5 validation fixture)",
        "target": os.path.join(SCRIPT_DIR, "test_page_form_validation.html"),
        "expected_categories": {
            "Form Needs A Look": 1,
        },
    },
    {
        # Case 2 (iframe-embedded forms) — see review finding #2. Uses a
        # local HTTP server (not a live Calendly/Typeform/etc. site) with
        # one working page and one path that 404s, and points
        # GETBUGGY_TEST_EMBEDDED_PROVIDER_HOST at that local server so
        # detect_embedded_form_provider recognizes it as a stand-in
        # provider — see run_embedded_form_target() below.
        "name": "test_page_iframe_form.html (embedded-form fixture)",
        "mode": "embedded_form",
        "target": os.path.join(SCRIPT_DIR, "test_page_iframe_form.html"),
        "expected_categories": {
            "Embedded Form": 2,
            # The broken iframe's own real (main-page) navigation to a
            # 404 is also caught by core.py's ordinary failed-resource
            # listener — a genuine, pre-existing, unrelated side effect
            # of embedding a broken iframe at all, not something
            # check_embedded_forms itself produces.
            "Third-Party Resource Failed": 1,
        },
    },
    {
        # LIVE NETWORK CHECK against a real third-party site we don't
        # control. Verified against the actual current output of
        # medvi.org's homepage. Unlike the local fixture above, this can
        # start failing purely because medvi.org's own site changed (new
        # content, a fixed/broken link, a redesigned mobile layout, a
        # transient network timeout hitting one of their links) — that's
        # expected and informative, not necessarily a regression in this
        # codebase. If this target starts failing, check whether the site
        # itself changed before assuming core.py broke.
        #
        # Note: medvi.org's mobile layout has some text under 12px and some
        # tap targets under 24x24px, but those checks were removed entirely
        # as a product decision 2026-09-26 (see PLAN.md) — small text on a
        # brand site is a design choice, not a bug. Expected values below
        # reflect what run_check() actually, repeatedly returns now.
        #
        # Also observed while verifying: medvi.org links to
        # https://meals.medvi.org, a subdomain that responds slowly enough
        # to occasionally exceed core.py's request timeout — in repeated
        # runs this showed up as an extra "Broken Link" problem roughly
        # half the time, purely from response timing, not from the link
        # actually being broken (manually confirmed the same timeout
        # happens intermittently outside of run_check() too). That's
        # real-world live-network noise, not a code regression, so it's
        # listed in flaky_categories below: if it appears, it's noted but
        # doesn't fail this target. If it starts appearing on every run (or
        # a NEW category shows up), that's worth investigating for real.
        "name": "medvi.org (live external site)",
        "target": "http://medvi.org",
        # Marks this target as depending on live, real-world network
        # state — excluded from --skip-live (what CI runs on every push
        # and PR; see .github/workflows/ci.yml), included in the
        # separately-scheduled live-regression workflow (manual dispatch
        # or a daily cron), per the standing rule that live-site
        # baselines never run on every push. Every other target here is
        # a local fixture (or a local HTTP server serving one) and stays
        # in both.
        "live": True,
        "expected_categories": {
            # Genuinely missing on medvi.org's homepage — added 2026-09-16
            # when checks_seo.py was wired into core.py. No other new SEO
            # or Core Web Vitals problems currently appear on this site.
            "Missing H1 Heading": 1,
            # medvi.org's homepage genuinely has 2 inline <script> tags in
            # <head> without async/defer — added 2026-09-17 when
            # check_render_blocking_scripts shipped (Step 2). A real,
            # structural (confidence: verified) finding on the live site,
            # not a false positive — see PROJECT_STATUS.md.
            "Render-Blocking Scripts": 1,
            # Added 2026-09-21 (Step 4): the homepage genuinely has links
            # whose visible text is a bare URL (e.g. the partner pharmacy
            # sites) — the new link-text-quality check groups them into one
            # LOW finding. A real property of the live site, not drift.
            "Vague Link Text": 1,
        },
        "flaky_categories": {
            "Broken Link": 1,
        },
    },
    {
        # LIVE WHOLE-SITE CRAWL against a real Shopify store we don't
        # control (the ten-business test's first target — see
        # PROJECT_STATUS.md Step 5). Unlike medvi.org above, this is a
        # `run_site_check()` crawl (5 pages), and this particular site is
        # complex and tracker-heavy enough that exact per-category counts
        # would flap constantly on nothing this codebase controls: which
        # of ~15 third-party trackers happens to be timing out this run,
        # and even whether cakesbody.com's own sitemap.xml is discovered
        # in time (observed both True and False across repeated runs),
        # both change which of the site's 36-185 pages get selected —
        # see `skip_category_check` in run_crawl_target(). What's checked
        # instead is the actual regression this step's three fixes exist
        # to prevent:
        #   1. JS errors aren't blamed on the site unless they're
        #      first-party AND something visibly broke (never verified
        #      here directly — the sitemap-exclusion guard below is the
        #      structural check that generalizes; the JS-crash logic
        #      itself is covered by test_page.html above and by unit
        #      tests).
        #   2. Cross-page dedup keeps the unique-problem count bounded —
        #      before the Step 5 fixes, this same site reported 382
        #      "problems" on 5 pages; after Step 5, repeated runs landed
        #      in the 40-60 range; after Step 5.1 (ERR_ABORTED and its
        #      local-network cousins moved to could_not_check instead of
        #      being reported as findings — this site's own product
        #      videos/images kept tripping that exact false positive),
        #      observed range dropped further to the 25-45 range. Real,
        #      complex Shopify store, not a "clean" one (a genuine
        #      first-party JS crash, several broken checkout/tracking
        #      endpoints), so it doesn't land in a single fixed number.
        #      100 is a ceiling with real headroom above the observed
        #      range, tight enough to still catch a reversion toward
        #      one-problem-per-occurrence.
        #   3. /cart, /account, /search, /customer_authentication/*, and
        #      similar pages are never flagged as "missing from sitemap"
        #      — asserted directly.
        "name": "cakesbody.com (live external site, whole-site crawl)",
        "mode": "crawl",
        "target": "https://cakesbody.com",
        "live": True,
        "page_cap": 5,
        "skip_category_check": True,
        "expected_pages_checked": 5,
        "expected_max_unique_problems": 100,
    },
    {
        # LIVE WHOLE-SITE CRAWL against lingcode.dev — a friend's small
        # dev-tool site, second target in the ten-business test. Much
        # simpler than cakesbody.com (5 pages, 2 third-party trackers, no
        # Shopify noise), so unlike that target this one uses ordinary
        # exact per-category matching, same as medvi.org.
        #
        # This run is what caught a real bug in the Step 5 dedup fix
        # itself (see PROJECT_STATUS.md): a form with no `id`/`name`
        # attribute falls back to a positional label ("#1" = "the first
        # form on this page") for its human-readable message, but that
        # label isn't a stable cross-page identity — every one of this
        # site's 5 pages has its own distinct, separately-broken/
        # unverified first form, and using the bare label as dedup
        # evidence collapsed all 5 into one misleading "found on 5 pages"
        # finding, hiding that they're different forms. Fixed by scoping
        # the fallback evidence to the page URL (`form_evidence` in
        # `check_forms`); confirmed here — expected_categories below
        # counts `Form Not Fully Verified` as 5 raw occurrences, and
        # (checked directly against the live report during the fix, not
        # re-asserted here since this harness compares raw categories,
        # not the deduped view) each now shows as its own unique finding
        # instead of one shared entry.
        #
        # Third-party findings are Cloudflare Insights and Google Tag
        # Manager, unreachable from this environment on every single page
        # — the same two trackers first observed 2026-09-15 when this
        # site validated the original first-party/third-party split, so
        # treated as a stable (not flaky) fact about running this check
        # from here rather than tolerated noise.
        #
        # No "Failed Network Request" here even though the homepage's
        # /promotion.mp4 does hit an ERR_ABORTED (Step 5.1, see
        # PROJECT_STATUS.md): a real user reported this exact video as
        # "the site works fine but it says it doesn't work" — it's a
        # multi-second video still downloading when the per-page check
        # finished and closed the browser, not a broken resource.
        # ERR_ABORTED/ERR_NETWORK_CHANGED/ERR_INTERNET_DISCONNECTED now go
        # to could_not_check instead of being reported as a finding at
        # all (same place a 401 already went) — this target's
        # `all_could_not_check` count is not asserted (it's exactly the
        # kind of single-shot, environment-dependent signal that made
        # `cakesbody.com` above use a ceiling instead of an exact count),
        # but its absence from `expected_categories` is itself a
        # regression guard: if this ever reappears as a "Failed Network
        # Request" finding, that's the old misleading-HIGH bug back.
        "name": "lingcode.dev (live external site, whole-site crawl)",
        "mode": "crawl",
        "target": "https://lingcode.dev",
        "live": True,
        "page_cap": 5,
        "expected_pages_checked": 5,
        "expected_used_sitemap": True,
        "expected_categories": {
            "Broken Form": 1,
            "Form Not Fully Verified": 5,
            "Layout Shifts While Loading": 1,
            "Many Requests": 1,
            "Menu Pages Missing From Sitemap": 1,
            "Multiple H1 Headings": 1,
            "Render-Blocking Scripts": 4,
            "Third-Party Resource Failed": 10,
        },
        "expected_max_unique_problems": 20,
    },
    {
        # LIVE WHOLE-SITE CRAWL against blaze.ai — ten-business test site
        # #3 (a marketing/SaaS site on Webflow). This is the run that
        # caught two real bugs, both fixed the same day (see
        # PROJECT_STATUS.md Step 5.2): (1) app.blaze.ai/login came back
        # HTTP 403 (bot protection on their app subdomain, not a broken
        # login page) and used to be reported as a HIGH "Failed Network
        # Request" — now correctly routes to could_not_check, and the
        # rest of that page's checks are skipped entirely rather than
        # running against whatever WAF challenge page rendered instead
        # (see BOT_BLOCK_STATUSES handling in record_failed_request and
        # the early-return in _check_single_page). (2) that same WAF page
        # produced a garbled console.error that used to be an
        # unconditional HIGH "JavaScript Console Error" — now correctly
        # classified via _classify_js_errors the same way a raw JS
        # exception is.
        "name": "blaze.ai (live external site, whole-site crawl)",
        "mode": "crawl",
        "target": "https://blaze.ai",
        "live": True,
        "page_cap": 5,
        "expected_pages_checked": 5,
        "expected_used_sitemap": True,
        "expected_categories": {
            "Heavy Page": 1,
            "Link Needs A Look": 2,
            "Menu Pages Missing From Sitemap": 1,
            "Missing Alt Text": 1,
            "Missing H1 Heading": 1,
            "Oversized Images": 4,
            "Render-Blocking Scripts": 4,
            "Third-Party Resource Failed": 5,
        },
        "flaky_categories": {
            # Trustpilot/G2 review-site bot-blocking and third-party
            # tracker timeouts vary run to run — real network noise, not
            # a code regression (same reasoning as medvi.org's).
            "Link Needs A Look": 2,
            "Third-Party Resource Failed": 3,
        },
        "expected_max_unique_problems": 25,
    },
    {
        # LIVE WHOLE-SITE CRAWL against play.lingcode.dev — ten-business
        # test site #4 (a Next.js app, a sibling of lingcode.dev/
        # lingcode.app already tested above). Caught the day's third real
        # bug (PROJECT_STATUS.md Step 5.2): a genuinely harmless CSP
        # violation (the page's own Content-Security-Policy blocking its
        # Cloudflare Insights beacon) still came out as a HIGH
        # "JavaScript Console Error", because `_classify_js_errors`'
        # "did something visibly break" heuristic used to check
        # `bool(could_not_check)` — and this app's Next.js prefetch
        # requests (`?_rsc=...`) get aborted constantly as completely
        # normal behavior (routed to could_not_check by the Step 5.1 fix
        # just above), which made that heuristic true on nearly every
        # page regardless of anything actually breaking. Fixed by
        # dropping `could_not_check` from that heuristic entirely — see
        # the function's docstring.
        "name": "play.lingcode.dev (live external site, whole-site crawl)",
        "mode": "crawl",
        "target": "https://play.lingcode.dev",
        "live": True,
        "page_cap": 5,
        "expected_pages_checked": 5,
        "expected_used_sitemap": False,
        "expected_categories": {
            "Form Not Fully Verified": 2,
            "Missing Favicon": 5,
            "Render-Blocking Scripts": 5,
            "Script Error": 5,
            "Third-Party Resource Failed": 5,
        },
        "expected_max_unique_problems": 15,
    },
    {
        # LIVE WHOLE-SITE CRAWL against heavenmayhem.com — ten-business
        # test site #9 (a Shopify store). Like cakesbody.com, this one's
        # tracker mix is heavy and variable enough (85 raw "Third-Party
        # Resource Failed" occurrences across 5 pages, ~20 distinct
        # trackers, observed on the run that shaped this target) to make
        # exact per-category matching flap on nothing this codebase
        # controls — hence skip_category_check + a ceiling, same
        # reasoning as cakesbody.com. This is also the report that caught
        # Step 5.3's three fixes (see PROJECT_STATUS.md): its primary nav
        # links directly to /search, /account, and /cart, and all three
        # get selected as checked pages here — a good real-world bed for
        # the universal utility-page guard below (see
        # run_crawl_target()), which failed on this exact site before the
        # fix (missing meta description / H1 on /search and /account;
        # /cart's newsletter... no, /cart has no lead form, but /search
        # and /account previously got flagged for SEO issues that don't
        # apply to a page that isn't meant to rank in search at all).
        "name": "heavenmayhem.com (live external site, whole-site crawl)",
        "mode": "crawl",
        "target": "https://heavenmayhem.com",
        "live": True,
        "page_cap": 5,
        "skip_category_check": True,
        "expected_pages_checked": 5,
        "expected_max_unique_problems": 40,
    },
    {
        # LIVE WHOLE-SITE CRAWL against housejanolo.com — ten-business
        # test site #10, the last one (a Squarespace store). Small
        # tracker footprint (1 raw "Third-Party Resource Failed" on the
        # shaping run) makes exact per-category matching practical here,
        # like medvi.org/lingcode.dev/blaze.ai/play.lingcode.dev, not the
        # ceiling-based treatment cakesbody.com/heavenmayhem.com need.
        #
        # This is the report that caught Step 5.5's three fixes (see
        # PROJECT_STATUS.md): a first-party 404 confirmed by both the
        # server probe and a real-browser recheck now reports HIGH/
        # verified (3 of this site's "Broken Link" entries are exactly
        # this — including a genuinely subtle double-domain link
        # (`.../https://www.housejanolo.com/shop/one-of-one`) an owner
        # would be unlikely to find on their own); the homepage no longer
        # gets a false "Menu Pages Missing From Sitemap" (Squarespace
        # lists it in the sitemap under `/home`, not `/`); and "Heavy
        # Page" is now the single LOW site-wide finding below, naming
        # only the heaviest page, not one MEDIUM per heavy page.
        "name": "housejanolo.com (live external site, whole-site crawl)",
        "mode": "crawl",
        "target": "https://housejanolo.com",
        "live": True,
        "page_cap": 5,
        "expected_pages_checked": 5,
        "expected_used_sitemap": True,
        "expected_categories": {
            "Broken Link": 11,
            "Form Not Fully Verified": 1,
            "Heavy Page": 1,
            "Layout Shifts While Loading": 1,
            "Many Requests": 3,
            "Missing H1 Heading": 2,
            "Missing Meta Description": 1,
            "Oversized Images": 5,
            "Render-Blocking Scripts": 5,
            "Third-Party Resource Failed": 1,
        },
        "expected_max_unique_problems": 20,
    },
    {
        # Whole-site crawl (run_site_check(), not run_check()). Serves
        # test_site/ over a real local HTTP server — the crawl needs
        # genuine HTTP semantics for /sitemap.xml and /robots.txt, which a
        # file:// target can't provide. test_site/sitemap.xml hardcodes
        # http://127.0.0.1:8977/ (TEST_SITE_PORT above), so this must run
        # on that exact port.
        #
        # 127.0.0.1 is a loopback address, which the crawl's normal safety
        # filter (_is_safe_to_crawl) rejects by design — the same
        # SSRF-style protection applied to every discovered URL in a real
        # crawl. GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS is the opt-in that
        # bypasses that specifically for this local test (see core.py);
        # run_crawl_target() below sets and clears it only around this
        # one check.
        "name": "test_site (local whole-site crawl fixture)",
        "mode": "crawl",
        "target": f"http://127.0.0.1:{TEST_SITE_PORT}/",
        "page_cap": 10,
        "expected_pages_found_total": 3,
        "expected_pages_checked": 3,
        "expected_used_sitemap": True,
        # Aggregated across all 3 pages: index.html has a missing-alt-text
        # image, about.html has a broken link, contact.html is clean.
        "expected_categories": {
            "Missing Alt Text": 1,
            "Broken Link": 1,
        },
        # Step 6 side effect of how this fixture is built, not what it
        # tests: no page links an accessibility statement.
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
    },
    {
        # GetBuggy Step 8 — the same site checked twice must score the same
        # within the timing tolerance (report.scores_match: identical once
        # timing-sensitive findings are left out). Crawls test_site twice.
        "name": "score stability (test_site checked twice)",
        "mode": "score_stability",
        "target": f"http://127.0.0.1:{TEST_SITE_PORT}/",
        "page_cap": 10,
        # 100 - 15 (Broken Link: same-site 404 confirmed twice, HIGH) - 1
        # (Missing Alt Text, LOW) - 21 (security: the fixture is plain http —
        # Site Doesn't Use HTTPS HIGH 15 + No Security Headers MEDIUM 5 +
        # Server Software Version Revealed LOW 1). needs_look findings (No
        # Accessibility Statement, No Privacy Policy Found) don't count.
        "expected_score": 63,
    },
    {
        # GetBuggy Step 4 fixtures (see fixture_server.py for how each is
        # served). Each is one thing Step 4 has to get right.
        #
        # Sitemap discovery via robots.txt -> a <sitemapindex> with two
        # children, one plain and one GZIPPED (sitemap-more.xml.gz, gzipped
        # on the fly). 10 in-scope pages, cap 5, so page selection matters:
        # home, the 3 menu pages (about/contact/services), then pricing —
        # pulled ahead of gone/old/blog/team by the contact/pricing/book/
        # order/shop priority rule. Sitemap findings: gone.html 404s, old.html
        # redirects, one URL is on another host, and services.html is in the
        # menu but not in the sitemap.
        "name": "test_site_sitemap (sitemap index + gzip + selection + sitemap findings)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_sitemap"),
        "port": 8979,
        "target": "http://127.0.0.1:8979/",
        "page_cap": 5,
        "expected_pages_found_total": 10,
        "expected_pages_checked": 5,
        "expected_used_sitemap": True,
        "expected_skipped_count": 5,
        "expected_selected_paths": ["/", "/about.html", "/contact.html", "/services.html", "/pricing.html"],
        "expected_categories": {
            "Sitemap Lists URLs On Another Host": 1,
            "Sitemap Lists Missing Pages": 1,
            "Sitemap Lists Redirecting Pages": 1,
            "Menu Pages Missing From Sitemap": 1,
        },
        # Step 6 side effect of how this fixture is built, not what it
        # tests: no homepage link or sitemap page is an accessibility
        # statement.
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
    },
    {
        # robots.txt blocks Googlebot from the whole site (HIGH); the
        # homepage is noindex via an X-Robots-Tag header (HIGH) and
        # about.html via a <meta robots> tag (MEDIUM); the menu's "Landing"
        # link goes through 3 redirects (LOW) — seen both as a link on the
        # homepage and as the page /hop1 itself when it's crawled. No
        # sitemap, so pages come from the homepage's rendered menu.
        "name": "test_site_robots (robots Disallow, noindex, redirect chain)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_robots"),
        "port": 8980,
        "target": "http://127.0.0.1:8980/",
        "page_cap": 5,
        "expected_pages_found_total": 3,
        "expected_pages_checked": 3,
        "expected_used_sitemap": False,
        "expected_categories": {
            "Site Blocked From Search (robots.txt)": 1,
            "Page Blocked From Search (noindex)": 2,
            "Redirect Chain": 2,
            # Step 5: this fixture has no sitemap, so the new site-wide
            # "No Sitemap Found" (LOW) correctly fires here too.
            "No Sitemap Found": 1,
        },
        # Step 6 side effect of how this fixture is built, not what it
        # tests: no page links an accessibility statement.
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
    },
    {
        # A site whose server answers a missing page with a normal 200 "Page
        # not found" page. old-service.html doesn't exist but is in the
        # sitemap and the menu; it must be flagged as a soft 404, while the
        # real about.html (real content) must not be.
        "name": "test_site_soft404 (soft 404 detection)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_soft404"),
        "port": 8981,
        "target": "http://127.0.0.1:8981/",
        "page_cap": 5,
        "expected_pages_found_total": 3,
        "expected_pages_checked": 3,
        "expected_used_sitemap": True,
        "expected_categories": {
            "Soft 404 Page": 1,
            # Step 5: the site-wide probe of a made-up address gets a 200
            # here — exactly what this fixture plants — so the new public
            # "Missing Pages Don't Say "Not Found"" (MEDIUM) fires too.
            'Missing Pages Don\'t Say "Not Found"': 1,
        },
        # Step 6 side effect of how this fixture is built, not what it
        # tests: no homepage link or sitemap page is an accessibility
        # statement.
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
    },
    {
        # A single-page app: the menu's #/about, #/pricing and #!/contact
        # are routes on one page, so the site is exactly ONE page (not
        # four). Also plants a #anchor with no target (LOW), a
        # javascript:void(0) link (MEDIUM, needs_look) and "click here"
        # link text (LOW). #features exists, so it must NOT be flagged.
        "name": "test_site_spa (hash routing, anchors, placeholder + vague links)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_spa"),
        "port": 8982,
        "target": "http://127.0.0.1:8982/",
        "page_cap": 5,
        "expected_pages_found_total": 1,
        "expected_pages_checked": 1,
        "expected_used_sitemap": False,
        "expected_categories": {
            "Broken In-Page Link": 1,
            "Placeholder Links": 1,
            "Vague Link Text": 1,
            # Step 5: this fixture has no sitemap, so the new site-wide
            # "No Sitemap Found" (LOW) correctly fires here too.
            "No Sitemap Found": 1,
        },
        # Step 6 side effect of how this fixture is built, not what it
        # tests: no page links an accessibility statement.
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
    },
    {
        # 12 of the homepage's 13 links are added by a script 300ms after
        # load: absent from the server HTML (static set ~8% of the rendered
        # set -> LOW), but found by the crawler's rendered-DOM discovery
        # (14 pages found; cap 2 so only the homepage and about.html are
        # checked, the 12 dynamic ones are skipped).
        "name": "test_site_dynamic (links that only exist after scripts run)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_dynamic"),
        "port": 8983,
        "target": "http://127.0.0.1:8983/",
        "page_cap": 2,
        "expected_pages_found_total": 14,
        "expected_pages_checked": 2,
        "expected_used_sitemap": False,
        "expected_skipped_count": 12,
        "expected_categories": {
            "Links Only Appear After Scripts Run": 1,
            # Step 5: this fixture has no sitemap, so the new site-wide
            # "No Sitemap Found" (LOW) correctly fires here too.
            "No Sitemap Found": 1,
        },
        # Step 6 side effect of how this fixture is built, not what it
        # tests: no page links an accessibility statement.
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
    },
    {
        # GetBuggy Step 5 — endpoint/transport/exposure fixture. robots.txt
        # answers 500 (HIGH, public), there's no sitemap, the favicon and
        # web manifest the pages point to don't exist, and missing pages get
        # nginx's bare 404 page. Security (ownership-gated): all seven
        # sensitive-file probes answer with plausible content, a Stripe
        # secret key sits in the homepage and an AWS key in /js/app.js
        # (both generated by fixture_server.py, never committed), app.js
        # publishes its source map, /js/jquery-1.8.3.min.js has known CVEs,
        # a script loads from a .invalid domain that can never resolve,
        # /files/ is a raw folder listing, and — like every fixture — the
        # site is plain http:// with Python's own Server header and no
        # security headers. The public extras are ordinary fallout of the
        # planted pages: the dead .invalid script (Third-Party Resource
        # Failed), the listing's link to a file that isn't there (Broken
        # Link), its wide <pre> line (Mobile Horizontal Scroll) and missing
        # meta description, and the head scripts (Render-Blocking Scripts).
        "name": "test_site_security (endpoints, exposed files and secrets, versions)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_security"),
        "port": 8985,
        "target": "http://127.0.0.1:8985/",
        "page_cap": 5,
        "expected_pages_found_total": 3,
        "expected_pages_checked": 3,
        "expected_used_sitemap": False,
        "expected_categories": {
            "robots.txt Is Erroring": 1,
            "No Sitemap Found": 1,
            "Favicon Doesn't Load": 1,
            "Web App Manifest Missing": 1,
            "Plain Server Error Page": 1,
            "Third-Party Resource Failed": 1,
            "Render-Blocking Scripts": 1,
            "Broken Link": 1,
            "Missing Meta Description": 1,
            "Mobile Horizontal Scroll": 1,
        },
        "expected_security_categories": {
            "Exposed Sensitive File": 7,
            "Secret Key Exposed In Page Source": 2,
            "Source Code Map Files Are Public": 1,
            "Outdated JavaScript Library": 1,
            "Script From A Domain That No Longer Exists": 1,
            "Folder Contents Are Public": 1,
            "Site Doesn't Use HTTPS": 1,
            "No Security Headers": 1,
            "Server Software Version Revealed": 1,
        },
        # Step 6 side effects of how this fixture is built, not what it
        # tests: no page links an accessibility statement, and the
        # /files/ folder-listing page has no <html lang>.
        "expected_accessibility_categories": {
            "No Accessibility Statement": 1,
            "Page Language Not Set": 1,
        },
    },
    {
        # GetBuggy Step 5 — signs of a break-in, each planted once: an
        # off-site <meta refresh>, an off-site JS redirect, a self-unpacking
        # eval(atob(...)) script, display:none spam links, and spam text in
        # the server's HTML that a script removes before anyone sees it. The
        # three Broken Links are the hidden spam links themselves (.invalid
        # domains, so they fail the same way every run).
        "name": "test_site_hacked (compromise signals)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_hacked"),
        "port": 8986,
        "target": "http://127.0.0.1:8986/",
        "page_cap": 5,
        "expected_pages_found_total": 1,
        "expected_pages_checked": 1,
        "expected_used_sitemap": False,
        "expected_categories": {
            "No Sitemap Found": 1,
            "Broken Link": 3,
            "Render-Blocking Scripts": 1,
        },
        "expected_security_categories": {
            "Site May Be Hacked": 5,
            "Site Doesn't Use HTTPS": 1,
            "No Security Headers": 1,
            "Server Software Version Revealed": 1,
        },
        # Step 6 side effects of how this fixture is built, not what it
        # tests: no page links an accessibility statement, and the
        # planted off-site <meta refresh> is also a timed redirect.
        "expected_accessibility_categories": {
            "No Accessibility Statement": 1,
            "Page Refreshes or Redirects on a Timer": 1,
        },
    },
    {
        # GetBuggy Step 5 — an outdated WordPress fingerprint: generator
        # tag says 5.8.1 (WordPress.org lists it "insecure" in the bundled
        # security_data/wordpress_core.json), Contact Form 7 5.4 via its
        # ?ver= (older than the bundled latest), xmlrpc.php open, usernames
        # readable via /wp-json/wp/v2/users and /?author=1. jQuery 3.5.1 has
        # no known issues in the bundled list, so it must NOT be flagged.
        "name": "test_site_wordpress (outdated WordPress fingerprint)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_wordpress"),
        "port": 8987,
        "target": "http://127.0.0.1:8987/",
        "page_cap": 5,
        "expected_pages_found_total": 1,
        "expected_pages_checked": 1,
        "expected_used_sitemap": False,
        "expected_platform": "WordPress",
        "expected_categories": {
            "No Sitemap Found": 1,
            "Render-Blocking Scripts": 1,
        },
        "expected_security_categories": {
            "WordPress Version Has Known Security Problems": 1,
            "WordPress Plugins Out Of Date": 1,
            "WordPress XML-RPC Is Open": 1,
            "WordPress Usernames Are Public": 1,
            "Site Doesn't Use HTTPS": 1,
            "No Security Headers": 1,
            "Server Software Version Revealed": 1,
        },
        # Step 6 side effects of how this fixture is built, not what it
        # tests: no page links an accessibility statement.
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
    },
    {
        # GetBuggy Step 6 — one planted violation per accessibility check
        # (see the comments in the fixture). Must find exactly these and
        # nothing else: the fixture's silent background video loop,
        # labelled field, named button and visible-focus link are controls
        # that must stay quiet.
        "name": "test_page_a11y.html (accessibility fixture with planted violations)",
        "target": os.path.join(SCRIPT_DIR, "test_page_a11y.html"),
        "expected_categories": {},
        "expected_accessibility_categories": {
            "Hard-to-Read Text (Low Contrast)": 1,
            "Form Fields Without Labels": 1,
            "Buttons Without a Name": 1,
            "Empty Links (No Link Text)": 1,
            "Page Language Not Set": 1,
            "Headings Skip Levels": 1,
            "Duplicate IDs in the Page Code": 1,
            "No Visible Keyboard Focus": 1,
            "Media Plays Automatically With Sound": 1,
            "Video Without Captions": 1,
            "Accessibility Overlay Widget": 1,
        },
    },
    {
        # GetBuggy Step 6 — the accessibility scan's time budget, and the
        # accessibility-statement check, on a real crawl. A11Y_SLOW_SCAN_
        # SECONDS=0 makes the first finished scan count as "too slow", so
        # the crawl falls back to homepage + contact/booking pages only:
        # home (low contrast) and contact (empty link) are scanned; about's
        # unlabelled field must NOT be reported, and about must carry the
        # "skipped" note. The footer links accessibility.html, so "No
        # Accessibility Statement" must not fire. Selection: home, then the
        # menu (contact, about) under a cap of 3.
        "name": "test_site_a11y (accessibility time-budget fallback + statement)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_a11y"),
        "port": 8990,
        "target": "http://127.0.0.1:8990/",
        "page_cap": 3,
        "env": {"A11Y_SLOW_SCAN_SECONDS": "0"},
        "expected_pages_found_total": 4,
        "expected_pages_checked": 3,
        "expected_used_sitemap": False,
        "expected_selected_paths": ["/", "/contact.html", "/about.html"],
        # Step 5: no sitemap on this fixture, so the site-wide
        # "No Sitemap Found" (LOW, public) fires here like on every other
        # sitemap-less fixture.
        "expected_categories": {"No Sitemap Found": 1},
        "expected_accessibility_categories": {
            "Hard-to-Read Text (Low Contrast)": 1,
            "Empty Links (No Link Text)": 1,
        },
        "expected_note_substrings": [
            "We skipped the automated accessibility scan on this page",
            "The automated accessibility scan only ran on your homepage and contact/booking pages",
        ],
    },
    {
        # GetBuggy Step 7 — no banner. Tracking starts on load (Google
        # Analytics + Meta cookies set by script, a request to a stand-in
        # "Hotjar" — this fixture's localhost, aliased), no banner, no privacy
        # policy, and the server sets a "sessionid" cookie without HttpOnly or
        # SameSite. No `jurisdiction` given, so it must default to "us" — where
        # the no-banner finding fires because Meta is an ADVERTISING tracker.
        # The sticky header talking about (baked) cookies must not be taken
        # for a banner. about.html sets a TikTok cookie: the cookie list
        # (5 cookies, 4 companies) must include it, merged from that page.
        "name": "test_site_cookies_nobanner (tracking with no banner, US default)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_cookies_nobanner"),
        "port": 8991,
        "target": "http://127.0.0.1:8991/",
        "page_cap": 5,
        "env": {"GETBUGGY_TEST_TRACKER_ALIAS": "localhost=static.hotjar.com"},
        "expected_pages_found_total": 2,
        "expected_pages_checked": 2,
        "expected_used_sitemap": False,
        "expected_jurisdiction": "us",
        "expected_categories": {"No Sitemap Found": 1},
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
        "expected_cookie_categories": {
            "Tracking With No Cookie Notice": 1,
            "No Privacy Policy Found": 1,
        },
        "expected_security_categories": {
            "Login Cookie Readable By Scripts": 1,
            "Cookies Missing SameSite Setting": 1,
            "Site Doesn't Use HTTPS": 1,
            "No Security Headers": 1,
            "Server Software Version Revealed": 1,
        },
        "expected_cookie_summary": {"cookie_count": 5, "company_count": 4, "banner_seen": False},
    },
    {
        # Step 7 — banner present but not blocking, EU/UK rules. The banner
        # offers only "Accept all" (plus "Manage settings"), a Google
        # Analytics cookie and a stand-in Meta pixel request (localhost,
        # aliased) fire before anyone touches it, at phone width the banner
        # fills the screen with its buttons pushed off the bottom, and the
        # footer's privacy policy is dated 2019 and doesn't mention Meta.
        "name": "test_site_cookies_notblocking (banner not blocking, eu_uk)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_cookies_notblocking"),
        "port": 8992,
        "target": "http://127.0.0.1:8992/",
        "page_cap": 5,
        "jurisdiction": "eu_uk",
        "env": {"GETBUGGY_TEST_TRACKER_ALIAS": "localhost=connect.facebook.net"},
        "expected_pages_found_total": 3,
        "expected_pages_checked": 3,
        "expected_used_sitemap": False,
        "expected_jurisdiction": "eu_uk",
        "expected_categories": {"No Sitemap Found": 1},
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
        "expected_cookie_categories": {
            "Tracking Starts Before Consent": 1,
            "Rejecting Cookies Is Harder Than Accepting": 1,
            "Cookie Banner Covers The Phone Screen": 1,
            "Privacy Policy May Be Out Of Date": 1,
            "Privacy Policy Doesn't Mention Your Trackers": 1,
        },
        "expected_cookie_summary": {"cookie_count": 2, "banner_seen": True},
    },
    {
        # Step 7 — the same site under the default US rules: the two EU/UK
        # consent findings (tracking before consent, reject harder than
        # accept) must disappear; the phone-screen and privacy-policy ones
        # apply everywhere and stay. This is the `jurisdiction` switch.
        "name": "test_site_cookies_notblocking (same site, us)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_cookies_notblocking"),
        "port": 8993,
        "target": "http://127.0.0.1:8993/",
        "page_cap": 5,
        "jurisdiction": "us",
        "env": {"GETBUGGY_TEST_TRACKER_ALIAS": "localhost=connect.facebook.net"},
        "expected_pages_found_total": 3,
        "expected_pages_checked": 3,
        "expected_used_sitemap": False,
        "expected_jurisdiction": "us",
        "expected_categories": {"No Sitemap Found": 1},
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
        "expected_cookie_categories": {
            "Cookie Banner Covers The Phone Screen": 1,
            "Privacy Policy May Be Out Of Date": 1,
            "Privacy Policy Doesn't Mention Your Trackers": 1,
        },
    },
    {
        # Step 7 — compliant, under the strictest rules (eu_uk): "Accept all"
        # and "Reject all" side by side, analytics only after Accept (never
        # clicked), the session cookie is HttpOnly + SameSite, and the footer's
        # privacy policy is dated today and names Google Analytics. Must
        # produce no cookie, consent or cookie-security finding at all.
        "name": "test_site_cookies_compliant (compliant banner and policy, eu_uk)",
        "mode": "crawl",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_cookies_compliant"),
        "port": 8994,
        "target": "http://127.0.0.1:8994/",
        "page_cap": 5,
        "jurisdiction": "eu_uk",
        "expected_pages_found_total": 3,
        "expected_pages_checked": 3,
        "expected_used_sitemap": False,
        "expected_jurisdiction": "eu_uk",
        "expected_categories": {"No Sitemap Found": 1},
        "expected_accessibility_categories": {"No Accessibility Statement": 1},
        "expected_cookie_categories": {},
        "expected_security_categories": {
            "Site Doesn't Use HTTPS": 1,
            "No Security Headers": 1,
            "Server Software Version Revealed": 1,
        },
        "expected_cookie_summary": {"cookie_count": 1, "company_count": 1, "banner_seen": True},
    },
    {
        # The time cap: a crawl of a site where slow-1..4.html never finish
        # loading, with a 40s cap. Must come back as a PARTIAL REPORT (the
        # homepage and about.html checked, the rest listed as not checked
        # in time), never a bare error. Goes through the real worker
        # subprocess and server._run_crawl_job, killed by the real watchdog.
        "name": "test_site_slow (crawl that hits the time cap returns a partial report)",
        "mode": "crawl_capped",
        "site_dir": os.path.join(SCRIPT_DIR, "test_site_slow"),
        "port": 8984,
        "target": "http://127.0.0.1:8984/",
        "page_cap": 5,
        "time_cap_seconds": 40,
    },
]


# Categories driven by a timing/perf measurement (rather than a
# structural DOM/network fact) drift run to run — network jitter, host
# load, a font finishing loading a beat later — even against a fixed
# local fixture on the exact same machine. Comparing them by exact count
# would make the harness flap on nothing anyone actually changed, so each
# gets its own tolerance band (a symmetric +/- allowance around whatever
# count a target expects for it, default 0 if the target doesn't mention
# it) instead of an exact match. A deviation within the band is silent; a
# deviation past it is printed as a note, not a failure — still visible
# if something's gone properly wrong (e.g. a code change permanently
# breaks the check), without making the harness flap on noise it can't
# control. Every other category (structural findings: broken link,
# missing title, missing alt text, etc.) is NOT in this set and is
# always compared exactly, via the flaky-category/exact-match path below.
TIMING_TOLERANT_CATEGORIES = {
    "Page Load Time": 2,
    "Largest Contentful Paint": 2,
    "Layout Shifts While Loading": 1,
    "Slow Server Response": 1,
    "Heavy Page": 1,
    "Many Requests": 1,
    "Oversized Images": 1,
}


def categorize(problems):
    """Collapse a list of problem dicts down to {category: count}.

    Security findings (`"group": "security"`, GetBuggy Step 5) are left
    out here on purpose: every fixture is served over plain http:// from
    Python's own server, so each one picks up the same handful of
    transport/header findings ("Site Doesn't Use HTTPS", "No Security
    Headers", "Server Software Version Revealed") that say nothing about
    what that fixture exists to test. They're compared only on targets
    that opt in with `expected_security_categories` — see
    categorize_security.

    Accessibility findings (`"topic": "accessibility"`, Step 6) are also
    left out here, but unlike security they're compared on EVERY target
    (see check_accessibility_categories), against
    `expected_accessibility_categories` (default: none) — kept as their
    own key so each fixture's baseline says which findings it exists to
    test and which are accessibility side effects of how it's built."""
    return Counter(
        p["category"] for p in problems
        if p.get("group") != "security" and p.get("topic") not in ("accessibility", "cookies")
    )


def categorize_security(problems):
    """{category: count} for security findings only."""
    return Counter(p["category"] for p in problems if p.get("group") == "security")


def check_accessibility_categories(spec, problems):
    """Fail lines for accessibility findings vs. the target's
    `expected_accessibility_categories` (default {}: none expected)."""
    actual = Counter(p["category"] for p in problems if p.get("topic") == "accessibility")
    fail_lines, _ = diff_report(Counter(spec.get("expected_accessibility_categories", {})), actual)
    return [line.replace("  - ", "  - [accessibility] ", 1) for line in fail_lines]


def check_cookie_results(spec, problems, result):
    """Fail lines for Step 7 (cookies and consent). Opt-in like security:
    only targets with `expected_cookie_categories` are compared — a live
    site's trackers and banner change on the site owner's schedule, not
    ours, and the older fixtures exist to test other things (they'd all
    pick up "No Privacy Policy Found"). Also checks the run's jurisdiction
    (`expected_jurisdiction`) and the cookie list's counts
    (`expected_cookie_summary`, e.g. {"cookie_count": 5})."""
    fail_lines = []
    if "expected_cookie_categories" in spec:
        actual = Counter(p["category"] for p in problems if p.get("topic") == "cookies")
        lines, _ = diff_report(Counter(spec["expected_cookie_categories"]), actual)
        fail_lines += [line.replace("  - ", "  - [cookies] ", 1) for line in lines]
    if "expected_jurisdiction" in spec and result.get("jurisdiction") != spec["expected_jurisdiction"]:
        fail_lines.append(
            f"  - jurisdiction: expected {spec['expected_jurisdiction']!r}, got {result.get('jurisdiction')!r}"
        )
    summary = result.get("cookies") or {}
    for key, want in spec.get("expected_cookie_summary", {}).items():
        if summary.get(key) != want:
            fail_lines.append(f"  - cookie list {key}: expected {want!r}, got {summary.get(key)!r}")
    return fail_lines


def check_expected_notes(spec, could_not_check):
    """Fail lines for `expected_note_substrings`: each must appear in at
    least one "couldn't check" note (how a skipped check proves it said
    so in the report)."""
    return [
        f"  - expected a \"couldn't check\" note containing {s!r}, found none"
        for s in spec.get("expected_note_substrings", [])
        if not any(s in note for note in could_not_check)
    ]


def diff_report(expected, actual, flaky=None):
    """Compare actual category counts against expected category counts.

    Returns (fail_lines, note_lines):
      - fail_lines: mismatches that should fail the target.
      - note_lines: informational-only mismatches — either a timing
        category (see TIMING_TOLERANT_CATEGORIES) outside its tolerance
        band, or a category listed in `flaky` (a {category:
        max_tolerated_extra_count} dict) that showed up more than
        expected, up to its tolerated amount. These are reported so
        they're visible, but never cause a FAIL.

    Both empty means actual matches expected (ignoring tolerated
    flakiness/timing drift).
    """
    flaky = flaky or {}
    fail_lines = []
    note_lines = []
    all_categories = sorted(set(expected) | set(actual) | set(TIMING_TOLERANT_CATEGORIES))
    for category in all_categories:
        exp_count = expected.get(category, 0)
        act_count = actual.get(category, 0)
        if exp_count == act_count:
            continue

        tolerance = TIMING_TOLERANT_CATEGORIES.get(category)
        if tolerance is not None:
            if abs(act_count - exp_count) > tolerance:
                note_lines.append(
                    f"  - (timing tolerance) '{category}' expected x{exp_count}, "
                    f"got x{act_count} — outside its +/-{tolerance} tolerance "
                    "band, but timing-based categories never fail the harness "
                    "on their own"
                )
            continue

        extra = act_count - exp_count
        tolerated = flaky.get(category, 0)
        if extra > 0 and extra <= tolerated:
            note_lines.append(
                f"  - (tolerated flake) '{category}' expected x{exp_count}, "
                f"got x{act_count} — known-flaky category, not counted as failure"
            )
            continue

        if exp_count > 0 and act_count == 0:
            fail_lines.append(
                f"  - MISSING: expected '{category}' x{exp_count}, got none"
            )
        elif exp_count == 0 and act_count > 0:
            fail_lines.append(
                f"  - UNEXPECTED: got '{category}' x{act_count}, expected none"
            )
        else:
            fail_lines.append(
                f"  - COUNT MISMATCH: '{category}' expected x{exp_count}, "
                f"got x{act_count}"
            )
    return fail_lines, note_lines


def _serve_test_site(directory, port):
    """Serves `directory` over real HTTP on 127.0.0.1:port in a background
    thread, so a crawl target has genuine /sitemap.xml and /robots.txt
    semantics to work with (see fixture_server.py for the extras some
    fixtures use). Returns the server; call .shutdown() when done."""
    return _serve_fixture_site(directory, port)


def run_crawl_target(spec):
    """Like run_target(), but for a "mode": "crawl" spec: spins up the
    local test-site HTTP server, calls run_site_check() instead of
    run_check(), aggregates problems across all pages for the category
    comparison, and also checks pages_found_total/pages_checked/
    used_sitemap against expected values (not just categories, since a
    crawl that silently found or checked the wrong number of pages is a
    real regression even if the aggregated categories happened to match).

    `expected_categories` is optional (default {}) — a real, complex,
    tracker-heavy live site (unlike the local fixtures, or medvi.org)
    doesn't hold still category-by-category run to run: which of a dozen
    third-party trackers happens to time out, and even whether the
    site's own sitemap gets discovered before it does, both vary — so
    forcing an exact per-category match would flap on nothing anyone
    changed. For a target like that, set `skip_category_check: True` and
    use `expected_max_unique_problems` instead (see below) — the
    invariant that actually matters (see PROJECT_STATUS.md Step 5: the
    382-problem cakesbody.com report that started this)."""
    name = spec["name"]
    target = spec["target"]
    expected = Counter(spec.get("expected_categories", {}))
    flaky = spec.get("flaky_categories")
    skip_category_check = spec.get("skip_category_check", False)

    print(f"=== {name} ===")
    print(f"    target: {target}")

    server = _serve_test_site(
        spec.get("site_dir", TEST_SITE_DIR), spec.get("port", TEST_SITE_PORT)
    )
    os.environ["GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS"] = "true"
    # Optional per-target env vars (e.g. a tiny A11Y_SLOW_SCAN_SECONDS to
    # force the accessibility scan's time-budget fallback), restored after.
    saved_env = {k: os.environ.get(k) for k in spec.get("env", {})}
    os.environ.update(spec.get("env", {}))
    try:
        result = run_site_check(
            target, page_cap=spec.get("page_cap", 10), jurisdiction=spec.get("jurisdiction")
        )
    except Exception as e:
        print(f"FAIL  ({e.__class__.__name__}: {e})")
        print()
        return False
    finally:
        os.environ.pop("GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS", None)
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        server.shutdown()

    fail_lines = []
    note_lines = []

    for field in ("pages_found_total", "pages_checked", "used_sitemap"):
        expected_key = f"expected_{field}"
        if expected_key not in spec:
            continue
        if result[field] != spec[expected_key]:
            fail_lines.append(
                f"  - {field}: expected {spec[expected_key]!r}, got {result[field]!r}"
            )

    # Selection under the page cap: which pages were chosen, which skipped.
    def _paths(urls):
        return sorted(urlparse(u).path or "/" for u in urls)

    if "expected_selected_paths" in spec:
        got = _paths(p["url"] for p in result["pages"])
        if got != sorted(spec["expected_selected_paths"]):
            fail_lines.append(f"  - pages checked: expected {sorted(spec['expected_selected_paths'])}, got {got}")
    if "expected_skipped_count" in spec and len(result["pages_skipped"]) != spec["expected_skipped_count"]:
        fail_lines.append(
            f"  - pages skipped: expected {spec['expected_skipped_count']}, got {len(result['pages_skipped'])}"
        )

    # Site-wide findings (robots.txt, sitemap) count alongside per-page ones.
    all_problems = list(result.get("site_findings", [])) + [
        p for page in result["pages"] for p in page["problems"]
    ]
    all_could_not_check = [
        n for page in result["pages"] for n in page.get("could_not_check", [])
    ]

    if skip_category_check:
        # Guards fix #3 (sitemap exclusions) directly: /cart, /account,
        # /search, etc. must never be flagged as "missing from sitemap" —
        # see _expected_absent_from_sitemap in core.py.
        bad_sitemap_findings = [
            p for p in all_problems
            if p["category"] == "Menu Pages Missing From Sitemap"
            and any(
                path in p["message"]
                for path in ("/cart", "/account", "/checkout", "/search",
                              "/collections/all", "/customer_authentication")
            )
        ]
        if bad_sitemap_findings:
            fail_lines.append(
                "  - a page expected to be absent from the sitemap (cart/account/"
                f"search/etc.) was flagged as missing anyway: {bad_sitemap_findings[0]['message']!r}"
            )
    else:
        actual = categorize(all_problems)
        category_fail_lines, category_note_lines = diff_report(expected, actual, flaky)
        fail_lines.extend(category_fail_lines)
        note_lines.extend(category_note_lines)

    if "expected_security_categories" in spec:
        security_fail_lines, _ = diff_report(
            Counter(spec["expected_security_categories"]), categorize_security(all_problems)
        )
        fail_lines.extend(line.replace("  - ", "  - [security] ", 1) for line in security_fail_lines)
    if not skip_category_check:
        fail_lines.extend(check_accessibility_categories(spec, all_problems))
    fail_lines.extend(check_cookie_results(spec, all_problems, result))
    fail_lines.extend(check_expected_notes(spec, all_could_not_check + list(result.get("site_could_not_check", []))))
    if "expected_platform" in spec and result.get("platform") != spec["expected_platform"]:
        fail_lines.append(f"  - platform: expected {spec['expected_platform']!r}, got {result.get('platform')!r}")

    # Guards Step 5.3's utility-page fixes directly, for every crawl
    # target (not just skip_category_check ones) — a cart/account/search/
    # login page must never get SEO-discoverability or form findings; see
    # core.py's _is_utility_page. No-op for a fixture with no such pages.
    _SEO_DISCOVERABILITY_CATEGORIES = {
        "Missing Page Title", "Missing Meta Description",
        "Missing H1 Heading", "Multiple H1 Headings",
        "Page Blocked From Search (noindex)",
    }
    _FORM_CATEGORIES = {
        "Broken Form", "Form Needs A Look", "Form Not Fully Verified", "Embedded Form",
    }
    for page in result["pages"]:
        if not _is_utility_page(page["url"]):
            continue
        page_categories = {p["category"] for p in page["problems"]}
        bad = (page_categories & _SEO_DISCOVERABILITY_CATEGORIES) | (page_categories & _FORM_CATEGORIES)
        if bad:
            fail_lines.append(
                f"  - utility page {page['url']!r} got SEO/form finding(s) that should "
                f"have been skipped: {sorted(bad)}"
            )

    # The actual invariant this step's fixes are for: a whole-site crawl's
    # DEDUPLICATED problem count (see core.py's dedupe_site_problems) must
    # stay bounded — the regression test for "382 problems on a 5-page
    # site" never happening again. Not an exact-match check (a live
    # site's real, distinct problem count shifts as its content and
    # third-party integrations change) — a ceiling, generous enough to
    # hold across ordinary drift but tight enough to catch the dedup/
    # classification logic regressing back toward one-problem-per-
    # occurrence.
    unique_count = len(result.get("unique_problems") or [])
    if "expected_max_unique_problems" in spec:
        cap = spec["expected_max_unique_problems"]
        if unique_count > cap:
            fail_lines.append(
                f"  - unique problem count: {unique_count} exceeds the expected "
                f"ceiling of {cap} — see PROJECT_STATUS.md Step 5 (this is the "
                "382-problem regression this check exists to catch)"
            )
        else:
            note_lines.append(f"  - (info) {unique_count} unique problem(s), within the expected <= {cap} ceiling")

    if not fail_lines:
        cnc = f", {len(all_could_not_check)} couldn't-check note(s)" if all_could_not_check else ""
        print(
            f"PASS  ({result['pages_checked']} of {result['pages_found_total']} "
            f"page(s) checked, {len(all_problems)} raw problem(s){cnc}, "
            f"{unique_count} unique)"
        )
        for line in note_lines:
            print(line)
        print()
        return True

    print("FAIL")
    for line in fail_lines:
        print(line)
    for line in note_lines:
        print(line)
    print()
    return False


def run_score_stability_target(spec):
    """GetBuggy Step 8's Definition of Done, as a harness target: crawl the
    same fixture twice, finalize both into reports, and require the two
    scores to match within the timing tolerance (report.scores_match).
    `expected_score`, when given, also pins the score itself, so a change
    to the formula or to what the fixture's findings cost shows up here."""
    import report

    name, target = spec["name"], spec["target"]
    print(f"=== {name} ===")
    print(f"    target: {target}")
    server = _serve_test_site(spec.get("site_dir", TEST_SITE_DIR), spec.get("port", TEST_SITE_PORT))
    os.environ["GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS"] = "true"
    scores = []
    try:
        for _ in range(2):
            result = run_site_check(target, page_cap=spec.get("page_cap", 10))
            scores.append(report.finalize_report(result, url=target, report_id=None)["score"])
    except Exception as e:
        print(f"FAIL  ({e.__class__.__name__}: {e})")
        print()
        return False
    finally:
        os.environ.pop("GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS", None)
        server.shutdown()

    a, b = scores
    fail_lines = []
    if a.get("value") is None:
        fail_lines.append(f"  - no score: {a.get('reason')}")
    elif not report.scores_match(a, b):
        fail_lines.append(
            f"  - scores differ beyond the timing tolerance: {a['value']} vs {b['value']} "
            f"(without timing findings: {a['value_without_timing']} vs {b['value_without_timing']})"
        )
    if "expected_score" in spec and a.get("value_without_timing") != spec["expected_score"]:
        fail_lines.append(
            f"  - score without timing findings: expected {spec['expected_score']}, "
            f"got {a.get('value_without_timing')} — deductions: {a.get('deductions')}"
        )
    if fail_lines:
        print("FAIL")
        for line in fail_lines:
            print(line)
        print()
        return False
    print(f"PASS  (scores {a['value']} and {b['value']}; "
          f"{a['timing_sensitive_points']}/{b['timing_sensitive_points']} timing-sensitive points)")
    print()
    return True


def run_capped_crawl_target(spec):
    """A crawl that hits the time cap must come back as a *partial report*,
    never a bare error. Runs the real worker subprocess through the real
    server job runner (server._run_crawl_job) against a local site where
    some pages never finish loading, with a short cap, and checks the job
    finished as status "done" with partial=True, some pages checked, the
    unfinished ones listed, and a summary that says so."""
    import server  # imported here: pulls in FastAPI, unneeded by other targets

    name = spec["name"]
    print(f"=== {name} ===")
    print(f"    target: {spec['target']}  (time cap: {spec['time_cap_seconds']}s)")

    site = _serve_test_site(spec["site_dir"], spec["port"])
    os.environ["GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS"] = "true"
    job_id = "regression-capped-crawl"
    started = time.time()
    try:
        server._check_semaphore.acquire()  # _run_crawl_job releases it when done
        server._jobs[job_id] = {
            "status": "running", "phase": "finding_pages", "pages_checked": 0,
            "pages_total": None, "pages_found_total": None, "pages_selected": [],
            "pages_skipped": [], "pages_done": [], "result": None, "detail": None,
            "created_at": time.time(), "authorized": True,
        }
        server._run_crawl_job(
            job_id, spec["target"], spec["page_cap"], timeout_seconds=spec["time_cap_seconds"]
        )
    finally:
        os.environ.pop("GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS", None)
        site.shutdown()
    elapsed = time.time() - started
    job = server._jobs.pop(job_id)

    fail_lines = []
    result = job.get("result") or {}
    if job["status"] != "done":
        fail_lines.append(f"  - job status: expected 'done' (a partial report), got {job['status']!r}: {job.get('detail')}")
    if not result.get("partial"):
        fail_lines.append("  - result is not marked partial")
    if not (1 <= result.get("pages_checked", 0) < result.get("pages_planned", 0)):
        fail_lines.append(
            f"  - expected some but not all pages checked, got {result.get('pages_checked')} of {result.get('pages_planned')}"
        )
    if not result.get("pages_not_checked_in_time"):
        fail_lines.append("  - unfinished pages were not listed")
    if not str(result.get("summary", "")).startswith("Partial report"):
        fail_lines.append(f"  - summary doesn't say it's partial: {result.get('summary')!r}")
    if elapsed > spec["time_cap_seconds"] + 15:
        fail_lines.append(f"  - took {elapsed:.0f}s, well past the {spec['time_cap_seconds']}s cap")

    if not fail_lines:
        print(f"PASS  (partial report after {elapsed:.0f}s: {result['summary']})")
        print()
        return True
    print("FAIL")
    for line in fail_lines:
        print(line)
    print()
    return False


def run_target(spec):
    name = spec["name"]
    target = spec["target"]
    expected = Counter(spec["expected_categories"])
    flaky = spec.get("flaky_categories")

    print(f"=== {name} ===")
    print(f"    target: {target}")

    try:
        problems, could_not_check = run_check(target)
    except Exception as e:
        print(f"FAIL  ({e.__class__.__name__}: {e})")
        print()
        return False

    actual = categorize(problems)
    fail_lines, note_lines = diff_report(expected, actual, flaky)
    fail_lines.extend(check_accessibility_categories(spec, problems))
    fail_lines.extend(check_expected_notes(spec, could_not_check))

    if not fail_lines:
        total = sum(actual.values())
        cnc = f", {len(could_not_check)} couldn't-check note(s)" if could_not_check else ""
        print(f"PASS  ({total} problem(s){cnc}, matching expected categories)")
        for line in note_lines:
            print(line)
        print()
        return True

    print("FAIL")
    for line in fail_lines:
        print(line)
    for line in note_lines:
        print(line)
    print()
    return False


def run_embedded_form_target(spec):
    """Like run_target(), but for a "mode": "embedded_form" spec: spins up
    a local HTTP server standing in for a real embedded-form provider,
    and sets GETBUGGY_TEST_EMBEDDED_PROVIDER_HOST so
    detect_embedded_form_provider recognizes that local server's hostname
    as a provider — without this, the fixture's iframe (pointing at
    127.0.0.1) would never be recognized as an embedded form at all, since
    real provider domains like calendly.com obviously don't match it.
    GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS is also set, the same opt-in
    run_crawl_target() uses, since check_embedded_forms' fetch of the
    iframe's src goes through the same _is_safe_to_crawl SSRF guard, which
    otherwise rejects a loopback address by design."""
    name = spec["name"]
    target = spec["target"]
    expected = Counter(spec["expected_categories"])
    flaky = spec.get("flaky_categories")

    print(f"=== {name} ===")
    print(f"    target: {target}")

    server = _serve_test_site(EMBEDDED_TEST_SITE_DIR, EMBEDDED_TEST_SITE_PORT)
    os.environ["GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS"] = "true"
    os.environ[TEST_PROVIDER_HOST_ENV_VAR] = "127.0.0.1"
    try:
        problems, could_not_check = run_check(target)
    except Exception as e:
        print(f"FAIL  ({e.__class__.__name__}: {e})")
        print()
        return False
    finally:
        os.environ.pop("GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS", None)
        os.environ.pop(TEST_PROVIDER_HOST_ENV_VAR, None)
        server.shutdown()

    actual = categorize(problems)
    fail_lines, note_lines = diff_report(expected, actual, flaky)
    fail_lines.extend(check_accessibility_categories(spec, problems))
    fail_lines.extend(check_expected_notes(spec, could_not_check))

    if not fail_lines:
        total = sum(actual.values())
        cnc = f", {len(could_not_check)} couldn't-check note(s)" if could_not_check else ""
        print(f"PASS  ({total} problem(s){cnc}, matching expected categories)")
        for line in note_lines:
            print(line)
        print()
        return True

    print("FAIL")
    for line in fail_lines:
        print(line)
    for line in note_lines:
        print(line)
    print()
    return False


def main():
    # --skip-live (or REGRESSION_SKIP_LIVE=true): excludes targets marked
    # "live": True — real external sites subject to real-world drift and
    # network flakiness, not appropriate for a CI check that runs on
    # every push/PR and needs to be fully deterministic. This is what
    # .github/workflows/ci.yml uses; the separate scheduled/manual-
    # dispatch-only live-regression workflow runs the full suite,
    # unfiltered.
    skip_live = "--skip-live" in sys.argv or os.environ.get(
        "REGRESSION_SKIP_LIVE", ""
    ).strip().lower() in ("1", "true", "yes")
    targets = [t for t in TARGETS if not (skip_live and t.get("live"))]
    skipped = len(TARGETS) - len(targets)

    print("GetBuggy regression check")
    print(f"(ENABLE_REAL_FORM_SUBMISSION={os.environ.get('ENABLE_REAL_FORM_SUBMISSION')!r} "
          "— should be None/unset, i.e. default safe mode)")
    if skip_live:
        print(f"(--skip-live: excluding {skipped} live-site target(s))")
    print()

    def _run(spec):
        mode = spec.get("mode")
        if mode == "crawl":
            return run_crawl_target(spec)
        if mode == "score_stability":
            return run_score_stability_target(spec)
        if mode == "crawl_capped":
            return run_capped_crawl_target(spec)
        if mode == "embedded_form":
            return run_embedded_form_target(spec)
        return run_target(spec)

    results = [_run(spec) for spec in targets]

    passed = sum(results)
    total = len(results)
    print("=" * 40)
    print(f"{passed}/{total} target(s) passed")

    if passed != total:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
