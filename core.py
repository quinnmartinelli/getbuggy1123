import concurrent.futures
import datetime
import os
import re
import time
import socket
import ipaddress
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
from playwright.sync_api import sync_playwright

from checks_links import LinkCache, check_page_links, extract_rendered_links
from checks_performance import check_core_web_vitals
from checks_security import check_page_security, run_site_security_pass
from checks_accessibility import (
    A11yScanBudget,
    accessibility_summary,
    check_accessibility,
    has_accessibility_statement,
    missing_statement_finding,
    site_skipped_scan_note,
)
from checks_cookies import (
    DEFAULT_JURISDICTION,
    merge_page_snapshots,
    normalize_jurisdiction,
    run_site_cookie_pass,
    snapshot_page,
)
from checks_seo import check_indexability, check_seo_and_security
from crawl_utils import (
    classify_sitemap_urls,
    clean_url,
    is_same_site,
    looks_like_non_page,
    make_fingerprint,
    matches_soft_404,
    MAX_SITEMAP_BYTES,
    normalize_host,
    page_key,
    parse_robots,
    parse_sitemap,
    registrable_domain,
    select_pages,
    sitemap_candidates,
)
from embedded_form_providers import detect_embedded_form_provider

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

# Every finding also carries a `confidence`, independent of severity:
# `VERIFIED` means the check directly observed the thing it's reporting
# (a real click produced no effect, a tag is missing from the DOM, a real
# request failed); `NEEDS_LOOK` means the signal is inherently indirect,
# single-shot, or environment-dependent (a bot-blocked link probe, a
# multi-step form the check couldn't fully get through, a timing
# measurement made from our own server) — worth a person's judgment
# before treating it as confirmed. Severity says how bad it'd be *if
# true*; confidence says how sure we are. A finding can be HIGH severity
# and still `needs_look` (a form that looks broken but that the check
# couldn't fully verify), and vice versa.
VERIFIED = "verified"
NEEDS_LOOK = "needs_look"


class UnsafeURLError(ValueError):
    pass


def is_local_target(target):
    return not target.startswith("http://") and not target.startswith("https://")


def to_playwright_url(target):
    if is_local_target(target):
        abs_path = os.path.abspath(target)
        return f"file://{abs_path}"
    return target


# A small, fast, well-known page used to calibrate how quickly *this*
# environment can load and render a page right now, before judging whether
# a target page is genuinely slow. Without this, "page took Xs to load"
# conflates the target site's own speed with wherever the checker itself
# happens to be running — a checker on a slower/more constrained host
# would flag every single page it checks as slow, regardless of the site.
REFERENCE_PAGE_URL = "https://example.com"

# Absolute thresholds for how long a page took to load — plain seconds,
# not a multiple of the reference page's own load time. A ratio like
# "took 2.7s — about 50.2x slower than a 0.1s reference page" is
# alarming and means nothing to a business owner (found testing
# heavenmayhem.com): it doesn't say whether 50x is a real problem or two
# extra seconds nobody will notice. Below LOW, no finding at all; a page
# that loads in 2s isn't "slow" just because it's some multiple of
# whatever example.com happened to take.
PAGE_LOAD_LOW_MIN_SECONDS = 3.0
PAGE_LOAD_MEDIUM_MIN_SECONDS = 5.0

# The reference page is still measured (see _measure_reference_baseline)
# and still used — just internally, for calibration, never shown in the
# finding text or driving its threshold. If the reference page itself
# loads this slowly right now, this checker's own environment/network is
# under load, and an absolute load-time reading can't be trusted to
# reflect the target site rather than us — the finding is skipped
# entirely rather than risk blaming the site for something on this end.
REFERENCE_PAGE_UNRELIABLE_MS = 2000

TTFB_GOOD_MAX_MS = 800
TTFB_POOR_MIN_MS = 1800

HEAVY_PAGE_WEIGHT_BYTES = 3 * 1024 * 1024
MANY_REQUESTS_THRESHOLD = 100
OVERSIZED_IMAGE_BYTES = 300 * 1024

# An image whose natural (file) dimensions are more than this many times
# its actual displayed size is being downloaded far bigger than it needs
# to be shown at — a full-resolution photo squeezed into a 200x150
# thumbnail, say. Independent of the 300KB byte-size check above: a
# small, heavily-compressed file can still fail this if the display size
# is tiny, and a large file can still pass it if it's genuinely displayed
# at (close to) its native resolution.
OVERSIZED_IMAGE_DIMENSION_RATIO = 2


def _find_dimension_oversized_images(page):
    """DOM-only pass (no network data needed): compares each <img>'s
    natural (file) pixel dimensions against how big it's actually
    rendered on the page. A pure structural/DOM fact, not timing- or
    network-dependent."""
    try:
        return page.evaluate(
            """
            () => Array.from(document.querySelectorAll('img')).map(img => {
                const rect = img.getBoundingClientRect();
                return {
                    src: img.currentSrc || img.src,
                    naturalWidth: img.naturalWidth,
                    naturalHeight: img.naturalHeight,
                    displayWidth: rect.width,
                    displayHeight: rect.height,
                };
            }).filter(i =>
                i.naturalWidth > 0 && i.naturalHeight > 0 &&
                i.displayWidth > 0 && i.displayHeight > 0 &&
                i.naturalWidth > i.displayWidth * %(ratio)d &&
                i.naturalHeight > i.displayHeight * %(ratio)d
            )
            """
            % {"ratio": OVERSIZED_IMAGE_DIMENSION_RATIO}
        )
    except Exception:
        return []


def _measure_reference_baseline(browser, timeout_ms):
    """Loads REFERENCE_PAGE_URL once and times it, to calibrate "how fast
    is this environment right now" (network path + Chromium rendering)
    before judging any target page's load time relative to it. Returns
    None (calibration unavailable — callers should just skip the relative
    check) if the reference page itself can't be loaded, e.g. no network."""
    ref_page = browser.new_page()
    try:
        start = time.time()
        ref_page.goto(REFERENCE_PAGE_URL, wait_until="load", timeout=timeout_ms)
        return (time.time() - start) * 1000
    except Exception:
        return None
    finally:
        ref_page.close()


def _check_page_load_time(load_ms, baseline_ms, problems):
    """Flags a page whose total load time crosses a fixed, absolute
    threshold (PAGE_LOAD_LOW_MIN_SECONDS / PAGE_LOAD_MEDIUM_MIN_SECONDS
    above) — always `confidence: needs_look`, never a flat claim, since
    this measures *our* Chromium's load time on *our* host, not a real
    visitor's device and connection. This is deliberately not one of the
    "primary" speed signals (TTFB, page weight, request count, oversized
    images, render-blocking scripts) that drive a `verified` speed
    finding — see the note above check_forms's TTFB/weight checks in
    _check_single_page. `baseline_ms` is used only to sanity-check that
    this checker's own environment is currently fast enough to trust
    (see REFERENCE_PAGE_UNRELIABLE_MS) — never shown in the message."""
    if not baseline_ms or baseline_ms > REFERENCE_PAGE_UNRELIABLE_MS:
        return
    seconds = load_ms / 1000
    if seconds < PAGE_LOAD_LOW_MIN_SECONDS:
        return
    severity = MEDIUM if seconds >= PAGE_LOAD_MEDIUM_MIN_SECONDS else LOW
    problems.append(
        {
            "category": "Page Load Time",
            "message": (
                f"This page took {seconds:.1f}s to load. Visitors on a slower "
                "connection may leave before it finishes. Needs a look: "
                "measured from our servers; your visitors may see different "
                "numbers — worth a second look (e.g. with Google PageSpeed "
                "Insights) before treating it as confirmed."
            ),
            "severity": severity,
            "confidence": NEEDS_LOOK,
        }
    )


def get_base_domain(hostname):
    """Registrable-domain heuristic — see crawl_utils.registrable_domain
    (understands common two-part suffixes like "example.co.uk")."""
    return registrable_domain(hostname)


def validate_public_url(url):
    """Raise UnsafeURLError unless url is a public http(s) address.

    This exists for the web service, not the CLI: when a server fetches
    whatever URL a visitor hands it, an attacker can point it at internal
    infrastructure (localhost, cloud metadata endpoints, private IPs) to
    probe or reach systems that should never be internet-exposed. Rejecting
    non-http(s) schemes and private/loopback/link-local resolved addresses
    closes that off.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeURLError("Only http:// and https:// URLs are supported.")

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeURLError("URL is missing a hostname.")

    if hostname.lower() == "localhost":
        raise UnsafeURLError("Local/internal addresses are not allowed.")

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise UnsafeURLError(f"Could not resolve hostname: {hostname}")

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise UnsafeURLError(
                "This URL resolves to a private/internal address and cannot be checked."
            )


# Python's requests library sends a User-Agent that plainly identifies it
# as a script, and some sites (e.g. beakerpharmacy.com) block that outright
# with a 403/406 even though the link works fine for a real visitor. These
# headers make the request look like an ordinary browser to avoid that.
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Status codes that usually mean "this specific request got blocked as a
# bot," not "this link is actually broken." Worth a second opinion before
# reporting them.
BOT_BLOCK_STATUSES = {403, 406, 429}


def _recheck_with_browser(page, url, could_not_check):
    """Re-verify a link using the real browser's own request context
    instead of the requests library. Far less likely to be blocked as a
    bot, since it carries the browser's genuine fingerprint. Only called
    after requests already got a bot-blocking-shaped status code.

    If this ALSO fails, we genuinely have no way to tell "actually
    broken" apart from "blocked as a bot everywhere we tried, including a
    real browser" — that's a "couldn't check" case (recorded in
    `could_not_check`), not a finding."""
    try:
        resp = page.request.head(url, timeout=10000)
        if resp.status >= 400:
            return (
                f"Link to {url} returned HTTP {resp.status} "
                "(confirmed with a real browser, not just blocked as a bot)"
            )
        return None
    except Exception:
        could_not_check.append(
            f"{url} — appears to block automated checks (still blocked even "
            "from a real browser context); couldn't verify whether it's "
            "actually broken."
        )
        return None


def _check_absolute_link(url, page, could_not_check):
    try:
        resp = requests.head(
            url, allow_redirects=True, timeout=5, headers=BROWSER_HEADERS
        )
        if resp.status_code == 401:
            could_not_check.append(
                f"{url} — looks like it requires a login (HTTP 401), so we "
                "can't tell whether it's actually broken."
            )
            return None
        if resp.status_code in BOT_BLOCK_STATUSES:
            return _recheck_with_browser(page, url, could_not_check)
        if resp.status_code >= 400:
            return f"Link to {url} returned HTTP {resp.status_code}"
    except requests.Timeout:
        could_not_check.append(
            f"{url} — timed out, so we can't tell whether it's actually broken."
        )
        return None
    except requests.RequestException as e:
        return f"Link to {url} is unreachable ({e.__class__.__name__})"
    return None


def check_link(href, base_target, page, could_not_check):
    """Return (error message, confidence) if the link is broken, else
    None. A local file-existence check is a direct, deterministic fact —
    `verified`. Every network-based check is a single HTTP probe from our
    own infrastructure, not a real visitor's browser/network/session —
    always `needs_look`, regardless of which branch (plain 4xx/5xx,
    bot-block-recheck-confirmed, connection error) produced it. See
    PROJECT_STATUS.md Known Issues for this check's long history of
    false-positive fixes, which is exactly why."""
    if href.startswith("http://") or href.startswith("https://"):
        message = _check_absolute_link(href, page, could_not_check)
        return (message, NEEDS_LOOK) if message else None

    if is_local_target(base_target):
        base_dir = os.path.dirname(os.path.abspath(base_target))
        local_path = os.path.join(base_dir, href.split("#")[0])
        if not os.path.exists(local_path):
            return (f"Link to {href} points to a file that does not exist", VERIFIED)
        return None

    absolute_url = urljoin(base_target, href)
    message = _check_absolute_link(absolute_url, page, could_not_check)
    return (message, NEEDS_LOOK) if message else None


# Only the first few forms on a page are checked — each one costs several
# seconds (fill + submit + wait to see what happens), and pages with many
# forms are rare enough that this keeps runtime bounded without losing much
# real coverage.
MAX_FORMS_TO_CHECK = 5

FORM_SUBMIT_WAIT_MS = 4000

CONFIRMATION_KEYWORDS = (
    "thank you", "thanks", "success", "received", "confirm", "submitted",
    "we'll be in touch", "we will be in touch", "message sent", "appreciate",
)

# Actually letting a form submission reach a real business's backend creates
# a real fake lead/message every time a check runs — fine for a site you
# own and are deliberately testing, not fine for the public web app
# checking arbitrary strangers' sites with no ownership verification. Off
# by default everywhere (including any future deploy, since nothing sets
# this env var there); set it to "true" only for deliberate local testing.
REAL_FORM_SUBMISSION_ENV_VAR = "ENABLE_REAL_FORM_SUBMISSION"


def _real_form_submission_enabled():
    return os.environ.get(REAL_FORM_SUBMISSION_ENV_VAR, "").strip().lower() in (
        "1", "true", "yes",
    )


PHONE_CANDIDATES = ("5555555555", "555-555-5555", "(555) 555-5555", "555.555.5555")

_DATE_FORMATS = {
    "date": "%Y-%m-%d",
    "datetime-local": "%Y-%m-%dT%H:%M",
}
_DATE_DEFAULTS = {
    "date": "2026-06-15",
    "month": "2026-06",
    "week": "2026-W25",
    "time": "12:30",
    "datetime-local": "2026-06-15T12:30",
}


def _clamp_str_length(value, minlength, maxlength):
    if maxlength is not None and len(value) > maxlength:
        value = value[:maxlength]
    if minlength is not None and len(value) < minlength:
        value = value + ("x" * (minlength - len(value)))
    return value


def _date_within_range(field_type, min_attr, max_attr):
    """Best-effort date/time-ish value inside [min, max] if given, else a
    safe fixed default for the field's type. Only "date" and
    "datetime-local" have a min/max format simple enough to parse and
    clamp here; month/week/time fall back to a fixed plausible value."""
    default = _DATE_DEFAULTS.get(field_type, "2026-06-15")
    fmt = _DATE_FORMATS.get(field_type)
    if fmt is None:
        return default
    try:
        candidate = datetime.datetime.strptime(default, fmt)
        if min_attr:
            lo = datetime.datetime.strptime(min_attr, fmt)
            candidate = max(candidate, lo)
        if max_attr:
            hi = datetime.datetime.strptime(max_attr, fmt)
            candidate = min(candidate, hi)
    except ValueError:
        return default
    return candidate.strftime(fmt)


def _number_within_range(min_attr, max_attr):
    try:
        lo = float(min_attr) if min_attr not in (None, "") else None
    except ValueError:
        lo = None
    try:
        hi = float(max_attr) if max_attr not in (None, "") else None
    except ValueError:
        hi = None
    candidate = 1.0
    if lo is not None and candidate < lo:
        candidate = lo
    if hi is not None and candidate > hi:
        candidate = hi
    return str(int(candidate)) if candidate == int(candidate) else str(candidate)


def _fill_value_for(field, tag, field_type):
    """Pick a harmless test value that satisfies whatever HTML5 validation
    constraints the field declares (type/pattern/min/max/minlength/
    maxlength), based on hints about what it's for (type, name, id,
    placeholder, autocomplete). Returns None if nothing tried satisfies a
    declared `pattern` — callers should treat that as "couldn't fill this
    field" rather than filling it with a value the field itself would
    reject."""
    hints = " ".join(
        filter(
            None,
            [
                field.get_attribute("name") or "",
                field.get_attribute("id") or "",
                field.get_attribute("placeholder") or "",
                field.get_attribute("autocomplete") or "",
            ],
        )
    ).lower()

    pattern = field.get_attribute("pattern")
    minlength = field.get_attribute("minlength")
    maxlength = field.get_attribute("maxlength")
    minlength = int(minlength) if minlength and minlength.isdigit() else None
    maxlength = int(maxlength) if maxlength and maxlength.isdigit() else None

    if field_type in ("date", "month", "week", "time", "datetime-local"):
        candidates = [
            _date_within_range(
                field_type, field.get_attribute("min"), field.get_attribute("max")
            )
        ]
    elif field_type in ("number", "range"):
        candidates = [
            _number_within_range(field.get_attribute("min"), field.get_attribute("max"))
        ]
    elif field_type == "email" or "email" in hints:
        candidates = ["test@example.com"]
    elif field_type == "tel" or "phone" in hints or "tel" in hints:
        candidates = list(PHONE_CANDIDATES)
    elif field_type == "url" or "website" in hints:
        candidates = ["https://example.com"]
    elif tag == "textarea" or "message" in hints or "comment" in hints:
        candidates = ["This is a test message from an automated website checker."]
    elif "name" in hints:
        candidates = ["Test User"]
    elif "zip" in hints or "postal" in hints:
        candidates = ["90210"]
    else:
        candidates = ["Test"]

    candidates = [_clamp_str_length(c, minlength, maxlength) for c in candidates]

    if pattern:
        try:
            compiled = re.compile(pattern)
        except re.error:
            compiled = None
        if compiled is not None:
            matching = [c for c in candidates if compiled.fullmatch(c)]
            if matching:
                return matching[0]
            # The type-specific guesses above didn't satisfy this field's
            # own pattern — try a few generic shapes before giving up.
            for fallback in ("Test123", "12345", "test"):
                fallback = _clamp_str_length(fallback, minlength, maxlength)
                if compiled.fullmatch(fallback):
                    return fallback
            return None

    return candidates[0]


def _fill_form(form):
    """Fill a form's visible, enabled fields with harmless test values
    that satisfy each field's own HTML5 validation constraints. Returns
    True if anything was actually filled — a form with nothing fillable
    (e.g. just a submit button) isn't the "silently broken lead capture
    form" case this check cares about.

    A field this couldn't find a valid value for (a `pattern` none of the
    guesses match, or a `required` file/password field, which are never
    filled) is deliberately left blank rather than filled with something
    the field would reject — `check_forms` checks the form's overall
    validity afterward and reports which fields are still invalid, rather
    than assuming a resulting failed submit means the form itself is
    broken."""
    filled_any = False

    for field in form.query_selector_all("input, textarea, select"):
        try:
            if not field.is_visible() or not field.is_enabled():
                continue

            tag = field.evaluate("el => el.tagName.toLowerCase()")
            field_type = (field.get_attribute("type") or "text").lower()

            if tag == "input" and field_type in (
                "hidden", "submit", "button", "reset", "image", "file", "password",
            ):
                continue

            if tag == "select":
                for option in field.query_selector_all("option"):
                    value = option.get_attribute("value")
                    if value:
                        field.select_option(value=value)
                        filled_any = True
                        break
            elif field_type in ("checkbox", "radio"):
                if not field.is_checked():
                    field.check()
                filled_any = True
            else:
                value = _fill_value_for(field, tag, field_type)
                if value is None:
                    continue
                field.fill(value)
                filled_any = True
        except Exception:
            # Some fields resist scripted input (custom widgets, readonly,
            # unusual types) — skip rather than let one field abort the
            # whole form check.
            continue

    return filled_any


def check_render_blocking_scripts(page, problems):
    """A <script> in <head> that isn't async/defer (or type="module",
    which is deferred by default) blocks the browser from continuing to
    parse and render the rest of the page until it finishes downloading
    (if external) and executing — a pure DOM/attribute fact, no timing
    or network measurement involved, so `confidence: verified`. One of
    the "primary" speed signals (alongside TTFB, page weight, request
    count, and oversized images) that don't depend on where this checker
    happens to be hosted."""
    try:
        blocking = page.evaluate(
            """
            () => Array.from(document.querySelectorAll('head script')).filter(s => {
                const type = (s.getAttribute('type') || '').toLowerCase();
                if (type && type !== 'text/javascript' && type !== 'application/javascript') {
                    return false;
                }
                return !s.async && !s.defer;
            }).map(s => s.src || '(inline script)')
            """
        )
    except Exception:
        return

    if not blocking:
        return

    external = [b for b in blocking if b != "(inline script)"]
    inline_count = len(blocking) - len(external)

    parts = []
    if external:
        examples = ", ".join(u.rsplit("/", 1)[-1] for u in external[:3])
        more = f" (+{len(external) - 3} more)" if len(external) > 3 else ""
        parts.append(f"{len(external)} external script(s) ({examples}{more})")
    if inline_count:
        parts.append(f"{inline_count} inline script(s)")

    problems.append(
        {
            "category": "Render-Blocking Scripts",
            "message": (
                f"This page's <head> loads {' and '.join(parts)} without "
                "`async` or `defer` — the browser has to stop and run them "
                "before it can continue showing the rest of the page, which "
                "delays when visitors see anything at all. Adding `defer` "
                "(or `async` if the script doesn't depend on page content) "
                "usually fixes this."
            ),
            "severity": MEDIUM,
            "confidence": VERIFIED,
            # This page's exact set of blocking scripts — typically the
            # same theme-wide set on every page (so it still collapses via
            # dedupe_site_problems), but a page that genuinely loads a
            # different set stays its own finding.
            "evidence": "|".join(sorted(blocking)),
        }
    )


# Wizards very often give their step-advance button no explicit `type`
# attribute — the same shape a real submit button has — so step
# advancement is detected by text/label instead of by selector, checked
# BEFORE the submit-trigger search so a "Next" click is never mistaken for
# the form's real, final submission.
NEXT_TRIGGER_TEXT_RE = re.compile(r"^\s*(next|continue|proceed)\s*$", re.I)

# Words a JS-framework "button" (a styled <div>/<a> with a click handler,
# not a semantic <button>) commonly carries when it's really this form's
# submit trigger. Deliberately excludes "next"/"continue" so a wizard's
# step-advance control is never picked up here instead of by
# NEXT_TRIGGER_TEXT_RE.
SUBMIT_TRIGGER_TEXT_RE = re.compile(
    r"\b(submit|send|book|schedule|subscribe|sign\s?up|get\s+quote|request|"
    r"apply|register|order|buy|checkout)\b",
    re.I,
)

MAX_WIZARD_STEPS = 8
WIZARD_STEP_WAIT_MS = 500


def _element_label(el):
    """Best-effort human-readable text for a candidate trigger element,
    whatever kind of element it is (a <button>/<div>'s inner text, or an
    <input type=button>'s value, or an aria-label as a last resort)."""
    try:
        text = el.inner_text().strip()
        if text:
            return text
    except Exception:
        pass
    try:
        value = (el.get_attribute("value") or "").strip()
        if value:
            return value
    except Exception:
        pass
    try:
        return (el.get_attribute("aria-label") or "").strip()
    except Exception:
        return ""


def _find_native_submit_trigger(form):
    """The semantic-HTML submit trigger, if any — regardless of whether
    it's currently visible (a wizard's final step is often hidden until
    earlier steps are completed)."""
    return form.query_selector(
        "button[type=submit], input[type=submit], button:not([type])"
    )


def _find_next_trigger(form):
    """Look for a wizard's step-advance control: a visible button/link
    whose label reads "Next"/"Continue"/"Proceed", or that's explicitly
    marked as one via a data-next-ish attribute."""
    for el in form.query_selector_all(
        "button, input[type=button], input[type=submit], [role='button'], a"
    ):
        try:
            if not el.is_visible():
                continue
        except Exception:
            continue
        if NEXT_TRIGGER_TEXT_RE.match(_element_label(el)):
            return el
        for attr in ("data-next", "data-step-next", "data-action"):
            try:
                if "next" in (el.get_attribute(attr) or "").lower():
                    return el
            except Exception:
                continue
    return None


def _find_submit_trigger(form):
    """Find the element that actually submits this form, checked in
    priority order: native semantic elements first (most certain), then
    progressively wider heuristics for JS-framework "buttons" that aren't
    real HTML submit elements at all. Returns (element, kind); both are
    None if nothing at any priority level matches.

    `<a>` candidates with a real navigational `href` are excluded from the
    click-handler heuristic — clicking a genuine link elsewhere on a live
    site is a real navigation, not a safe thing to trigger speculatively
    just because its label looks submit-ish."""
    el = _find_native_submit_trigger(form)
    if el:
        return el, "native"

    for el in form.query_selector_all("[role='button']"):
        try:
            if el.is_visible():
                return el, "role-button"
        except Exception:
            continue

    for el in form.query_selector_all("a, div"):
        try:
            if not el.is_visible():
                continue
            href = el.get_attribute("href")
            if href and href not in ("", "#") and not href.lower().startswith("javascript:"):
                continue
            has_onclick = el.get_attribute("onclick") is not None
            looks_like_submit = has_onclick or bool(
                SUBMIT_TRIGGER_TEXT_RE.search(_element_label(el))
            )
            if not looks_like_submit:
                continue
            cursor = el.evaluate("e => getComputedStyle(e).cursor")
        except Exception:
            continue
        if has_onclick or cursor == "pointer":
            return el, "click-handler"

    return None, None


def _is_multi_step_form(form):
    """Detect a wizard/multi-step form: a "Next"-style step-advance
    control, more than one <fieldset> with not all of them visible at
    once, or a submit trigger that exists but is hidden on load (a very
    common way a wizard hides its final step until earlier ones are
    done)."""
    if _find_next_trigger(form) is not None:
        return True
    try:
        fieldsets = form.query_selector_all("fieldset")
        if len(fieldsets) > 1:
            visible = sum(1 for fs in fieldsets if fs.is_visible())
            if 0 < visible < len(fieldsets):
                return True
    except Exception:
        pass
    try:
        submit_el = _find_native_submit_trigger(form)
        if submit_el is not None and not submit_el.is_visible():
            return True
    except Exception:
        pass
    return False


def _advance_wizard(form, page):
    """Best-effort: fill and click through a wizard's steps until either
    reaching a step whose native submit trigger is visible (ready for the
    normal test-and-observe flow below) or getting stuck partway through
    (no step-advance control found, or clicking one changes nothing).
    Returns the final step's submit-trigger element, or None if stuck."""
    for _ in range(MAX_WIZARD_STEPS):
        _fill_form(form)

        submit_el = _find_native_submit_trigger(form)
        if submit_el is not None:
            try:
                if submit_el.is_visible():
                    return submit_el
            except Exception:
                pass

        next_el = _find_next_trigger(form)
        if next_el is None:
            break

        try:
            before_html = form.evaluate("f => f.innerHTML")
        except Exception:
            before_html = None

        try:
            next_el.click(timeout=3000)
        except Exception:
            break

        page.wait_for_timeout(WIZARD_STEP_WAIT_MS)

        try:
            after_html = form.evaluate("f => f.innerHTML")
        except Exception:
            after_html = None

        if before_html is not None and before_html == after_html:
            break  # clicking "next" changed nothing on the page — stuck

    # The wizard never revealed a *visible native* submit trigger — one
    # more chance, in case the final step's real trigger is a
    # JS-framework "button" (role=button, or a styled div/a) rather than
    # a semantic <button>. _find_next_trigger would already have caught
    # and clicked a genuine step-advance control before we got here, so
    # anything this finds now is a real final-step submit trigger, not
    # another "Next". Must still check visibility explicitly:
    # _find_submit_trigger's native branch (unlike its role-button/
    # click-handler branches) doesn't check it, since callers elsewhere
    # rely on being able to find a not-yet-visible native button — here,
    # a hidden one just means the wizard is still genuinely stuck.
    fallback_el, _ = _find_submit_trigger(form)
    if fallback_el is not None:
        try:
            if fallback_el.is_visible():
                return fallback_el
        except Exception:
            pass
    return None


# A form posting to one of these is the platform's own infrastructure
# (login, account management, ...) embedded by the theme — not a lead
# form the business owns or is trying to capture, and not something this
# checker's form-verification logic (fill test data, submit, look for a
# confirmation) has any business testing. Registrable domains, so a
# subdomain (e.g. accounts.google.com under a hypothetical future entry)
# would still match. Found worth adding testing heavenmayhem.com — see
# PROJECT_STATUS.md.
PLATFORM_FORM_DOMAINS = {
    "shopify.com",
    "myshopify.com",
    "squarespace.com",
    "wix.com",
    "webflow.io",
    "wordpress.com",
}


def check_forms(page, problems, all_responses, deliberately_blocked_urls, target_base_domain=""):
    """Fill and submit each form with harmless test data, then check what
    actually happened afterward. A form that produces no redirect, no
    confirmation message, and no successful response is likely silently
    dropping every submission — a business's contact/booking/signup form
    failing this way means real leads vanish with no one aware it's
    happening.

    By default (REAL_FORM_SUBMISSION_ENV_VAR unset), the actual outgoing
    submission is intercepted and aborted before it leaves the browser, so
    no real test data ever reaches the target site's backend — this is the
    "front-end-only" mode. A form that doesn't even attempt to submit
    anything (no request, no navigation) is still reported as genuinely
    broken, since that's observable without letting anything through. A
    form that does attempt something is reported as unverified rather than
    "working," since the real submission was never allowed to complete.
    Full verification (actually letting the submission through) only runs
    when explicitly opted into for testing.

    Handles three cases that used to produce a wrong verdict: multi-step
    "wizard" forms (advances through steps to actually test the final
    submit, instead of mistaking a step-advance click for success),
    non-button submit triggers (role=button / styled div-or-a "buttons" /
    Enter-to-submit, not just <button type=submit>), and HTML5 validation
    that would otherwise silently block the test submission (fields are
    filled with constraint-satisfying values where feasible; a field that
    can't be satisfied is reported by name as "needs a look" rather than
    the form being called broken)."""
    real_submission = _real_form_submission_enabled()
    forms = page.query_selector_all("form")[:MAX_FORMS_TO_CHECK]

    blocked_attempts = []

    # Only intercepts background AJAX/fetch-style submissions (the common
    # case for modern contact-form widgets), and deliberately leaves
    # navigation requests alone. Aborting a *navigation* request makes
    # Chromium load its own network-error page — which both changes
    # page.url (falsely looking like "it redirected, so it must have
    # worked") and fires a requestfailed event that would otherwise get
    # mistaken for a real broken-resource bug. Native/full-page-navigation
    # forms are instead stopped at the DOM level below, before the browser
    # ever tries to make the request in the first place.
    def _block_mutating_requests(route):
        request = route.request
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and not (
            request.is_navigation_request()
        ):
            blocked_attempts.append(request.method)
            deliberately_blocked_urls.add(request.url)
            route.abort()
        else:
            route.continue_()

    if not real_submission:
        page.route("**/*", _block_mutating_requests)

    try:
        for index, form in enumerate(forms):
            try:
                if not form.is_visible():
                    continue
            except Exception:
                continue

            # Read before doing anything else: even an aborted navigation
            # can destroy the page's JS execution context, which would
            # make a later form.get_attribute() call throw.
            try:
                identity = form.get_attribute("id") or form.get_attribute("name")
            except Exception:
                identity = None
            label = identity or f"#{index + 1}"
            # Cross-page dedup evidence (see dedupe_site_problems): a real
            # id/name is a stable identity, so the same form repeated on
            # every page (e.g. a shared header signup form) correctly
            # collapses to one finding. The "#N" fallback is NOT a stable
            # identity — it's just "the Nth form on THIS page" — so two
            # unrelated, both-unlabeled forms on two different pages would
            # otherwise get merged into one finding, silently hiding that
            # they're separate. Scoping the fallback to this page's URL
            # means it can never wrongly merge across pages; the worst
            # case is under-merging (an actually-identical shared form
            # without an id shows up once per page instead of once) —
            # a far safer failure than hiding a distinct broken form.
            form_evidence = identity if identity else f"{label}@{page.url}"

            # A form that posts to the platform's own domain (Shopify's
            # own login, a Squarespace/Wix account form embedded by the
            # theme, ...) isn't a lead the business is trying to capture
            # — it's the platform's own infrastructure, tested and
            # maintained by the platform, not something a "your contact
            # form might be losing leads" check should ever touch. Read
            # before anything else so a login form is never filled,
            # clicked, or submitted at all — not just excused afterward.
            action = form.get_attribute("action") or ""
            action_domain = ""
            try:
                absolute_action = urljoin(page.url, action) if action else page.url
                action_domain = get_base_domain(urlparse(absolute_action).hostname)
            except Exception:
                pass
            if action_domain in PLATFORM_FORM_DOMAINS:
                continue

            wizard_trigger = None
            if _is_multi_step_form(form):
                wizard_trigger = _advance_wizard(form, page)
                if wizard_trigger is None:
                    problems.append(
                        {
                            "category": "Form Needs A Look",
                            "message": (
                                f"Form {label} looks like a multi-step ('Next'/"
                                "step-by-step) form, but the automated check "
                                "couldn't get all the way through it to test the "
                                "real, final submission — worth a manual "
                                "walkthrough to confirm it actually works."
                            ),
                            "severity": MEDIUM,
                            "confidence": NEEDS_LOOK,
                            "evidence": form_evidence,
                        }
                    )
                    continue
                # _advance_wizard already filled and left the DOM on the
                # final step, ready to be tested exactly like a normal
                # single-step form below.
            else:
                # Skip only if the form has nothing to fill at all (e.g.
                # just a submit button) — not the same as "everything we
                # tried to fill failed": a form whose one field's pattern
                # we couldn't satisfy still has a real field, and must
                # fall through to the checkValidity() check below rather
                # than being silently skipped as "not this check's
                # concern."
                has_candidate_fields = (
                    form.query_selector("input, textarea, select") is not None
                )
                _fill_form(form)
                if not has_candidate_fields:
                    continue

            try:
                is_valid = form.evaluate("f => f.checkValidity()")
            except Exception:
                is_valid = True  # can't determine — don't block on an unknown

            if not is_valid:
                try:
                    invalid_fields = form.evaluate(
                        "f => Array.from(f.querySelectorAll(':invalid')).map("
                        "el => el.name || el.id || el.type || 'field')"
                    )
                except Exception:
                    invalid_fields = []
                fields_note = f" ({', '.join(invalid_fields)})" if invalid_fields else ""
                problems.append(
                    {
                        "category": "Form Needs A Look",
                        "message": (
                            f"Form {label} has a field{fields_note} the "
                            "automated test couldn't fill with a value that "
                            "satisfies its format rules (required, pattern, "
                            "min/max, etc.), so the real submission was never "
                            "attempted — worth a manual check to confirm real "
                            "visitors can actually submit it."
                        ),
                        "severity": MEDIUM,
                        "confidence": NEEDS_LOOK,
                        "evidence": form_evidence,
                    }
                )
                continue

            trigger = wizard_trigger
            trigger_kind = "native" if wizard_trigger is not None else None
            if trigger is None:
                trigger, trigger_kind = _find_submit_trigger(form)

            if trigger is None:
                # Last resort: a form with a fillable text field but no
                # button, role=button, or click-handler-looking element
                # at all relies on the browser's native Enter-to-submit
                # behavior, the same as a real visitor pressing Enter.
                try:
                    first_text_field = form.query_selector(
                        "input:not([type=hidden]):not([type=submit])"
                        ":not([type=button]):not([type=checkbox])"
                        ":not([type=radio]):not([type=file])"
                    )
                    if first_text_field is not None and first_text_field.is_visible():
                        trigger = first_text_field
                        trigger_kind = "enter-to-submit"
                except Exception:
                    pass

            if trigger is None:
                problems.append(
                    {
                        "category": "Form Needs A Look",
                        "message": (
                            f"Form {label} doesn't have a submit button, a "
                            "labeled action control, or a text field a real "
                            "visitor could press Enter in — the automated "
                            "check couldn't find any way to submit it. Worth "
                            "a manual check."
                        ),
                        "severity": MEDIUM,
                        "confidence": NEEDS_LOOK,
                        "evidence": form_evidence,
                    }
                )
                continue

            submits_third_party = bool(target_base_domain) and bool(action_domain) and action_domain != target_base_domain
            destination_note = (
                f" This form submits to a third-party service ({action_domain}), not your own site."
                if submits_third_party
                else " This form submits to your own site."
            )

            if not real_submission:
                # Stops the browser's default action (a real page
                # navigation) before it's ever dispatched, for forms with
                # no JS override. This doesn't stop the form's own JS
                # handlers from running — only the route interception
                # above does that, for whatever network call they make.
                #
                # A submit event fires on every click regardless of
                # whether the form actually does anything useful, so "the
                # event fired" can't be the signal for "this form tries to
                # do something." What matters is whether the default
                # action was *still going to happen* when our handler
                # runs: if an earlier handler (the site's own JS, or an
                # inline onsubmit like the intentionally-broken test form)
                # already called preventDefault, the native navigation was
                # never going to happen regardless of us, so we don't mark
                # it as an attempt — only a real fetch/XHR call the site's
                # own code makes (caught by the route interception above)
                # counts in that case. This must be a bubble-phase listener
                # (the default — no {capture: true}): capturing listeners
                # run before bubble-phase ones on the same element
                # regardless of registration order, and the site's own
                # handlers (inline onsubmit=, or a plain addEventListener
                # call) are bubble-phase, so a bubble-phase listener here
                # is what actually runs after them, in registration order.
                try:
                    form.evaluate(
                        "f => f.addEventListener('submit', e => { "
                        "if (!e.defaultPrevented) { "
                        "f.setAttribute('data-getbuggy-attempted', '1'); "
                        "} "
                        "e.preventDefault(); "
                        "})"
                    )
                except Exception:
                    pass

            pre_url = page.url
            try:
                pre_text = page.inner_text("body")
            except Exception:
                pre_text = ""

            responses_start = len(all_responses)
            blocked_start = len(blocked_attempts)

            try:
                if trigger_kind == "enter-to-submit":
                    trigger.click(timeout=3000)
                    trigger.press("Enter")
                else:
                    trigger.click(timeout=3000)
            except Exception:
                # If the click/submit itself errors (e.g. navigation tore
                # down the context mid-click), fall through to the outcome
                # check below rather than assume broken — a real
                # navigation may have already started.
                pass

            page.wait_for_timeout(FORM_SUBMIT_WAIT_MS)

            post_url = page.url
            try:
                post_text = page.inner_text("body")
            except Exception:
                post_text = pre_text

            redirected = post_url != pre_url

            new_responses = all_responses[responses_start:]
            got_success_response = any(
                method in ("POST", "PUT", "PATCH") and 200 <= status < 400
                for method, status in new_responses
            )

            confirmation_appeared = False
            if post_text != pre_text:
                lowered = post_text.lower()
                confirmation_appeared = any(
                    k in lowered for k in CONFIRMATION_KEYWORDS
                )

            if redirected or got_success_response or confirmation_appeared:
                continue

            native_attempted = False
            if not real_submission:
                try:
                    native_attempted = (
                        form.get_attribute("data-getbuggy-attempted") == "1"
                    )
                except Exception:
                    native_attempted = False

            was_attempted = len(blocked_attempts) > blocked_start or native_attempted
            if was_attempted and not real_submission:
                problems.append(
                    {
                        "category": "Form Not Fully Verified",
                        "message": (
                            f"Form {label} attempted to submit, but real-submission "
                            "checks are disabled in this environment, so it wasn't "
                            "allowed to actually send — this only confirms the form "
                            "tries to do something, not that it succeeds. Recommend "
                            f"a manual test to confirm leads are actually received.{destination_note}"
                        ),
                        "severity": LOW,
                        "confidence": NEEDS_LOOK,
                        "evidence": form_evidence,
                    }
                )
            else:
                problems.append(
                    {
                        "category": "Broken Form",
                        "message": (
                            f"Form {label} was filled with test values and "
                            "submitted, but nothing happened afterward — no "
                            "redirect, no confirmation message, and no successful "
                            f"network response. This may be silently losing leads.{destination_note}"
                        ),
                        "severity": HIGH,
                        "confidence": VERIFIED,
                        "evidence": form_evidence,
                    }
                )
    finally:
        if not real_submission:
            page.unroute("**/*", _block_mutating_requests)


EMBEDDED_FORM_LOAD_TIMEOUT_MS = 15000


def check_embedded_forms(browser, page, problems, could_not_check=None):
    """Detect iframe-embedded third-party form/booking widgets (Calendly,
    Typeform, HubSpot, etc. — see embedded_form_providers.py) that
    check_forms can't fill or submit into at all, since they're
    cross-origin iframes, not real <form> elements on this page. The
    original bug this fixes: these were silently skipped entirely, with
    nothing in the report indicating anything was skipped, even though an
    embedded booking/contact widget is often the one form that actually
    matters for this tool's target audience.

    Rather than trying to reach into the iframe's cross-origin content (or
    just silently skipping it, the original bug), this does a fresh,
    independent navigation straight to the iframe's own src — the same
    address the provider serves the widget from — and checks the HTTP
    status, that real content rendered, and that it didn't log an error
    in its own console. That's the front-end-only signal that's actually
    available for an embed this tool deliberately doesn't fill or
    submit. Every resulting finding is `confidence: verified` — this is
    always a directly-observed load outcome, not an inference."""
    seen_srcs = set()
    for iframe_el in page.query_selector_all("iframe"):
        try:
            src = iframe_el.get_attribute("src") or ""
        except Exception:
            continue
        if not src or src in seen_srcs:
            continue
        provider = detect_embedded_form_provider(src)
        if not provider:
            continue
        seen_srcs.add(src)

        absolute_src = urljoin(page.url, src)

        # Same SSRF guard every other fetch derived from site content goes
        # through — the iframe's src is untrusted page content, not
        # something the user directly typed in. Failing this guard means
        # we genuinely never looked at it at all, not that we looked and
        # found something dubious — that's a "couldn't check" case.
        if not _is_safe_to_crawl(absolute_src):
            note = (
                f"This page embeds a {provider} form, but its address "
                "didn't pass our safety check, so it couldn't be verified."
            )
            if could_not_check is not None:
                could_not_check.append(note)
            else:
                problems.append(
                    {
                        "category": "Embedded Form",
                        "message": note,
                        "severity": MEDIUM,
                        "confidence": NEEDS_LOOK,
                    }
                )
            continue

        console_errors = []
        widget_page = browser.new_page()
        try:
            widget_page.on(
                "console",
                lambda msg: console_errors.append(msg.text)
                if msg.type == "error"
                else None,
            )

            try:
                response = widget_page.goto(
                    absolute_src,
                    timeout=EMBEDDED_FORM_LOAD_TIMEOUT_MS,
                    wait_until="load",
                )
            except Exception as e:
                problems.append(
                    {
                        "category": "Embedded Form",
                        "message": (
                            f"Embedded form from {provider} fails to load "
                            f"({e.__class__.__name__})."
                        ),
                        "severity": HIGH,
                        "confidence": VERIFIED,
                    }
                )
                continue

            status = response.status if response else None
            try:
                has_content = widget_page.evaluate(
                    "() => !!(document.body && "
                    "document.body.innerText.trim().length > 0)"
                )
            except Exception:
                has_content = False

            if status is not None and status >= 400:
                problems.append(
                    {
                        "category": "Embedded Form",
                        "message": (
                            f"Embedded form from {provider} fails to load "
                            f"(HTTP {status})."
                        ),
                        "severity": HIGH,
                        "confidence": VERIFIED,
                    }
                )
            elif not has_content:
                problems.append(
                    {
                        "category": "Embedded Form",
                        "message": (
                            f"Embedded form from {provider} fails to load "
                            "(the widget loaded blank, with no visible content)."
                        ),
                        "severity": HIGH,
                        "confidence": VERIFIED,
                    }
                )
            elif console_errors:
                problems.append(
                    {
                        "category": "Embedded Form",
                        "message": (
                            f"Embedded form from {provider} loaded, but logged "
                            f"an error in its own console ({console_errors[0]}) "
                            "— worth a manual look to confirm it still works."
                        ),
                        "severity": HIGH,
                        "confidence": VERIFIED,
                    }
                )
            else:
                problems.append(
                    {
                        "category": "Embedded Form",
                        "message": f"Embedded form from {provider} — loads correctly.",
                        "severity": LOW,
                        "confidence": VERIFIED,
                        # A "this works" note, not a problem: never scored (Step 8).
                        "informational": True,
                    }
                )
        finally:
            widget_page.close()


MOBILE_VIEWPORT = {"width": 390, "height": 844}

# Runs in the page: checks for horizontal overflow at a phone-width
# viewport — a real layout break, not a design choice. This used to also
# count small text and small tap targets, removed as a deliberate product
# decision (2026-09-26, see PLAN.md): small text on a brand site is a
# design choice, not a bug, and flagging it read as not understanding the
# business — a site owner reading "12 elements have text smaller than
# 12px" about their own intentional typography doesn't trust the rest of
# the report. The tap-target version of the same check also had a
# documented over-counting problem (PROJECT_STATUS.md Known Issues)
# that's moot now that it's gone entirely, not just tuned.
_MOBILE_CHECK_JS = """
() => ({
  scrollWidth: document.documentElement.scrollWidth,
  clientWidth: document.documentElement.clientWidth,
})
"""


def check_mobile_responsiveness(browser, url, timeout_ms, problems, could_not_check=None):
    """Load the same page again at a phone-sized viewport and check for
    horizontal overflow — content wider than the viewport, a real,
    unambiguous layout break on small screens, never a design choice.
    This is a direct pixel measurement at a fixed viewport, not timing-
    or network-dependent, so the finding is `confidence: verified`.

    (This check used to also flag small text and small tap targets;
    removed 2026-09-26 as a product decision, not a bug fix — see
    PLAN.md.)

    If the check itself can't complete (most commonly: this fresh
    navigation times out on an unusually slow/heavy page), that's an
    expensive check we couldn't finish, not a "problem" with the page —
    recorded in `could_not_check` instead of `problems` if a list is
    given."""
    mobile_page = browser.new_page(viewport=MOBILE_VIEWPORT)
    try:
        mobile_page.goto(url, wait_until="load", timeout=timeout_ms)
        result = mobile_page.evaluate(_MOBILE_CHECK_JS)

        if result["scrollWidth"] > result["clientWidth"] + 5:
            problems.append(
                {
                    "category": "Mobile Horizontal Scroll",
                    "message": (
                        f"Page content is {result['scrollWidth']}px wide but the "
                        f"phone screen is only {result['clientWidth']}px — visitors "
                        "on mobile have to scroll sideways, a sign the layout "
                        "breaks on small screens."
                    ),
                    "severity": MEDIUM,
                    "confidence": VERIFIED,
                }
            )
    except Exception as e:
        note = (
            f"Couldn't complete the mobile responsiveness check on this "
            f"page ({e.__class__.__name__}) — often means the page was too "
            "slow or heavy to finish loading within our time budget."
        )
        if could_not_check is not None:
            could_not_check.append(note)
        else:
            problems.append(
                {
                    "category": "Mobile Check Failed",
                    "message": note,
                    "severity": LOW,
                    "confidence": NEEDS_LOOK,
                }
            )
    finally:
        mobile_page.close()


# ---------------------------------------------------------------------------
# Whole-site crawl: discover a site's pages (sitemap.xml, falling back to
# homepage links), respect robots.txt, cap how many pages get checked, and
# run the normal per-page checks on each one.
# ---------------------------------------------------------------------------

# 5 by default (product decision, 2026-09-19 — see PLAN.md's pricing
# table): the free tier checks 5 pages; Pro checks 10+. A config value,
# not a hardcoded limit, specifically so it can be raised for Pro without
# touching the crawl logic itself — set CRAWL_PAGE_CAP to override. Each
# additional page costs a full page-load-plus-checks pass, so this also
# keeps a single "check my site" request from potentially running for
# many minutes.
DEFAULT_CRAWL_PAGE_CAP = 5

# How many pages within a single crawl are checked at once. Each one is a
# real headless Chromium instance (or two — see _check_page_standalone),
# so this is a real memory/CPU tradeoff, not just a number. Lowered from
# 3 to 2 on 2026-09-17 after a live-server crawl of medvi.org (10 pages)
# crashed the deployed Render container three times in a row at
# concurrency 3 — then lowered again to 1 on 2026-09-18 after a 3-page
# live crawl still crashed the container at concurrency 2 — see
# PROJECT_STATUS.md Known Issues. An env var, not just a constant,
# specifically so it can be tuned on Render without a deploy while the
# founders decide on a longer-term fix (lower concurrency vs. a bigger
# instance tier).
CRAWL_CONCURRENCY = int(os.environ.get("CRAWL_CONCURRENCY", "1"))


def _check_page_standalone(target, timeout_ms, baseline_ms, **page_kwargs):
    """Used by run_site_check's thread pool: each worker thread gets its
    own Playwright driver connection and browser instance, rather than
    sharing one browser across threads — Playwright's sync API isn't
    documented as safe to call concurrently from multiple threads, so this
    trades one extra Chromium launch per page for genuine, safe wall-clock
    parallelism within a crawl. `page_kwargs` (homepage flag, shared link
    cache, soft-404 fingerprint...) are passed straight through."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            return _check_single_page(
                browser, target, timeout_ms, baseline_ms=baseline_ms, **page_kwargs
            )
        finally:
            browser.close()


# Crawl-discovery requests (sitemap.xml, robots.txt) identify themselves
# truthfully, per the project's safety policy (see PLAN.md's Safety
# section) — unlike BROWSER_HEADERS above, which exists specifically to
# avoid bot-blocking false positives on an individual link-liveness check a
# real visitor could click. A site's robots.txt is exactly the mechanism by
# which it tells crawlers what they may access, so pretending to be a
# browser here would defeat the point of checking it at all.
CRAWLER_USER_AGENT = "GetBuggyBot"
CRAWLER_HEADERS = {
    "User-Agent": (
        f"{CRAWLER_USER_AGENT}/1.0 "
        "(+https://github.com/quinnmartinelli/website-checker)"
    ),
}

# Sitemap index files can chain (a sitemap index pointing at other sitemap
# indexes); this bounds how deep we'll follow that chain, and how many
# page URLs we'll collect in total before applying page_cap — both guard
# against a pathological or malicious sitemap making discovery itself slow
# or unbounded. (Each sitemap download is also size-capped: see
# crawl_utils.MAX_SITEMAP_BYTES.)
MAX_SITEMAP_INDEX_DEPTH = 3
MAX_SITEMAP_URLS_TO_COLLECT = 500

# How many sitemap URLs get a status probe (404? redirect?) — bounded so a
# 500-URL sitemap can't turn discovery into a minute of HEAD requests.
SITEMAP_PROBE_LIMIT = 100
SITEMAP_PROBE_WORKERS = 8


# Off by default everywhere, same pattern as REAL_FORM_SUBMISSION_ENV_VAR:
# an explicit opt-in only the regression test suite sets, to crawl a local
# test server (necessarily a loopback address, which _is_safe_to_crawl
# rejects by design). Never set in normal/production operation.
ALLOW_PRIVATE_CRAWL_TARGETS_ENV_VAR = "GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS"


def _is_safe_to_crawl(url):
    """Sitemap.xml and on-page links are untrusted data from the site
    being checked, not something the user directly typed in — a malicious
    or compromised site could list an internal address (e.g. a cloud
    metadata endpoint) as a "page" to trick the crawler into fetching it.
    Every discovered URL gets the same public-address check the originally
    submitted URL already gets at the API layer, not just that one."""
    if os.environ.get(ALLOW_PRIVATE_CRAWL_TARGETS_ENV_VAR, "").strip().lower() in (
        "1", "true", "yes",
    ):
        return True
    try:
        validate_public_url(url)
        return True
    except UnsafeURLError:
        return False


def _fetch_robots(site_root):
    """Fetch robots.txt once. Returns (RobotFileParser used to decide what
    this crawler may visit, parse_robots() summary used for findings and
    Sitemap: directives). Missing/unreachable/unparseable robots.txt means
    "no restrictions stated," not "assume the worst.\""""
    robots_url = urljoin(site_root, "/robots.txt")
    text = ""
    status = None
    try:
        resp = requests.get(robots_url, timeout=10, headers=CRAWLER_HEADERS)
        status = resp.status_code
        if resp.status_code < 400:
            text = resp.text
    except requests.RequestException:
        pass
    parser = RobotFileParser()
    parser.set_url(robots_url)
    parser.parse(text.splitlines())
    info = parse_robots(text)
    info["http_status"] = status
    return parser, info


def _fetch_bytes(url, limit=MAX_SITEMAP_BYTES):
    """Size-bounded download for sitemaps, behind the SSRF guard. None on
    any failure or if the file is over `limit`."""
    if not _is_safe_to_crawl(url):
        return None
    try:
        with requests.get(url, timeout=10, headers=CRAWLER_HEADERS, stream=True) as resp:
            if resp.status_code >= 400:
                return None
            buf = bytearray()
            for chunk in resp.iter_content(65536):
                buf += chunk
                if len(buf) > limit:
                    return None
            return bytes(buf)
    except requests.RequestException:
        return None


def _collect_sitemap(url, site_domain, depth, collected, visited):
    if depth > MAX_SITEMAP_INDEX_DEPTH or len(collected) >= MAX_SITEMAP_URLS_TO_COLLECT:
        return
    if url in visited or not is_same_site(url, site_domain):
        return  # child sitemaps must stay on the site being checked
    visited.add(url)
    parsed = parse_sitemap(_fetch_bytes(url))
    if parsed is None:
        return
    kind, locs = parsed
    for loc in locs:
        if len(collected) >= MAX_SITEMAP_URLS_TO_COLLECT:
            return
        if kind == "sitemapindex":
            _collect_sitemap(loc, site_domain, depth + 1, collected, visited)
        else:
            collected.append(loc)


def _discover_sitemap(site_root, robots_sitemaps, site_domain):
    """Tries each sitemap location in the spec'd order (robots.txt
    `Sitemap:` lines → /sitemap.xml → /sitemap_index.xml →
    /sitemap-index.xml → /wp-sitemap.xml) and stops at the first that
    yields page URLs. Follows sitemap indexes and reads gzipped sitemaps.
    Returns (page URLs, the sitemap URL they came from or None)."""
    for group in sitemap_candidates(site_root, robots_sitemaps):
        collected, visited = [], set()
        for url in group:
            _collect_sitemap(url, site_domain, 0, collected, visited)
        if collected:
            return collected, group[0]
    return [], None


def _probe_sitemap_url(url):
    """(status, redirect location) without following redirects, so a
    sitemap entry that redirects is seen as one. Anything that looks like an
    error gets a GET before it's believed (some servers refuse HEAD).
    (None, None) if the URL couldn't be tested at all."""
    try:
        resp = requests.head(url, allow_redirects=False, timeout=5, headers=BROWSER_HEADERS)
        status, location = resp.status_code, resp.headers.get("location")
        if status >= 400 and status != 401:
            get = requests.get(
                url, allow_redirects=False, timeout=5, headers=BROWSER_HEADERS, stream=True
            )
            try:
                status, location = get.status_code, get.headers.get("location")
            finally:
                get.close()
        return status, location
    except requests.RequestException:
        return None, None


def _probe_sitemap_urls(urls):
    """Tests up to SITEMAP_PROBE_LIMIT sitemap URLs in parallel. Returns
    (missing, redirecting, tested_count)."""
    urls = [u for u in urls if _is_safe_to_crawl(u)][:SITEMAP_PROBE_LIMIT]
    missing, redirecting = [], []
    if not urls:
        return missing, redirecting, 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=SITEMAP_PROBE_WORKERS) as ex:
        for url, (status, location) in zip(urls, ex.map(_probe_sitemap_url, urls)):
            if status in (404, 410):
                missing.append(url)
            elif status in (301, 302, 303, 307, 308):
                redirecting.append(url)
    return missing, redirecting, len(urls)


def _link_urls_in_scope(links, base_url, site_domain, only_nav=False):
    """Rendered links -> distinct, cleaned, same-site page URLs (fragments
    and tracking parameters removed, so hash routes and "?utm_source=..."
    variants collapse into the page they belong to)."""
    out, seen = [], set()
    for link in links:
        if only_nav and not link.get("inNav"):
            continue
        href = (link.get("href") or "").strip()
        if not href or href.lower().startswith(("mailto:", "tel:", "sms:", "javascript:")):
            continue
        absolute = clean_url(link.get("resolved") or urljoin(base_url, href))
        if urlparse(absolute).scheme not in ("http", "https"):
            continue
        if not is_same_site(absolute, site_domain) or looks_like_non_page(absolute):
            continue
        key = page_key(absolute)
        if key not in seen:
            seen.add(key)
            out.append(absolute)
    return out


def _examples_text(items, n=3):
    return ", ".join(items[:n]) + (f" (+{len(items) - n} more)" if len(items) > n else "")


def _summarize_time_cap(seconds):
    if seconds % 60 == 0:
        return f"{int(seconds // 60)}-minute"
    return f"{int(seconds)}-second"


def _problem_evidence_key(problem):
    """Identity of a problem for cross-page deduplication in a whole-site
    crawl: the same real thing (an image, a link, a failing resource, a
    script's own error text) reported on more than one page is one thing
    to fix, not one per page it happens to appear on. Checks that involve
    a concrete "thing" record its identity in an explicit `evidence`
    field (see e.g. Missing Alt Text, Broken Link, Failed Network
    Request, Third-Party Resource Failed). Every other category has no
    single identifying value to key on — a generic per-page count like
    "12 elements are hard to tap on a phone" isn't about one concrete
    thing — so it falls back to the category alone. That's still
    correct: it's the same underlying (usually template-wide) issue
    wherever it recurs, even though the exact count differs page to
    page."""
    return (problem["category"], problem.get("evidence"))


def dedupe_site_problems(pages):
    """Collapses `pages[i]["problems"]` across an entire crawl into one
    entry per distinct (category, evidence) pair (see
    _problem_evidence_key), each carrying every page it was found on.
    This is what makes a crawl report's headline number "how many
    distinct things are wrong with your site" instead of "how many times
    something wrong showed up on some page" — the fix for the wildly
    inflated per-page counts found testing cakesbody.com (382 "problems"
    on a 5-page site were really a couple dozen distinct issues, each
    counted once per page it happened to recur on — the same tracker
    failing on every page, the same missing alt text on the header logo,
    the same theme-wide font size, each multiplied by 5). Severity,
    message and confidence are taken from the first occurrence — this
    codebase already treats those as determined entirely by category
    (see regression_check.py's module docstring), so nothing is lost by
    not comparing later duplicates."""
    groups = {}
    order = []
    for page in pages:
        for problem in page["problems"]:
            key = _problem_evidence_key(problem)
            if key not in groups:
                groups[key] = {
                    "category": problem["category"],
                    "message": problem["message"],
                    "severity": problem["severity"],
                    "confidence": problem["confidence"],
                    "pages": [],
                }
                # Accessibility findings (Step 6): `topic` lets the report
                # pull them together, and `element_count` is summed across
                # pages so "N elements on M pages" is a whole-site total.
                if "topic" in problem:
                    groups[key]["topic"] = problem["topic"]
                # Security findings (Step 5): `group` is what the ownership
                # gate (checks_security.redact_security_details) keys on —
                # dropping it here would leak a deduplicated finding's
                # details into the public report.
                # `evidence` is the dedup identity itself (and what report.py
                # builds a finding's stable id from); `informational` keeps
                # a "this works" note out of the score (Step 8).
                for field in ("group", "who_fixes", "evidence", "informational"):
                    if field in problem:
                        groups[key][field] = problem[field]
                if "element_count" in problem:
                    groups[key]["element_count"] = 0
                order.append(key)
            if "element_count" in groups[key]:
                groups[key]["element_count"] += problem.get("element_count") or 0
            entry_pages = groups[key]["pages"]
            if page["url"] not in entry_pages:
                entry_pages.append(page["url"])
    return _rollup_third_party_failures([groups[key] for key in order])


THIRD_PARTY_ROLLUP_CATEGORY = "Third-Party Resource Failed"


def _rollup_third_party_failures(unique_problems):
    """A real site loads dozens of third-party trackers/pixels, and it's
    normal for several distinct ones to be broken or blocked at once (ad
    blockers, a cookie-consent gate, one app's own outage) — see
    CHECKS.md. Each is a real, already-deduplicated fact, but none of
    them are usually something the business needs to act on, and listing
    every failing tracker as its own "unique problem" buries the findings
    that ARE actionable under LOW-severity noise. This collapses them
    into one rollup finding, with the individual trackers kept as `items`
    (each still carrying its own `pages`) so the report can still show
    exactly which ones failed and where."""
    items = [p for p in unique_problems if p["category"] == THIRD_PARTY_ROLLUP_CATEGORY]
    if not items:
        return unique_problems
    kept = [p for p in unique_problems if p["category"] != THIRD_PARTY_ROLLUP_CATEGORY]
    kept.append({
        "category": "Third-Party Resources Didn't Load",
        "message": (
            f"{len(items)} third-party resource{'' if len(items) == 1 else 's'} didn't load — "
            "usually trackers or ad-blocked scripts, not something you need to fix."
        ),
        "severity": LOW,
        "confidence": NEEDS_LOOK,
        "items": [{"message": p["message"], "pages": p["pages"]} for p in items],
    })
    return kept


def summarize_site_check(result):
    """The plain-English summary line for a whole-site check result, e.g.
    "Checked 5 of 37 pages — 6 problems on 3 pages. Checking more pages
    is coming with Pro." The Pro note only appears when the site
    actually had more pages than got checked (product decision,
    2026-09-19 — see PLAN.md's pricing table: free checks
    DEFAULT_CRAWL_PAGE_CAP pages, Pro checks 10+) — a site with fewer
    pages than the cap has nothing to upsell. A crawl cut off by the time
    cap says so up front ("Partial report — N of M pages checked...") so it
    can never be mistaken for a complete one.

    The problem count is the number of UNIQUE problems (see
    dedupe_site_problems) — the same finding recurring on every page of
    the crawl counts once, not once per page."""
    unique_problems = result.get("unique_problems")
    if unique_problems is None:
        unique_problems = dedupe_site_problems(result["pages"])
    total_problems = len(unique_problems)
    pages_with_problems = sum(1 for p in result["pages"] if p["problems"])
    site_wide = len(result.get("site_findings") or [])
    if result.get("partial") and not result.get("pages_planned"):
        return (
            f"The check ran out of time (the {_summarize_time_cap(result.get('time_cap_seconds', 360))} "
            "limit) while it was still finding your site's pages, so no pages were checked. "
            "Please try again."
        )
    if result.get("partial"):
        planned = result.get("pages_planned", result["pages_checked"])
        reason = result.get("partial_reason")
        if reason == "pages_failed":
            # Every page was attempted, but some couldn't be opened (the
            # "(N couldn't be opened)" note below names how many).
            opened = sum(1 for p in result["pages"] if not p.get("could_not_load"))
            summary = f"Partial report — {opened} of {planned} pages could be opened and checked"
        elif reason == "worker_stopped":
            summary = (
                f"Partial report — {result['pages_checked']} of {planned} pages checked "
                "before the check stopped unexpectedly"
            )
        else:
            summary = (
                f"Partial report — {result['pages_checked']} of {planned} pages checked "
                f"before the {_summarize_time_cap(result.get('time_cap_seconds', 360))} time limit "
                f"ran out"
            )
    else:
        summary = f"Checked {result['pages_checked']} of {result['pages_found_total']} page(s)"
    summary += f" — {total_problems} problem(s) on {pages_with_problems} page(s)"
    if site_wide:
        summary += f", plus {site_wide} site-wide problem(s)"
    unopened = sum(1 for p in result["pages"] if p.get("could_not_load"))
    if unopened:
        summary += f" ({unopened} page(s) couldn't be opened at all — see below)"
    if result["pages_checked"] < result["pages_found_total"]:
        summary += ". Checking more pages is coming with Pro."
    return summary


# Pages a normal site — especially a Shopify store, which is what most of
# GetBuggy's early users run — deliberately keeps out of its sitemap:
# they're user/session-specific (cart, checkout, account, login/logout,
# the customer-auth handoff), a filtered or search view of content that's
# already indexed via its real pages (site search, the paginated
# catch-all /collections/all), or carry a query string at all (a sorted/
# filtered view of another page, not a distinct page of its own). Search
# engines aren't supposed to index these, so a menu link to one being
# absent from the sitemap is correct, not a problem — flagging it was
# the single biggest source of false "missing from sitemap" noise found
# testing cakesbody.com (see PROJECT_STATUS.md).
_SITEMAP_EXCLUDED_PATH_PREFIXES = (
    "/cart",
    "/checkout",
    "/account",
    "/customer_authentication/",
    "/search",
    "/collections/all",
)
# "signin"/"signout" added testing heavenmayhem.com (2026-09-26) — a real
# gap found on an earlier live report (lingcode.dev's /signin.html got
# flagged "missing from sitemap"), the exact false positive this whole
# list exists to prevent, just with a spelling this list didn't cover yet.
_SITEMAP_EXCLUDED_PATH_KEYWORDS = ("login", "logout", "signin", "signout")


def _expected_absent_from_sitemap(url):
    parsed = urlparse(url)
    if parsed.query:
        return True
    path = (parsed.path or "/").lower()
    if any(path.startswith(prefix) for prefix in _SITEMAP_EXCLUDED_PATH_PREFIXES):
        return True
    segments = path.strip("/").split("/")
    return any(seg in _SITEMAP_EXCLUDED_PATH_KEYWORDS for seg in segments)


# A distinct, narrower concept from the sitemap-exclusion list above: a
# page whose whole purpose is a transient, session-specific, or personal
# action (log in, view your cart, search) rather than content a visitor
# reads or a search engine ranks. SEO metadata (title/meta description/
# H1/noindex) and lead-generation form checks don't meaningfully apply to
# a page like this — a missing meta description on a cart page isn't a
# real SEO problem, and a login form isn't a lead the business is trying
# to capture. Deliberately excludes /collections/all and any URL with a
# query string, both of which the sitemap-exclusion list above treats as
# "expected absent from a sitemap" for entirely different reasons (a
# paginated/duplicate view, not a session/utility page) — a collection
# page or a filtered product view is still real, readable content that
# SEO metadata and form checks apply to normally. Same keyword list as
# above, since "login segment = session utility page" is true either way.
_UTILITY_PAGE_PATH_PREFIXES = tuple(
    p for p in _SITEMAP_EXCLUDED_PATH_PREFIXES if p != "/collections/all"
)


def _is_utility_page(url):
    path = (urlparse(url).path or "/").lower()
    if any(path.startswith(prefix) for prefix in _UTILITY_PAGE_PATH_PREFIXES):
        return True
    segments = path.strip("/").split("/")
    return any(seg in _SITEMAP_EXCLUDED_PATH_KEYWORDS for seg in segments)


def _site_findings(robots_info, sitemap_urls, sitemap_source, site_host, site_scheme):
    """Findings about the site as a whole (robots.txt, sitemap), plus notes
    about what couldn't be checked. Returns (findings, could_not_check).

    "Menu Pages Missing From Sitemap" is deliberately NOT computed here —
    see _menu_pages_missing_from_sitemap_finding, called once the crawl's
    pages are known."""
    findings, notes = [], []

    if robots_info["blocks_all_agents"] or robots_info["blocks_googlebot"]:
        who = "all search engines" if robots_info["blocks_all_agents"] else "Google"
        findings.append({
            "category": "Site Blocked From Search (robots.txt)",
            "message": (
                f"Your site's robots.txt file tells {who} to stay out of the entire site "
                "('Disallow: /'). Your pages won't show up in search results. If the site is "
                "still being built, that's fine — otherwise ask your web person to remove that "
                "line right away."
            ),
            "severity": HIGH,
            "confidence": VERIFIED,
        })

    if not sitemap_source:
        findings.append({
            "category": "No Sitemap Found",
            "message": (
                "We couldn't find a sitemap for your site (we looked where robots.txt points and "
                "at the usual addresses like /sitemap.xml). A sitemap is a list of your pages that "
                "helps Google find all of them, especially new ones. Most website builders can "
                "create one automatically. Who fixes it: your web person."
            ),
            "severity": LOW,
            "confidence": VERIFIED,
            "who_fixes": "your web person",
        })

    if sitemap_source:
        unique, seen = [], set()
        for u in sitemap_urls:
            if page_key(u) not in seen:
                seen.add(page_key(u))
                unique.append(u)

        other_host, insecure = classify_sitemap_urls(unique, site_host, site_scheme)
        if other_host:
            findings.append({
                "category": "Sitemap Lists URLs On Another Host",
                "message": (
                    f"Your sitemap lists {len(other_host)} address(es) on a different website "
                    f"({_examples_text(other_host)}). Search engines ignore or distrust those "
                    "entries, and it usually means the sitemap was set up for the wrong domain. "
                    "Ask your web person to fix the sitemap settings."
                ),
                "severity": MEDIUM,
                "confidence": VERIFIED,
            })
        if insecure:
            findings.append({
                "category": "Sitemap Lists Insecure URLs",
                "message": (
                    f"Your sitemap lists {len(insecure)} address(es) that start with http:// "
                    f"instead of https:// ({_examples_text(insecure)}). Your site is secure, so "
                    "those entries send visitors and Google through an extra redirect. Ask your "
                    "web person to update the sitemap to https:// addresses."
                ),
                "severity": MEDIUM,
                "confidence": VERIFIED,
            })

        on_site = [u for u in unique if u not in set(other_host)]
        missing, redirecting, tested = _probe_sitemap_urls(on_site)
        if len(on_site) > tested:
            notes.append(
                f"Your sitemap lists {len(on_site)} pages; we tested the first {tested} to see "
                "whether they load."
            )
        if missing:
            findings.append({
                "category": "Sitemap Lists Missing Pages",
                "message": (
                    f"{len(missing)} page(s) in your sitemap don't exist anymore — they give a "
                    f"'not found' error ({_examples_text(missing)}). Telling Google about pages "
                    "that aren't there wastes its attention on your site and hurts trust. Ask your "
                    "web person to remove them from the sitemap or bring the pages back."
                ),
                "severity": MEDIUM,
                "confidence": VERIFIED,
            })
        if redirecting:
            findings.append({
                "category": "Sitemap Lists Redirecting Pages",
                "message": (
                    f"{len(redirecting)} address(es) in your sitemap just redirect somewhere else "
                    f"({_examples_text(redirecting)}). A sitemap should list each page's final "
                    "address. Ask your web person to update the sitemap."
                ),
                "severity": MEDIUM,
                "confidence": VERIFIED,
            })

    return findings, notes


def _is_site_root(url):
    """True for the bare domain / "/" — the one URL a sitemap comparison
    should never call "missing," since a domain's root is discoverable by
    definition regardless of any sitemap (see
    _menu_pages_missing_from_sitemap_finding)."""
    return not (urlparse(url).path or "/").strip("/")


def _promote_heaviest_page_finding(pages):
    """"Heavy Page" is reported per page by _check_single_page (each
    carrying its own byte count as `evidence`, precisely so this
    function can compare them), but on a whole-site crawl a business
    doesn't need to be told the same thing once per heavy page — see
    PLAN.md, 2026-09-26: large images on a brand site are usually a
    deliberate choice, and a MEDIUM-per-page finding read as this tool
    not understanding that. This mutates `pages` in place, removing
    every per-page "Heavy Page" entry, and returns a single LOW
    site-wide finding naming only the heaviest one (or None if no page
    was heavy)."""
    heavy = [
        (page["url"], p)
        for page in pages
        for p in page["problems"]
        if p["category"] == "Heavy Page"
    ]
    if not heavy:
        return None
    for page in pages:
        page["problems"] = [p for p in page["problems"] if p["category"] != "Heavy Page"]
    heaviest_url, heaviest = max(heavy, key=lambda item: float(item[1]["evidence"]))
    mb = float(heaviest["evidence"]) / (1024 * 1024)
    return {
        "category": "Heavy Page",
        "message": (
            f"Your heaviest page ({heaviest_url}) downloads about {mb:.1f}MB to load — more "
            "than the roughly 3MB guideline, which can mean slow loads for visitors on mobile "
            "data or a weak connection. Large images on a brand site are often a deliberate "
            "choice, so this is worth a look rather than an assumed bug."
        ),
        "severity": LOW,
        "confidence": VERIFIED,
    }


def _menu_pages_missing_from_sitemap_finding(sitemap_urls, sitemap_source, nav_urls, pages):
    """The "Menu Pages Missing From Sitemap" finding — deliberately
    computed separately from _site_findings (which runs before any page
    is checked) rather than inline there, specifically so it can be
    checked against `pages` once the crawl is done. Two things found
    testing housejanolo.com (a Squarespace store), neither a www/apex/
    trailing-slash issue (`page_key` already handles those correctly —
    that theory didn't hold up under investigation):

    1. Never flags the site root ("/"). Squarespace (like other
       platforms) often lists the homepage's actual content in the
       sitemap under an internal page slug (e.g. `/home`) rather than at
       "/" itself — a real path difference `page_key`'s host/scheme/
       trailing-slash normalization was never meant to reconcile, not a
       bug in it. But the fix isn't teaching it Squarespace's specific
       alias scheme (fragile, platform-specific, and still wrong for the
       next platform's own alias) — it's recognizing the root doesn't
       need this finding at all: a domain's homepage is trivially
       discoverable regardless of whether any sitemap lists it.
    2. Never flags a URL that's already reported as a broken link
       somewhere in this crawl. Telling a business "add this page to
       your sitemap" about a page that doesn't even work is confusing,
       redundant noise on top of the real, actionable finding (the
       broken link itself).
    """
    if not sitemap_source:
        return None
    unique, seen = [], set()
    for u in sitemap_urls:
        if page_key(u) not in seen:
            seen.add(page_key(u))
            unique.append(u)
    sitemap_keys = {page_key(u) for u in unique}

    broken_keys = {
        page_key(p["evidence"])
        for page in pages
        for p in page["problems"]
        if p["category"] in ("Broken Link", "Broken Social Link") and p.get("evidence")
    }

    missing_nav = [
        u for u in nav_urls
        if page_key(u) not in sitemap_keys
        and not _expected_absent_from_sitemap(u)
        and not _is_site_root(u)
        and page_key(u) not in broken_keys
    ]
    if not missing_nav:
        return None
    return {
        "category": "Menu Pages Missing From Sitemap",
        "message": (
            f"{len(missing_nav)} page(s) linked from your main menu aren't in your "
            f"sitemap ({_examples_text(missing_nav)}). Search engines may be slower to "
            "find them. Ask your web person to add them to the sitemap."
        ),
        "severity": LOW,
        "confidence": VERIFIED,
    }


def _probe_soft_404(browser, site_root, timeout_ms):
    """Loads an address that cannot exist and, if the site answers it with
    a normal 200 page instead of an error, returns that page's fingerprint
    so real pages that merely *look* like it can be flagged. None if the
    site correctly returns an error status (nothing to detect) or the probe
    couldn't run."""
    import uuid

    url = urljoin(site_root, f"/getbuggy-missing-{uuid.uuid4().hex[:10]}")
    page = browser.new_page()
    try:
        resp = page.goto(url, wait_until="load", timeout=timeout_ms)
        if resp is None or resp.status >= 400:
            return None
        try:
            page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            pass
        return make_fingerprint(page.title(), page.inner_text("body"), url)
    except Exception:
        return None
    finally:
        page.close()


def run_site_check(
    target,
    page_cap=DEFAULT_CRAWL_PAGE_CAP,
    timeout_ms=60000,
    on_progress=None,
    on_meta=None,
    on_page=None,
    jurisdiction=DEFAULT_JURISDICTION,
):
    """Crawls a whole site rather than just one page. Discovery: the
    homepage is loaded once in a real browser (its rendered menu links
    are the "primary nav"), robots.txt and the sitemap (robots.txt
    `Sitemap:` → /sitemap.xml → /sitemap_index.xml → /sitemap-index.xml →
    /wp-sitemap.xml; indexes and gzip supported) are read, and links are
    filtered to the same site (www = apex), stripped of fragments and
    tracking parameters, and through robots.txt and the same public-address
    safety check the submitted URL gets. Selection under `page_cap`:
    homepage → primary-nav pages → contact/pricing/book/order/shop pages →
    sitemap order. Every selected page then gets the full per-page check
    pass, up to CRAWL_CONCURRENCY pages at a time.

    Callbacks, all optional, all called from this thread only:
      on_progress(completed, total)   each time a page finishes
      on_meta(meta)                   once, after discovery, before any page
                                      is checked: what was found/selected
      on_page(index, page_result)     each finished page, as soon as it's done
    They exist so a caller that has to kill this crawl mid-run (the server's
    6-minute cap) still holds everything gathered up to that point.

    Returns:
        {
            "pages_found_total": int,   # distinct in-scope pages found
            "pages_planned": int,       # how many were selected (<= page_cap)
            "pages_checked": int,       # how many finished
            "used_sitemap": bool,
            "sitemap_source": str|None,
            "pages": [{"url", "problems", "could_not_check"}, ...],  # priority order
            "pages_skipped": [url, ...],        # found but over the cap
            "site_findings": [...],             # robots.txt / sitemap findings
            "site_could_not_check": [str, ...],
            "partial": False,
        }

    Local file targets (used by the CLI/tests) aren't "sites" with a
    sitemap or robots.txt, so they're just checked as a single page, same
    as run_check().

    `jurisdiction` (`us` default, `eu_uk`, `both`) picks which cookie and
    consent findings show and how they're worded (Step 7, checks_cookies.py).
    """
    jurisdiction = normalize_jurisdiction(jurisdiction)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            if is_local_target(target):
                local_problems, local_notes = _check_single_page(browser, target, timeout_ms)
                page_result = {
                    "url": target,
                    "problems": local_problems,
                    "could_not_check": local_notes,
                }
                if on_progress:
                    on_progress(1, 1)
                local_unique = dedupe_site_problems([page_result])
                return {
                    "pages_found_total": 1,
                    "pages_planned": 1,
                    "pages_checked": 1,
                    "used_sitemap": False,
                    "sitemap_source": None,
                    "pages": [page_result],
                    "pages_skipped": [],
                    "site_findings": [],
                    "site_could_not_check": [],
                    "unique_problems": local_unique,
                    "accessibility": accessibility_summary(local_unique),
                    "jurisdiction": jurisdiction,
                    "cookies": None,
                    "partial": False,
                }

            site_findings, site_notes = [], []

            # Resolve redirects up front (e.g. medvi.org -> home.medvi.org)
            # so sitemap.xml/robots.txt get looked up on the host the site
            # actually lives on, not wherever the submitted URL happened to
            # point. Capped at 5 hops; a longer chain is reported.
            homepage_url = target
            try:
                with requests.Session() as s:
                    s.max_redirects = 5
                    resp = s.head(
                        target, allow_redirects=True, timeout=10, headers=CRAWLER_HEADERS
                    )
                    homepage_url = resp.url
            except requests.TooManyRedirects:
                site_findings.append({
                    "category": "Too Many Redirects",
                    "message": (
                        f"Opening {target} sends visitors through more than 5 redirects in a row. "
                        "Browsers and search engines may give up before reaching your site. Ask "
                        "your web person or host to point the address straight at the final page."
                    ),
                    "severity": MEDIUM,
                    "confidence": NEEDS_LOOK,
                })
            except requests.RequestException:
                pass

            parsed_home = urlparse(homepage_url)
            site_root = f"{parsed_home.scheme}://{parsed_home.netloc}/"
            site_domain = registrable_domain(parsed_home.hostname)

            robots_parser, robots_info = _fetch_robots(site_root)

            sitemap_urls, sitemap_source = [], None
            if _is_safe_to_crawl(site_root):
                sitemap_urls, sitemap_source = _discover_sitemap(
                    site_root, robots_info["sitemaps"], site_domain
                )
            used_sitemap = bool(sitemap_urls)

            # The homepage, loaded once for real: its rendered menu is the
            # "primary nav" used to choose pages, and — with no sitemap —
            # its links are the whole candidate list.
            nav_urls, body_urls = [], []
            # None = the homepage's links couldn't be read, so "no
            # accessibility statement" can't be judged (see below).
            homepage_links = None
            homepage_page = browser.new_page()
            try:
                homepage_page.goto(homepage_url, wait_until="load", timeout=timeout_ms)
                data = extract_rendered_links(homepage_page)
                homepage_links = data["links"]
                base = homepage_page.url
                nav_urls = _link_urls_in_scope(data["links"], base, site_domain, only_nav=True)
                body_urls = _link_urls_in_scope(data["links"], base, site_domain)
            except Exception as e:
                site_notes.append(
                    f"Couldn't read the homepage's menu ({e.__class__.__name__}), so pages were "
                    "chosen from the sitemap alone."
                )
            finally:
                homepage_page.close()

            in_scope = lambda u: (  # noqa: E731
                is_same_site(u, site_domain)
                and not looks_like_non_page(u)
                and _is_safe_to_crawl(u)
                and robots_parser.can_fetch(CRAWLER_USER_AGENT, u)
            )
            sitemap_pages = [clean_url(u) for u in sitemap_urls if in_scope(u)]
            nav_pages = [u for u in nav_urls if in_scope(u)]
            other_pages = [] if used_sitemap else [u for u in body_urls if in_scope(u)]

            selected, skipped, pages_found_total = select_pages(
                homepage_url, nav_pages, sitemap_pages, other_pages, page_cap
            )

            more_findings, more_notes = _site_findings(
                robots_info, sitemap_urls, sitemap_source,
                parsed_home.hostname, parsed_home.scheme,
            )
            site_findings += more_findings
            site_notes += more_notes

            # Step 5: endpoints, transport, headers, platform — GETs to a
            # fixed list of paths on the submitted site only, all behind
            # the SSRF guard (see checks_security.py).
            security = run_site_security_pass(
                homepage_url,
                _is_safe_to_crawl,
                CRAWLER_HEADERS,
                robots_status=robots_info.get("http_status"),
            )
            site_findings += security["findings"]
            site_notes += security["notes"]
            platform = security["platform"]

            # Step 6: an accessibility statement linked from the homepage
            # (footer links count) or listed in the sitemap.
            if homepage_links is None:
                site_notes.append(
                    "Couldn't look for an accessibility statement, because the homepage's links "
                    "couldn't be read."
                )
            elif not has_accessibility_statement(homepage_links, sitemap_urls):
                site_findings.append(missing_statement_finding())

            # Step 7: cookies, consent banner and privacy policy — a fresh
            # visit to the homepage, nothing clicked (checks_cookies.py).
            cookie_pass = run_site_cookie_pass(
                browser,
                homepage_url,
                site_domain,
                _is_safe_to_crawl,
                jurisdiction=jurisdiction,
                sitemap_urls=sitemap_urls,
                site_is_https=parsed_home.scheme == "https",
                platform=platform,
                timeout_ms=timeout_ms,
            )
            site_findings += cookie_pass["findings"]
            site_notes += cookie_pass["notes"]

            meta = {
                "pages_found_total": pages_found_total,
                "pages_planned": len(selected),
                "selected": selected,
                "pages_skipped": skipped,
                "used_sitemap": used_sitemap,
                "sitemap_source": sitemap_source,
                "site_findings": site_findings,
                "site_could_not_check": site_notes,
                "platform": platform,
                "jurisdiction": jurisdiction,
                "cookies": cookie_pass["summary"],
            }
            if on_meta:
                on_meta(meta)

            # One calibration measurement for the whole crawl (not one per
            # page — that would just add an extra page load to every
            # single page) using the outer browser, which by this point is
            # done with discovery and otherwise idle: the concurrent
            # per-page phase below launches its own browser per page (see
            # _check_page_standalone) rather than reusing this one.
            baseline_ms = _measure_reference_baseline(browser, timeout_ms)
            soft_404_fp = _probe_soft_404(browser, site_root, timeout_ms)

            link_cache = LinkCache()
            # Step 6: decides, crawl-wide, whether each page still gets the
            # axe scan (see checks_accessibility.A11yScanBudget).
            a11y_budget = A11yScanBudget()
            pages = [None] * len(selected)
            page_extras = [{} for _ in selected]
            completed = 0
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=CRAWL_CONCURRENCY
            ) as executor:
                future_to_index = {
                    executor.submit(
                        _check_page_standalone,
                        page_url,
                        timeout_ms,
                        baseline_ms,
                        is_homepage=(i == 0),
                        link_cache=link_cache,
                        soft_404_fp=soft_404_fp,
                        site_domain=site_domain,
                        site_is_https=parsed_home.scheme == "https",
                        skip_favicon=security["favicon_ico_ok"],
                        extras=page_extras[i],
                        a11y_budget=a11y_budget,
                    ): i
                    for i, page_url in enumerate(selected)
                }
                for future in concurrent.futures.as_completed(future_to_index):
                    i = future_to_index[future]
                    failed_to_load = False
                    try:
                        page_problems, page_could_not_check = future.result()
                    except Exception as e:
                        failed_to_load = True
                        page_problems, page_could_not_check = [], [
                            f"Could not check {selected[i]} at all "
                            f"({e.__class__.__name__}) — it may be down, "
                            "blocking automated checks, or too slow to respond."
                        ]
                    pages[i] = {
                        "url": selected[i],
                        "problems": page_problems,
                        "could_not_check": page_could_not_check,
                    }
                    if failed_to_load:
                        pages[i]["could_not_load"] = True
                    if page_extras[i].get("third_party_scripts"):
                        pages[i]["third_party_scripts"] = page_extras[i]["third_party_scripts"]
                    completed += 1
                    if on_page:
                        on_page(i, pages[i])
                    if on_progress:
                        on_progress(completed, len(selected))

            # Computed here, not inside _site_findings above (which runs
            # before any page is checked) — needs `pages` to exclude a
            # nav link that's already reported as a broken link elsewhere
            # in this crawl. See _menu_pages_missing_from_sitemap_finding.
            missing_from_sitemap = _menu_pages_missing_from_sitemap_finding(
                sitemap_urls, sitemap_source, nav_urls, pages
            )
            if missing_from_sitemap:
                site_findings = site_findings + [missing_from_sitemap]

            heaviest_page_finding = _promote_heaviest_page_finding(pages)
            if heaviest_page_finding:
                site_findings = site_findings + [heaviest_page_finding]

            a11y_note = site_skipped_scan_note(a11y_budget)
            if a11y_note:
                site_notes = site_notes + [a11y_note]
            # The cookie list covers every page checked, not just the
            # homepage: each page's own on-load snapshot is merged in.
            cookie_summary = merge_page_snapshots(
                cookie_pass["summary"],
                [e.get("cookie_snapshot") for i, e in enumerate(page_extras) if i != 0],
            )
            unique_problems = dedupe_site_problems(pages)

            return {
                "pages_found_total": pages_found_total,
                "pages_planned": len(selected),
                "pages_checked": len(selected),
                "used_sitemap": used_sitemap,
                "sitemap_source": sitemap_source,
                "pages": pages,
                "pages_skipped": skipped,
                "site_findings": site_findings,
                "site_could_not_check": site_notes,
                "unique_problems": unique_problems,
                "accessibility": accessibility_summary(unique_problems, site_findings),
                "platform": platform,
                "jurisdiction": jurisdiction,
                "cookies": cookie_summary,
                # Ownership-gated: server.py strips this from public
                # responses (checks_security.redact_security_details).
                "security_details": {
                    "probes": security["probes"],
                    "third_party_scripts": sorted({
                        h for p in pages for h in p.get("third_party_scripts", [])
                    }),
                },
                "partial": False,
            }
        finally:
            browser.close()


REDIRECT_CHAIN_MIN_HOPS = 3
REDIRECT_CHAIN_MAX_HOPS = 5


def _check_redirect_chain(response, problems):
    """LOW finding when reaching this page took 3+ redirects. Measured
    after the fact from the browser's own redirect record (Chromium follows
    up to 20 hops; we can't lower that, so a chain longer than 5 is
    reported as such rather than cut off)."""
    try:
        hops, req = 0, response.request if response is not None else None
        while req is not None and req.redirected_from is not None:
            hops += 1
            req = req.redirected_from
    except Exception:
        return
    if hops >= REDIRECT_CHAIN_MIN_HOPS:
        extra = (
            f" That's more than the {REDIRECT_CHAIN_MAX_HOPS} hops most browsers and search "
            "engines will follow." if hops > REDIRECT_CHAIN_MAX_HOPS else ""
        )
        problems.append({
            "category": "Redirect Chain",
            "message": (
                f"Reaching this page takes {hops} redirects in a row (each one bounces the visitor "
                f"to another address before the page loads).{extra} Every hop slows the page down "
                "a little. Ask your web person to make the first address point straight to the "
                "final page."
            ),
            "severity": LOW,
            "confidence": VERIFIED,
        })


def _check_soft_404(page, response, soft_404_fp, is_homepage, problems):
    """Flags a page that answers 'OK' but reads like the site's own 'page
    not found' page — visitors see an error, but Google is told all is
    well. Compares against the fingerprint of an address that cannot
    exist (see _probe_soft_404). Never applied to the homepage."""
    if soft_404_fp is None or is_homepage or response is None or response.status >= 400:
        return
    try:
        fp = make_fingerprint(page.title(), page.inner_text("body"), page.url)
    except Exception:
        return
    is_match, exact = matches_soft_404(fp, soft_404_fp)
    if is_match:
        problems.append({
            "category": "Soft 404 Page",
            "message": (
                "This page loads normally as far as the browser is concerned, but what visitors "
                "read on it is the same as your site's 'page not found' message. Google is being "
                "told the page is fine, so it may keep listing an empty page. Ask your web person "
                "to make missing pages return a proper 'not found' error, or bring the real "
                "content back."
            ),
            "severity": MEDIUM,
            "confidence": VERIFIED if exact else NEEDS_LOOK,
        })


# A JS error's origin can't be read off Playwright's Error object
# directly — the closest thing is a URL somewhere in its stack trace (or,
# failing that, its message, which sometimes embeds one, e.g. a failed
# dynamic import). Matches file:// as well as http(s):// so this also
# works for the local-file targets the CLI/regression harness check
# (which have no real domain at all — see _classify_js_errors). If no URL
# shows up anywhere, there's no way to tell whose script threw it.
_JS_ERROR_ORIGIN_RE = re.compile(r'\w+://[^\s()\'"]+')

# A raw JS error only becomes a "your site is broken" HIGH finding when
# BOTH of these are true; otherwise it's real, but not proven to be
# something the site owner needs to fix (see _classify_js_errors).
_JS_VISIBLE_BREAK_CATEGORIES = {
    "Broken Form",
    "Failed Network Request",
    "Mobile Horizontal Scroll",
}


def _classify_js_errors(js_error_candidates, console_error_candidates, problems, target_base_domain):
    """Turns raw `pageerror` exceptions and `console.error()` messages into
    findings. Neither is, by itself, evidence the *page* is broken — most
    of what trips this on a real site is a third-party app/tracker
    misbehaving on its own, invisibly to the visitor, or (for console
    messages especially) code logging an error deliberately: a CSP
    violation report, a feature-detection warning, a widget's own
    diagnostic message. A console.error() is a weaker signal than an
    uncaught exception for exactly this reason (code chooses to log an
    error; it doesn't choose to throw an uncaught one), but both are
    judged the same way here. It's only a HIGH finding — "JavaScript
    Crash" for an exception, "JavaScript Console Error" for a logged
    one — when BOTH:
      1. it came from a first-party script (same domain as the page), AND
      2. something visibly broke on this same page load (a form, a
         same-site resource, or the layout — see
         _JS_VISIBLE_BREAK_CATEGORIES). This deliberately does NOT look at
         `could_not_check` as a "something failed to render" proxy, even
         though a couple of check functions do put a real "this whole
         check couldn't complete" note there — a modern single-page app
         can rack up a couldn't-check note on nearly every page just from
         normal operation (Next.js prefetch requests aborting when the
         check moves on — see Step 5.1's ERR_ABORTED handling), which
         made `bool(could_not_check)` true almost everywhere and defeated
         the whole point of requiring a *visible* break. Confirmed on a
         real report: play.lingcode.dev's CSP-violation console message
         (blocking its own Cloudflare Insights beacon — genuinely no
         visible breakage) still came out HIGH under the old
         `bool(could_not_check)` check, purely because *unrelated*
         ERR_ABORTED prefetch requests on the same page had already
         populated `could_not_check`.
    That correlation is a heuristic, not a proof the error and the
    breakage are the same bug — this check can observe that both
    happened on the same page load, not prove causation between them. A
    third-party-origin signal goes into the same "Third-Party Resource
    Failed" bucket the rest of third-party noise collapses into (deduped
    by its text as evidence). Everything else — first-party with no
    confirmed breakage, or a signal with no determinable origin at all —
    is real but unproven, so it's a LOW needs_look "Script Error," not a
    "Crash" or a HIGH console error. Confirmed worth doing on two real
    reports the same day this was written: the CSP violation above, and a
    garbled console message from a bot-protection challenge page on
    blaze.ai — both previously unconditional HIGH "JavaScript Console
    Error" findings.
    """
    if not js_error_candidates and not console_error_candidates:
        return

    visible_break = any(
        p["category"] in _JS_VISIBLE_BREAK_CATEGORIES for p in problems
    )

    def classify(text, origin_domain, crash_category):
        is_first_party = origin_domain is not None and origin_domain == target_base_domain
        is_third_party = origin_domain is not None and origin_domain != target_base_domain

        if is_first_party and visible_break:
            problems.append({
                "category": crash_category,
                "message": (
                    f"{text} — this error is from your own site's code, and something on this "
                    "page (a form, a link, or the layout) also failed to work right."
                ),
                "severity": HIGH,
                "confidence": VERIFIED,
                "evidence": text,
            })
        elif is_third_party:
            problems.append({
                "category": "Third-Party Resource Failed",
                "message": (
                    f"A third-party script reported an error ({text}) — likely an app or "
                    "tracker, not something you need to fix."
                ),
                "severity": LOW,
                "confidence": NEEDS_LOOK,
                "evidence": text,
            })
        else:
            problems.append({
                "category": "Script Error",
                "message": (
                    f"A script on this page reported an error ({text}) — it may be an app or "
                    "tracker, not something you need to fix."
                ),
                "severity": LOW,
                "confidence": NEEDS_LOOK,
                "evidence": text,
            })

    for exc in js_error_candidates:
        text = str(exc)
        haystack = (getattr(exc, "stack", None) or "") + "\n" + text
        match = _JS_ERROR_ORIGIN_RE.search(haystack)
        origin_domain = get_base_domain(urlparse(match.group(0)).hostname) if match else None
        classify(text, origin_domain, "JavaScript Crash")

    for msg in console_error_candidates:
        text = msg.text
        # Unlike a raw exception's stack trace, a console message's
        # origin is a direct field — no regex-guessing needed. A
        # browser-generated message (a CSP violation report, for one)
        # isn't tied to any script and can leave this empty; that's the
        # same "no determinable origin" case an exception can also land
        # in, handled the same way (see `classify`).
        try:
            location_url = (msg.location or {}).get("url") or None
        except Exception:
            location_url = None
        origin_domain = get_base_domain(urlparse(location_url).hostname) if location_url else None
        classify(text, origin_domain, "JavaScript Console Error")


def _check_single_page(
    browser,
    target,
    timeout_ms=60000,
    baseline_ms=None,
    is_homepage=None,
    link_cache=None,
    soft_404_fp=None,
    site_domain=None,
    site_is_https=None,
    skip_favicon=False,
    extras=None,
    a11y_budget=None,
):
    """Runs every check against one page and returns its problem list.
    Takes an already-launched `browser` (rather than launching its own)
    so a multi-page crawl can reuse one browser across many pages instead
    of paying Chromium's startup cost per page. `run_check()` below is the
    single-page entry point used by the CLI and regression tests; it just
    launches a browser and delegates here.

    `baseline_ms`, if given (see _measure_reference_baseline), is how long
    a known-fast reference page took to load from here just now — used to
    judge this page's render time *relative to current conditions* instead
    of against a fixed number that conflates the site's speed with the
    checker's own hosting.

    Crawl context (all optional; a lone run_check() gets sensible
    defaults): `is_homepage` decides how severe a 'noindex' is (defaults to
    "the URL's path is /"); `link_cache` is the crawl-wide LinkCache shared
    across pages; `soft_404_fp` is the site's "page that can't exist"
    fingerprint (see _probe_soft_404); `site_domain` is the registrable
    domain that counts as "internal" for links. `site_is_https`,
    `skip_favicon` and `extras` come from the crawl's site-level security
    pass (see checks_security.py); `extras` is filled with this page's
    third-party script hosts. `a11y_budget` is the crawl's
    checks_accessibility.A11yScanBudget (None = always run the axe scan)."""
    problems = []
    # Things this check genuinely couldn't observe at all — an auth-gated
    # page, a link that blocks automated checks even after a second
    # attempt, a request that timed out, an expensive check that couldn't
    # finish in time — as distinct from a `problems` entry, which is
    # always something the check *did* observe (even if, for a
    # `needs_look`-confidence one, ambiguously). Plain strings are enough
    # here; nothing downstream needs to group or count these by category.
    could_not_check = []
    url = to_playwright_url(target)
    target_base_domain = get_base_domain(urlparse(url).hostname)
    if is_homepage is None:
        is_homepage = not is_local_target(target) and (urlparse(url).path or "/") == "/"

    page = browser.new_page()
    try:
        # The browser automatically logs a console error every time a
        # network request fails (e.g. "Failed to load resource: net::ERR_...").
        # That's just an echo of the same failure the response/requestfailed
        # listeners below already record, not an independent JS problem, so
        # it's filtered out here to avoid reporting one failure twice.
        def is_resource_load_echo(text):
            return text.startswith("Failed to load resource:")

        # Failed requests are deduplicated by URL because a single broken
        # resource can be reported by both "response" (HTTP error status)
        # and "requestfailed" (network-level failure) depending on how it
        # failed — without this, one broken resource becomes two problems.
        reported_failed_urls = set()

        # Populated by check_forms when it deliberately aborts a form's
        # background submission request for safety — that's an intentional
        # block, not a real broken-resource bug, so it shouldn't show up
        # in the report as a "Failed Network Request."
        deliberately_blocked_urls = set()

        def record_failed_request(req_url, message, status=None, failure_text=None):
            if req_url in reported_failed_urls or req_url in deliberately_blocked_urls:
                return
            reported_failed_urls.add(req_url)

            # A 401 almost always means "this needs a login," not "this is
            # broken" — we have no way to tell those apart without
            # credentials, so this is a "couldn't check" case, not a
            # (mis-)verified problem (see PROJECT_STATUS.md Known Issues).
            if status == 401:
                could_not_check.append(
                    f"{req_url} — looks like it requires a login (HTTP 401), "
                    "so we can't tell whether it's actually broken."
                )
                return

            # A 403/406/429 often means a WAF or bot-protection service
            # blocked THIS SPECIFIC AUTOMATED CHECK, not that the page or
            # resource is actually broken for a real visitor — the exact
            # standing rule in CLAUDE.md ("never evade a bot block —
            # report 'this site blocks automated checks' instead").
            # checks_links.py's own link-checking path already treats
            # these statuses this way, escalating to a real-browser
            # recheck before giving up; there's no equivalent second
            # opinion to try here, since this failure already came from a
            # full Playwright browser load/request — the "more real"
            # recheck link-checking falls back to IS this check. Confirmed
            # on a real report: blaze.ai's own "Log In" page returned 403
            # here (almost certainly bot protection on their app
            # subdomain, not a broken login page).
            if status in BOT_BLOCK_STATUSES:
                could_not_check.append(
                    f"{req_url} — returned HTTP {status}, which often means bot "
                    "protection blocked this automated check specifically, not that "
                    "it's actually broken for real visitors. Worth opening it "
                    "yourself to confirm."
                )
                return

            # ERR_ABORTED very often just means the resource (typically a
            # large video or image) was STILL DOWNLOADING when the check
            # moved on and closed the page — not a genuine failure. This
            # used to be reported anyway (just at `needs_look` confidence),
            # which still read as a confirmed HIGH "failed to load" to a
            # non-technical reader — confirmed wrong on a real report: a
            # promotion video that plays fine for a visitor was flagged
            # this way, simply because it was a multi-second video still
            # streaming in when the per-page check finished and closed the
            # browser. ERR_NETWORK_CHANGED and ERR_INTERNET_DISCONNECTED
            # are Chromium reporting that THIS machine's own network
            # connection dropped or changed mid-request — nothing to do
            # with the site being checked (seen firsthand testing
            # cakesbody.com: a real local network blip mid-crawl briefly
            # failed a dozen otherwise-fine product images). None of the
            # three are evidence the resource is actually broken — an
            # unconfirmed signal like this belongs in "couldn't check,"
            # the same place a 401 goes above, not reported as a finding
            # at all (see Known Issues).
            AMBIGUOUS_FAILURES = ("ERR_ABORTED", "ERR_NETWORK_CHANGED", "ERR_INTERNET_DISCONNECTED")
            if failure_text and any(code in failure_text for code in AMBIGUOUS_FAILURES):
                could_not_check.append(
                    f"{req_url} — the connection was interrupted while this was loading "
                    f"({failure_text}). This often just means a large file (a video or image) "
                    "was still downloading when the check finished, or a brief network hiccup — "
                    "not necessarily that it's actually broken. Worth opening it yourself to "
                    "double-check."
                )
                return

            # Real sites load dozens of third-party trackers/pixels
            # (analytics, ads, chat widgets) that fail constantly for
            # reasons outside the site owner's control. Those are flagged
            # separately at low severity so genuine first-party problems
            # aren't buried in the noise.
            parsed_req = urlparse(req_url)
            same_site = get_base_domain(parsed_req.hostname) == target_base_domain
            if same_site:
                # A first-party endpoint is worth naming individually (the
                # cart API failing is a different bug from checkout
                # failing) — but the query string is dropped, since a
                # cache-busting/session token there would otherwise make
                # every single hit on the same endpoint look like a
                # different "thing" and defeat cross-page deduplication.
                evidence = f"{parsed_req.scheme}://{parsed_req.netloc}{parsed_req.path}"
            else:
                # A third-party tracker/pixel is "the same thing" at the
                # tracker level, not the exact endpoint: most trackers
                # (Pinterest, Klaviyo, TikTok...) fire a fresh pixel URL
                # with a random trace/session id on every single page load,
                # so keying on anything more specific than the domain would
                # make "the same tracker failing on every page" look like a
                # different problem every time.
                evidence = get_base_domain(parsed_req.hostname)
            problems.append(
                {
                    "category": "Failed Network Request"
                    if same_site
                    else "Third-Party Resource Failed",
                    "message": message,
                    "severity": HIGH if same_site else LOW,
                    # Every ambiguous failure signal (401, ERR_ABORTED, and
                    # the local-network codes above) returns early into
                    # could_not_check instead of reaching here — what's
                    # left is always a real HTTP error status or a genuine
                    # network-level failure, so this is always `verified`.
                    "confidence": VERIFIED,
                    # See dedupe_site_problems — this is what lets the same
                    # broken endpoint/tracker recurring across a crawl (or
                    # firing several times on one page with a different
                    # random query string each time) count once.
                    "evidence": evidence,
                }
            )

        # Listeners must be attached BEFORE navigating, or we miss events
        # that fire during the initial page load.
        #
        # Both console.error() calls and raw uncaught exceptions are
        # collected here rather than appended to `problems` directly,
        # because whether either deserves to be a HIGH finding can't be
        # decided the instant it fires — see _classify_js_errors below,
        # run once at the end of this page's checks when the rest of
        # `problems` (forms, links, mobile layout) is known. A
        # console.error() is a much weaker signal than an uncaught
        # exception (code often logs an error deliberately — a CSP
        # violation report, a feature-detection warning, a third-party
        # widget's own diagnostic message — not evidence the page is
        # actually broken), which is exactly why this used to be an
        # unconditional HIGH "JavaScript Console Error" and produced false
        # alarms on two different real reports the same day this was
        # written (a CSP violation blocking a third-party analytics
        # script; a garbled console message from a bot-protection
        # challenge page). `msg.location()["url"]` — the file the
        # console call actually happened in — is a direct signal of
        # origin, unlike a raw exception's stack trace, which has to be
        # regex-matched (see _JS_ERROR_ORIGIN_RE below).
        console_error_candidates = []
        page.on(
            "console",
            lambda msg: console_error_candidates.append(msg)
            if msg.type == "error" and not is_resource_load_echo(msg.text)
            else None,
        )

        js_error_candidates = []
        page.on("pageerror", lambda exc: js_error_candidates.append(exc))

        page.on(
            "response",
            lambda resp: record_failed_request(
                resp.url, f"{resp.url} returned HTTP {resp.status}", status=resp.status
            )
            if resp.status >= 400
            else None,
        )

        page.on(
            "requestfailed",
            lambda req: record_failed_request(
                req.url,
                f"{req.url} failed to load ({req.failure})",
                failure_text=str(req.failure),
            ),
        )

        # Every response the page makes, kept separately from the failure
        # tracking above — the form check needs to see successful responses
        # too, to tell whether a form submission actually went anywhere.
        all_responses = []
        page.on(
            "response",
            lambda resp: all_responses.append((resp.request.method, resp.status)),
        )

        # Script responses, read in place by check_page_security (secrets,
        # library versions, source maps) — no second download.
        script_responses = []
        page.on(
            "response",
            lambda resp: script_responses.append(resp)
            if resp.request.resource_type == "script"
            else None,
        )

        # Speed signals that reflect the *site*, not wherever this checker
        # happens to be hosted: how much data it takes to download the
        # page, how many separate requests that takes, whether any single
        # image is unusually large, and how long the server itself took to
        # send back the first byte (server/hosting speed, not our
        # rendering speed). Unlike a raw "time to load" measurement, none
        # of these depend on how fast our own Chromium instance is.
        request_count = [0]
        page_weight_bytes = [0]
        oversized_images = []
        ttfb_ms = [None]

        # Every request URL, for the cookie list's "companies contacted"
        # (Step 7) — see the snapshot taken before the link checks below.
        request_urls = []

        def track_request(req):
            request_count[0] += 1
            if len(request_urls) < 2000:
                request_urls.append(req.url)

        page.on("request", track_request)

        def track_response_weight(resp):
            try:
                content_length = resp.headers.get("content-length")
                size = int(content_length) if content_length else 0
            except Exception:
                size = 0
            page_weight_bytes[0] += size

            try:
                resource_type = resp.request.resource_type
            except Exception:
                resource_type = None

            if resource_type == "image" and size > OVERSIZED_IMAGE_BYTES:
                oversized_images.append((resp.url, size))

            if resource_type == "document" and ttfb_ms[0] is None:
                try:
                    timing = resp.request.timing()
                    request_start = timing.get("requestStart", 0)
                    response_start = timing.get("responseStart", -1)
                    if response_start >= 0:
                        ttfb_ms[0] = response_start - request_start
                except Exception:
                    pass

        page.on("response", track_response_weight)

        start_time = time.time()
        main_response = page.goto(url, wait_until="load", timeout=timeout_ms)
        load_time = time.time() - start_time

        # When the PAGE ITSELF (not just some sub-resource) comes back
        # bot-blocked, whatever actually rendered is very likely a WAF's
        # own challenge/error page, not the site's real content — running
        # the rest of this function's checks (SEO, mobile, forms, console
        # errors...) against that would report on the block page, not the
        # business's site, which is exactly the kind of misattribution
        # this tool exists to avoid (confirmed on a real report: blaze.ai's
        # own "Log In" page came back 403, and a garbled console message
        # from whatever error page loaded got reported as a HIGH
        # "JavaScript Console Error" on their login page — not a real bug
        # of theirs). The "response" listener registered above has
        # already recorded the couldn't-check note for this exact status
        # (see record_failed_request's BOT_BLOCK_STATUSES handling), so
        # there's nothing more useful this function can learn from a page
        # it never really got to see.
        if main_response is not None and main_response.status in BOT_BLOCK_STATUSES:
            return problems, could_not_check

        # page.url is the URL the browser actually ended up on after any
        # redirects (e.g. medvi.org -> home.medvi.org). Relative links on
        # the page are resolved by the browser against that final URL, not
        # the one we originally requested, so this has to be the base used
        # below or relative links get checked against the wrong host and
        # falsely reported as broken. Local file targets don't redirect, so
        # they keep using the original path.
        link_base = target if is_local_target(target) else page.url

        # A cart/checkout/account/login/search page — see
        # _is_utility_page. SEO metadata and lead-generation form checks
        # don't meaningfully apply to a page like this (found testing
        # heavenmayhem.com: "missing meta description" on the cart page,
        # a login form flagged the same way a contact form would be).
        is_utility_page = _is_utility_page(page.url)

        _check_page_load_time(load_time * 1000, baseline_ms, problems)

        if ttfb_ms[0] is not None:
            ttfb = ttfb_ms[0]
            if ttfb > TTFB_POOR_MIN_MS:
                problems.append(
                    {
                        "category": "Slow Server Response",
                        "message": (
                            f"The server took {ttfb / 1000:.1f}s to send back the "
                            "first byte of the page, before the browser could even "
                            "start rendering anything. This points more toward the "
                            "site's own server/hosting than its content — it's not "
                            "affected by how fast this check's browser can render "
                            "the page (unlike page-load time), though network "
                            "distance between where this check runs and the site's "
                            "server can still play a part."
                        ),
                        "severity": MEDIUM,
                        "confidence": VERIFIED,
                    }
                )
            elif ttfb > TTFB_GOOD_MAX_MS:
                problems.append(
                    {
                        "category": "Slow Server Response",
                        "message": (
                            f"The server took {ttfb / 1000:.1f}s to send back the "
                            "first byte of the page — a bit slower than ideal "
                            f"(under {TTFB_GOOD_MAX_MS / 1000:.1f}s is the target)."
                        ),
                        "severity": LOW,
                        "confidence": VERIFIED,
                    }
                )

        if page_weight_bytes[0] > HEAVY_PAGE_WEIGHT_BYTES:
            mb = page_weight_bytes[0] / (1024 * 1024)
            problems.append(
                {
                    "category": "Heavy Page",
                    "message": (
                        f"This page downloads about {mb:.1f}MB to load — more "
                        "than the roughly 3MB guideline, which can mean slow "
                        "loads for visitors on mobile data or a weak connection."
                    ),
                    # LOW, not MEDIUM (product decision, 2026-09-26 — see
                    # PLAN.md): large images on a brand site are usually a
                    # deliberate choice, not a bug. On a whole-site crawl,
                    # this also collapses to one site-wide finding naming
                    # only the heaviest page, not one per heavy page — see
                    # the post-crawl step in run_site_check. The evidence
                    # here is this page's own byte count specifically
                    # (not the usual category-only fallback), so that step
                    # can compare pages and find the heaviest before
                    # removing these per-page entries.
                    "severity": LOW,
                    "confidence": VERIFIED,
                    "evidence": str(page_weight_bytes[0]),
                }
            )

        if request_count[0] > MANY_REQUESTS_THRESHOLD:
            problems.append(
                {
                    "category": "Many Requests",
                    "message": (
                        f"This page makes {request_count[0]} separate network "
                        "requests to load — a high number can slow down loading, "
                        "especially on mobile."
                    ),
                    "severity": LOW,
                    "confidence": VERIFIED,
                }
            )

        # Two independent ways an image can be "oversized": its downloaded
        # file is just heavy (byte-size, tracked above), or its file
        # resolution is much bigger than the size it's actually shown at
        # (a DOM-only fact, checked here) — a small/well-compressed file
        # can still fail the second one, and vice versa. Merged into one
        # finding, deduped by URL so an image that fails both isn't
        # listed twice.
        oversized_by_url = {
            img_url: f"{size // 1024}KB" for img_url, size in oversized_images
        }
        for item in _find_dimension_oversized_images(page):
            src = item.get("src") or ""
            if not src or src in oversized_by_url:
                continue
            nw, nh = int(item["naturalWidth"]), int(item["naturalHeight"])
            dw, dh = round(item["displayWidth"]), round(item["displayHeight"])
            oversized_by_url[src] = f"{nw}x{nh}px shown at only {dw}x{dh}px"

        if oversized_by_url:
            ordered = sorted(oversized_by_url.items())
            examples = ", ".join(
                f"{img_url.rsplit('/', 1)[-1]} ({detail})"
                for img_url, detail in ordered[:3]
            )
            more = f" (+{len(ordered) - 3} more)" if len(ordered) > 3 else ""
            problems.append(
                {
                    "category": "Oversized Images",
                    "message": (
                        f"{len(ordered)} image(s) are bigger than they need to "
                        f"be — over {OVERSIZED_IMAGE_BYTES // 1024}KB, or a much "
                        "higher resolution than the size they're actually shown "
                        f"at — which can slow the page down — e.g. {examples}"
                        f"{more}. Consider compressing or resizing them."
                    ),
                    "severity": LOW,
                    "confidence": VERIFIED,
                    # This page's exact set of oversized images — a
                    # different page with a different (or no) set of heavy
                    # images must stay its own finding, not get folded into
                    # this one just because both are "Oversized Images."
                    "evidence": "|".join(img_url for img_url, _ in ordered),
                }
            )

        # Bundled into one finding per page (like Oversized Images above)
        # rather than one per image — a product listing page can easily
        # have dozens of images, and "47 separate problems" for one root
        # cause (the theme/CMS not setting alt text) buries everything
        # else in the report. `evidence` is the page's exact set of
        # missing-alt image URLs: pages with a genuinely different set
        # (different products) stay distinct findings; the same set
        # recurring (e.g. a header/footer icon reused site-wide) collapses
        # across pages via dedupe_site_problems, same as any other check.
        missing_alt = [
            img.get_attribute("src") or "(no src)"
            for img in page.query_selector_all("img")
            if img.get_attribute("alt") is None
        ]
        if missing_alt:
            unique_srcs = sorted(dict.fromkeys(missing_alt))
            problems.append(
                {
                    "category": "Missing Alt Text",
                    "message": (
                        f"{len(missing_alt)} image(s) on this page have no alt attribute "
                        f"({_examples_text(unique_srcs)}) — screen readers can't describe them, "
                        "and search engines can't tell what they show. Ask your web person to add "
                        "a short description to each."
                    ),
                    "severity": LOW,
                    "confidence": VERIFIED,
                    "evidence": "|".join(unique_srcs),
                }
            )

        if is_local_target(target):
            # Local file fixtures: no HTTP, no crawl — just check that each
            # linked file exists (and probe absolute links, as before).
            for link in page.query_selector_all("a[href]"):
                href = link.get_attribute("href")
                if not href or href.startswith("#") or href.startswith(
                    ("mailto:", "tel:", "javascript:")
                ):
                    continue
                link_result = check_link(href, link_base, page, could_not_check)
                if link_result:
                    error, link_confidence = link_result
                    problems.append(
                        {
                            "category": "Broken Link",
                            "message": error,
                            "severity": MEDIUM,
                            "confidence": link_confidence,
                        }
                    )
        else:
            # Step 7: what this page picked up on its own, before any check
            # touches it — the link checks' browser rechecks share this
            # page's cookie jar, and later checks click, type and Tab.
            if extras is not None:
                try:
                    page.wait_for_load_state("networkidle", timeout=4000)
                except Exception:
                    pass
                extras["cookie_snapshot"] = snapshot_page(
                    page, list(request_urls), site_domain or target_base_domain
                )
            check_page_links(
                page,
                main_response,
                page.url,
                site_domain or get_base_domain(urlparse(page.url).hostname),
                problems,
                could_not_check,
                link_cache or LinkCache(),
                _is_safe_to_crawl,
                BROWSER_HEADERS,
            )
            _check_redirect_chain(main_response, problems)
            _check_soft_404(page, main_response, soft_404_fp, is_homepage, problems)
            if not is_utility_page:
                check_indexability(page, main_response, problems, is_homepage)

        check_seo_and_security(
            page, problems, skip_discoverability=is_utility_page, skip_favicon=skip_favicon
        )
        if not is_local_target(target):
            check_page_security(
                page,
                main_response,
                script_responses,
                problems,
                could_not_check,
                site_domain or target_base_domain,
                _is_safe_to_crawl,
                CRAWLER_HEADERS,
                get_base_domain,
                site_is_https=site_is_https,
                extras=extras,
            )
        check_render_blocking_scripts(page, problems)
        # Step 6. Before the form check, which fills fields in: axe and the
        # Tab-through focus check should see the page as a visitor first
        # does.
        check_accessibility(
            page, problems, could_not_check,
            budget=a11y_budget, page_url=page.url, is_homepage=is_homepage,
        )
        if not is_utility_page:
            check_forms(
                page, problems, all_responses, deliberately_blocked_urls, target_base_domain
            )
            check_embedded_forms(browser, page, problems, could_not_check)
        check_mobile_responsiveness(browser, url, timeout_ms, problems, could_not_check)
        check_core_web_vitals(
            browser, url, timeout_ms, problems, baseline_ms=baseline_ms, could_not_check=could_not_check
        )

        _classify_js_errors(js_error_candidates, console_error_candidates, problems, target_base_domain)
    finally:
        page.close()

    return problems, could_not_check


def run_check(target, timeout_ms=60000):
    """Single-page entry point used by the CLI (checker.py) and the
    regression tests: launches its own browser, checks one page, closes
    the browser. For checking a whole site, see run_site_check().

    Returns (problems, could_not_check) — see _check_single_page.

    Skips the reference-baseline calibration for local file:// targets
    (used heavily by the regression suite and CLI dev workflow) so those
    stay fast and network-independent — the relative-render-time check
    just doesn't run for them, same as it wouldn't have much meaning for
    an instant local file load anyway.

    If the page itself can't be checked at all (down, blocking automated
    checks entirely, too slow to even load) — as opposed to a check
    finding a real problem on a page that did load — that's reported via
    could_not_check, not an exception, so a single unreachable page
    doesn't take down the whole run."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            baseline_ms = (
                None
                if is_local_target(target)
                else _measure_reference_baseline(browser, timeout_ms)
            )
            try:
                return _check_single_page(browser, target, timeout_ms, baseline_ms=baseline_ms)
            except Exception as e:
                return [], [
                    f"Could not check {target} at all ({e.__class__.__name__}) — "
                    "it may be down, blocking automated checks, or too slow to "
                    "respond."
                ]
        finally:
            browser.close()


def sort_problems(problems):
    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    return sorted(problems, key=lambda p: order[p["severity"]])
