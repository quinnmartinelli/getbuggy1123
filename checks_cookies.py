"""Cookies and consent (GetBuggy Step 7).

What a visitor's browser picks up before they click anything: every cookie
set and every third-party request made while the homepage loads, each
classified (analytics / advertising / functional) from the bundled list in
cookie_data/trackers.json. On top of that record:

  * consent banner detection — known consent tools by script address
    (Cookiebot, OneTrust, Osano, CookieYes, Termly, Iubenda, ...) and
    generic banner patterns in the rendered page (fixed/pinned, or named
    "cookie"/"consent", with consent wording and a button)
  * whether tracking starts before anyone answers the banner, whether
    saying no is as easy as saying yes, and whether the banner swallows a
    phone screen with no way out
  * the privacy policy: linked from the footer, not a placeholder, dated
    within about two years, and naming the trackers the site really loads
  * the site's own cookies' Secure / HttpOnly / SameSite settings (these
    three are security findings and go through the ownership gate)

Which compliance findings show, and their wording, depends on the run's
`jurisdiction` (`us` — the default — `eu_uk` or `both`; see PLAN.md). All
compliance copy says "may" and carries the not-legal-advice line.

Passive like every other check: it loads pages the way a visitor would and
reads what happened. It never clicks the banner, never fills anything in,
and every URL it opens that came from site content (the homepage after
redirects, the privacy policy link) goes through the caller's SSRF guard.

Self-contained like checks_seo.py: no import of core.py (core imports this).
"""

import datetime
import json
import os
import re
import time
from urllib.parse import parse_qs, urlparse

from checks_security import _HOSTED_PLATFORMS, SECURITY_GROUP
from crawl_utils import registrable_domain

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
VERIFIED = "verified"
NEEDS_LOOK = "needs_look"

# Every public finding this module produces carries this, so the harness
# and report can pull them together without a hardcoded category list.
# Carried through core.dedupe_site_problems like accessibility's topic.
TOPIC = "cookies"

JURISDICTIONS = ("us", "eu_uk", "both")
DEFAULT_JURISDICTION = "us"
JURISDICTION_LABELS = {
    "us": "visitors in the US",
    "eu_uk": "visitors in the EU and UK",
    "both": "visitors in the US, the EU and the UK",
}

NOT_LEGAL_ADVICE = (
    "This is general information, not legal advice — a lawyer can tell you what applies "
    "to your business."
)

WHO_YOU = "you"
WHO_WEB_PERSON = "your web person"
WHO_YOU_OR_LAWYER = "you or your lawyer"

SKIP_ENV_VAR = "GETBUGGY_SKIP_COOKIE_CHECKS"
# Off by default everywhere, same pattern as embedded_form_providers'
# TEST_PROVIDER_HOST_ENV_VAR: only the regression harness sets it, so a
# local fixture's second hostname can stand in for a real tracker
# ("localhost=static.hotjar.com" = treat requests to localhost as Hotjar)
# without the fixture ever contacting a real tracking company.
TEST_TRACKER_ALIAS_ENV_VAR = "GETBUGGY_TEST_TRACKER_ALIAS"

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cookie_data", "trackers.json")

# Page loads in the site pass are capped below the per-page 60s: three
# loads (desktop, phone, privacy policy) must fit in SITE_PASS_BUDGET_SECONDS.
LOAD_TIMEOUT_MS = 30000
IDLE_WAIT_MS = 5000
SITE_PASS_BUDGET_SECONDS = 75
MOBILE_VIEWPORT = {"width": 390, "height": 844}
BANNER_BLOCKS_SCREEN_SHARE = 0.9
POLICY_MAX_AGE_DAYS = 2 * 365 + 60  # "about two years"
POLICY_MIN_WORDS = 100
MAX_REQUESTS_RECORDED = 2000
MAX_SET_COOKIE_RESPONSES = 200

TRACKING_CATEGORIES = ("analytics", "advertising")


def cookie_checks_skipped():
    return os.environ.get(SKIP_ENV_VAR, "").strip().lower() in ("1", "true", "yes")


def normalize_jurisdiction(value):
    """None/empty -> the default; anything else must be one of
    JURISDICTIONS (ValueError otherwise — the server turns that into a
    plain-English 400)."""
    if value is None or str(value).strip() == "":
        return DEFAULT_JURISDICTION
    value = str(value).strip().lower()
    if value not in JURISDICTIONS:
        raise ValueError(value)
    return value


# ---------------------------------------------------------------------------
# The bundled classification list.
# ---------------------------------------------------------------------------

_data = None


def load_trackers():
    global _data
    if _data is None:
        with open(DATA_PATH, encoding="utf-8") as f:
            _data = json.load(f)
    return _data


def _host_matches(host, domain):
    host = (host or "").lower().rstrip(".")
    return bool(domain) and (host == domain or host.endswith("." + domain))


def _aliases():
    out = {}
    for pair in os.environ.get(TEST_TRACKER_ALIAS_ENV_VAR, "").split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out


def _effective_host(host):
    host = (host or "").lower()
    return _aliases().get(host, host)


def classify_request(url):
    """The tracker-list entry a request belongs to, or None."""
    parsed = urlparse(url)
    host = _effective_host(parsed.hostname)
    for entry in load_trackers()["trackers"]:
        if not any(_host_matches(host, d) for d in entry["domains"]):
            continue
        prefixes = entry.get("path_prefixes")
        if prefixes and not any((parsed.path or "/").startswith(p) for p in prefixes):
            continue
        return entry
    return None


def _name_matches(name, pattern):
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def classify_cookie(name, domain, site_domain):
    """(company, category) for one cookie. By name first (a `_ga` cookie is
    Google Analytics whichever domain it's stored on — GA sets it on the
    site's own domain), then by the domain it's stored on. Anything not on
    the list is "unknown", never guessed."""
    data = load_trackers()["trackers"]
    for entry in data:
        if any(_name_matches(name, p) for p in entry["cookies"]):
            return entry["company"], entry["category"]
    host = _effective_host((domain or "").lstrip("."))
    for entry in data:
        if entry.get("path_prefixes"):
            continue  # a path-scoped entry can't own a whole domain's cookies
        if any(_host_matches(host, d) for d in entry["domains"]):
            return entry["company"], entry["category"]
    if registrable_domain(host) == site_domain:
        return "Your own site", "unknown"
    return registrable_domain(host) or host, "unknown"


def is_consent_mode_denied_ping(url):
    """Google's Consent Mode sends a cookieless "consent denied" ping
    (`gcs=G100`) before anyone answers the banner. That's how the tool is
    meant to work, not tracking before consent."""
    values = parse_qs(urlparse(url).query).get("gcs") or []
    return bool(values) and all(re.fullmatch(r"G1[0\-][0\-]", v) for v in values)


def detect_consent_tools(request_urls, script_srcs=()):
    found = []
    urls = list(request_urls or []) + list(script_srcs or [])
    for tool in load_trackers()["consent_tools"]:
        markers = tool.get("script_markers") or []
        for u in urls:
            host = (urlparse(u).hostname or "").lower()
            if any(_host_matches(host, d) for d in tool["domains"]) or any(
                m.lower() in u.lower() for m in markers
            ):
                found.append(tool["name"])
                break
    return found


# ---------------------------------------------------------------------------
# The site's own cookies: Secure / HttpOnly / SameSite (security, gated).
# ---------------------------------------------------------------------------

_AUTH_COOKIE_RE = re.compile(
    r"sess|session|auth|token|login|jwt|remember|^sid$|[._-]sid$|phpsessid|jsessionid", re.I
)
_NOT_AUTH_RE = re.compile(r"csrf|xsrf", re.I)


def looks_like_auth_cookie(name):
    if _NOT_AUTH_RE.search(name):
        return False
    known = any(
        any(_name_matches(name, p) for p in entry["cookies"])
        for entry in load_trackers()["trackers"]
        if entry["category"] in TRACKING_CATEGORIES
    )
    return not known and bool(_AUTH_COOKIE_RE.search(name))


def parse_set_cookie(line):
    """One Set-Cookie header value -> {name, secure, httponly, samesite}."""
    parts = [p.strip() for p in (line or "").split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    attrs = {}
    for p in parts[1:]:
        key, _, value = p.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": attrs.get("samesite") or None,
    }


def _names_text(names, n=5):
    names = sorted(names)
    more = f" and {len(names) - n} more" if len(names) > n else ""
    return ", ".join(f'"{x}"' for x in names[:n]) + more


def _and_join(items):
    items = list(items)
    return ", ".join(items[:-1]) + (" and " if len(items) > 1 else "") + (items[-1] if items else "")


def _security_finding(category, message, severity, confidence, evidence):
    return {
        "category": category,
        "message": f"{message} Who fixes it: {WHO_WEB_PERSON}.",
        "severity": severity,
        "confidence": confidence,
        "who_fixes": WHO_WEB_PERSON,
        "group": SECURITY_GROUP,
        "evidence": evidence,
    }


# Every category _security_finding is called with — checks_security's
# SECURITY_CATEGORIES must include all of them (unit-tested).
COOKIE_SECURITY_CATEGORIES = (
    "Cookies Not Marked Secure",
    "Login Cookie Readable By Scripts",
    "Cookies Missing SameSite Setting",
)


def cookie_attribute_findings(set_cookies, site_is_https):
    """Findings for the cookies the site's own server sets (parsed
    Set-Cookie headers from its own responses). Cookies set by a tracker's
    script aren't judged — the site owner can't change those. One finding
    per kind of problem, naming the cookies."""
    by_name = {}
    for c in set_cookies:
        if c:
            by_name.setdefault(c["name"], c)
    findings = []
    not_secure = [n for n, c in by_name.items() if not c["secure"]]
    if site_is_https and not_secure:
        findings.append(_security_finding(
            "Cookies Not Marked Secure",
            f"{len(not_secure)} cookie(s) your site sets ({_names_text(not_secure)}) aren't marked "
            "\"Secure\", so a browser may send them over an unencrypted connection, where someone on "
            "the same Wi-Fi could read them. How to fix: add the Secure flag wherever your site sets "
            "these cookies.",
            LOW, VERIFIED, "|".join(sorted(not_secure)),
        ))
    readable = [n for n, c in by_name.items() if not c["httponly"] and looks_like_auth_cookie(n)]
    if readable:
        findings.append(_security_finding(
            "Login Cookie Readable By Scripts",
            f"{_names_text(readable)} look{'s like a' if len(readable) == 1 else ' like'} login or "
            f"session cookie{'' if len(readable) == 1 else 's'} but {'isn' if len(readable) == 1 else 'aren'}'t "
            "marked \"HttpOnly\", so any script running on your page — including a malicious one — "
            "could read it and take over a visitor's session. How to fix: add the HttpOnly flag where "
            "your site sets it. Marked \"needs a look\" because we judge which cookies are logins by "
            "their names.",
            MEDIUM, NEEDS_LOOK, "|".join(sorted(readable)),
        ))
    no_samesite = [n for n, c in by_name.items() if not c["samesite"]]
    if no_samesite:
        findings.append(_security_finding(
            "Cookies Missing SameSite Setting",
            f"{len(no_samesite)} cookie(s) your site sets ({_names_text(no_samesite)}) don't say "
            "whether other websites may trigger them (the \"SameSite\" setting). Browsers fill in a "
            "safe default today, but setting it yourself guards against some cross-site tricks and "
            "behaves the same in every browser. How to fix: add SameSite=Lax (or Strict) wherever "
            "your site sets these cookies.",
            LOW, VERIFIED, "|".join(sorted(no_samesite)),
        ))
    return findings


# ---------------------------------------------------------------------------
# Consent banner: what the buttons say.
# ---------------------------------------------------------------------------

_REJECT_RE = re.compile(
    r"\b(reject|decline|deny|refuse|disagree|disallow|opt[- ]?out|do not (accept|allow|sell)|"
    r"don'?t (accept|allow)|no,? thanks|(strictly )?necessary (cookies )?only|only (strictly )?necessary|"
    r"essential (cookies )?only|only essential|continue without (accepting|agreeing))\b",
    re.I,
)
_SETTINGS_RE = re.compile(
    r"\b(settings|preferences|manage|customi[sz]e|options|choices|selection|more info(rmation)?|"
    r"learn more|details|read more|cookie policy|privacy policy|privacy notice)\b",
    re.I,
)
# A label that STARTS with an accept word is an accept even if it goes on
# to mention a policy ("Accept cookie policy", "Allow selection").
_ACCEPT_LEAD_RE = re.compile(r"^(i )?(accept|allow|agree|got it|ok(ay)?|understood|i understand|yes)\b", re.I)
_ACCEPT_RE = re.compile(
    r"\b(accept|allow|agree|got it|ok(ay)?|understood|i understand|consent|yes|continue|sounds good)\b",
    re.I,
)
_CLOSE_RE = re.compile(r"^([×✕✖x]|close|dismiss)$|\b(close|dismiss)\b", re.I)


def classify_control(text, aria=""):
    """'reject' / 'accept' / 'settings' / 'close' / None for one banner
    button, judged by its wording (its aria-label when it has no text, e.g.
    an "×" icon). Reject is tested first so "Continue without accepting"
    isn't read as an accept."""
    label = (text or "").strip() or (aria or "").strip()
    if _REJECT_RE.search(label):
        return "reject"
    if _ACCEPT_LEAD_RE.search(label):
        return "accept"
    if _SETTINGS_RE.search(label):
        return "settings"
    if _CLOSE_RE.search(label):
        return "close"
    if _ACCEPT_RE.search(label):
        return "accept"
    return None


def _control_kinds(banner):
    return [
        (classify_control(c.get("text"), c.get("aria")), c)
        for c in (banner or {}).get("controls") or []
    ]


def is_consent_banner(banner):
    """A pinned/named block with consent wording only counts as a cookie
    banner if one of its buttons answers it — a bakery's sticky header with
    a "Cookies" menu item is not a banner."""
    return any(kind in ("accept", "reject", "close") for kind, _ in _control_kinds(banner))


# ---------------------------------------------------------------------------
# Privacy policy: finding it, and reading it.
# ---------------------------------------------------------------------------

_PRIVACY_RE = re.compile(r"privacy|datenschutz|privacidad|confidentialit|privacit|data protection", re.I)
_NOT_POLICY_RE = re.compile(r"privacy (choices|settings|preferences)|do not sell|cookie (settings|preferences)", re.I)


def find_privacy_link(links):
    """(url, in_footer) for the best privacy-policy link on a page, or
    (None, False). A footer link wins over one elsewhere on the page.
    "Your privacy choices" / cookie-settings buttons aren't the policy."""
    best = None
    for link in links or []:
        href = link.get("href") or ""
        if not href.startswith(("http://", "https://")):
            continue
        text = link.get("text") or ""
        if _NOT_POLICY_RE.search(text):
            continue
        if not (_PRIVACY_RE.search(text) or _PRIVACY_RE.search(urlparse(href).path or "")):
            continue
        if link.get("inFooter"):
            return href, True
        best = best or href
    return best, False


def privacy_url_from_sitemap(sitemap_urls):
    for u in sitemap_urls or []:
        if _PRIVACY_RE.search(urlparse(u).path or ""):
            return u
    return None


_PLACEHOLDER_RE = re.compile(
    r"lorem ipsum|\[\s*(your|company|business|website|site|insert|name|date|address|email)[^\]]{0,40}\]|"
    r"\{\{|insert (your|company|business|date)|your company name|company name here|\bcompany_name\b|"
    r"this is a (sample|placeholder)|sample privacy policy|coming soon|under construction",
    re.I,
)

_MONTHS = {
    m: i + 1 for i, m in enumerate(
        ["january", "february", "march", "april", "may", "june", "july",
         "august", "september", "october", "november", "december"]
    )
}
_MONTHS.update({k[:3]: v for k, v in list(_MONTHS.items())})
_MONTHS["sept"] = 9
_MONTH_ALT = "|".join(sorted(_MONTHS, key=len, reverse=True))

_DATE_PATTERNS = (
    # March 5, 2024 / Mar 5th 2024
    (re.compile(rf"\b({_MONTH_ALT})\.?\s+(\d{{1,2}})(?:st|nd|rd|th)?,?\s+((?:19|20)\d\d)\b", re.I), "mdy"),
    # 5 March 2024
    (re.compile(rf"\b(\d{{1,2}})(?:st|nd|rd|th)?\s+({_MONTH_ALT})\.?,?\s+((?:19|20)\d\d)\b", re.I), "dmy"),
    # 2024-03-05
    (re.compile(r"\b((?:19|20)\d\d)-(\d{1,2})-(\d{1,2})\b"), "ymd"),
    # 03/05/2024 or 05.03.2024
    (re.compile(r"\b(\d{1,2})[/.](\d{1,2})[/.]((?:19|20)\d\d)\b"), "num"),
    # March 2024
    (re.compile(rf"\b({_MONTH_ALT})\.?,?\s+((?:19|20)\d\d)\b", re.I), "my"),
)
_UPDATED_RE = re.compile(r"updated|effective|revised|modified|last changed|as of|dated|version", re.I)
_YEAR_AFTER_KEYWORD_RE = re.compile(
    r"(?:updated|effective|revised|modified|last changed)\D{0,30}((?:19|20)\d\d)\b", re.I
)


def _safe_date(y, m, d):
    try:
        return datetime.date(int(y), int(m), int(d))
    except ValueError:
        return None


def _dates_in(text):
    """[(date, start_index)] for every date-looking thing in text. Where a
    date is only partly given (a month, a year) it's read as the END of
    that period — the benefit of the doubt goes to the site. Patterns run
    most-complete first, and a later match inside text an earlier one
    already read ("January 2026" inside "5 January 2026") is skipped."""
    out, taken = [], []

    def free(m):
        if any(m.start() < end and start < m.end() for start, end in taken):
            return False
        taken.append(m.span())
        return True

    for pattern, kind in _DATE_PATTERNS:
        for m in pattern.finditer(text):
            if not free(m):
                continue
            g = m.groups()
            if kind == "mdy":
                d = _safe_date(g[2], _MONTHS[g[0].lower().rstrip(".")], g[1])
            elif kind == "dmy":
                d = _safe_date(g[2], _MONTHS[g[1].lower().rstrip(".")], g[0])
            elif kind == "ymd":
                d = _safe_date(g[0], g[1], g[2])
            elif kind == "num":
                d = _safe_date(g[2], g[0], g[1]) or _safe_date(g[2], g[1], g[0])
            else:
                d = _safe_date(g[1], _MONTHS[g[0].lower().rstrip(".")], 28)
            if d:
                out.append((d, m.start()))
    for m in _YEAR_AFTER_KEYWORD_RE.finditer(text):
        if any(m.start(1) < end and start < m.end(1) for start, end in taken):
            continue
        d = _safe_date(m.group(1), 12, 31)
        if d:
            out.append((d, m.start(1)))
    return out


def policy_date(text, today=None):
    """The policy's "last updated" date, best guess: the latest date
    printed near "updated/effective/revised", else the latest date
    anywhere on the page. Future dates (beyond a month) are ignored."""
    today = today or datetime.date.today()
    limit = today + datetime.timedelta(days=31)
    dates = [(d, i) for d, i in _dates_in(text or "") if d <= limit]
    if not dates:
        return None
    near = [
        d for d, i in dates
        if _UPDATED_RE.search(text[max(0, i - 80):i + 20])
    ]
    return max(near or [d for d, _ in dates])


def placeholder_reason(text):
    """Why a policy page looks unfinished, or None."""
    m = _PLACEHOLDER_RE.search(text or "")
    if m:
        return f"it contains template text (\"{m.group(0).strip()[:40]}\")"
    words = len(re.findall(r"[A-Za-z]{2,}", text or ""))
    if words < POLICY_MIN_WORDS:
        return f"it's only about {words} words long — real privacy policies run to several paragraphs"
    return None


def policy_mentions(text, entry):
    lowered = (text or "").lower()
    return any(re.search(rf"\b{re.escape(t)}\b", lowered) for t in entry.get("policy_terms") or [])


# ---------------------------------------------------------------------------
# What a page load picked up: cookies + third-party requests.
# ---------------------------------------------------------------------------

def _cookie_records(cookies, site_domain):
    records = {}
    for c in cookies or []:
        name, domain = c.get("name"), (c.get("domain") or "").lstrip(".").lower()
        if not name:
            continue
        company, category = classify_cookie(name, domain, site_domain)
        records[(name, domain)] = {
            "name": name, "domain": domain, "company": company, "category": category,
            "first_party": registrable_domain(_effective_host(domain)) == site_domain,
        }
    return list(records.values())


def _third_party_hosts(request_urls, site_domain):
    found = {}
    for u in request_urls or []:
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            continue
        host = parsed.hostname.lower()
        if registrable_domain(host) == site_domain:
            continue
        entry = classify_request(u)
        if entry:
            found[host] = (entry["company"], entry["category"])  # a classified request wins
        elif host not in found:
            found[host] = (registrable_domain(host) or host, "unknown")
    return [
        {"host": host, "company": company, "category": category}
        for host, (company, category) in found.items()
    ]


def snapshot_page(page, request_urls, site_domain):
    """Called by core._check_single_page right after a crawl page loads,
    before any check touches it: the cookies and third-party hosts that
    page picked up on its own. Merged into the report's cookie summary
    after the crawl (merge_page_snapshots)."""
    try:
        cookies = page.context.cookies()
    except Exception:
        cookies = []
    return {
        "cookies": _cookie_records(cookies, site_domain),
        "hosts": _third_party_hosts(request_urls, site_domain),
    }


def tracking_evidence(cookie_records, request_urls, site_domain):
    """What counts as tracking: analytics/advertising cookies, and requests
    to analytics/advertising companies (not counting Consent Mode's
    "consent denied" pings). Returns (companies, advertising_companies,
    evidence_text)."""
    companies = {}  # company -> {"category", "cookies": set, "contacted": bool}

    def entry_for(company, category):
        return companies.setdefault(company, {"category": category, "cookies": set(), "contacted": False})

    for c in cookie_records:
        if c["category"] in TRACKING_CATEGORIES:
            entry_for(c["company"], c["category"])["cookies"].add(c["name"])
    for u in request_urls or []:
        host = (urlparse(u).hostname or "").lower()
        if not host or registrable_domain(host) == site_domain:
            continue
        entry = classify_request(u)
        if entry and entry["category"] in TRACKING_CATEGORIES and not is_consent_mode_denied_ping(u):
            entry_for(entry["company"], entry["category"])["contacted"] = True
    bits = []
    for name in sorted(companies):
        info = companies[name]
        what = []
        if info["cookies"]:
            what.append(f"cookie{'' if len(info['cookies']) == 1 else 's'} {_names_text(info['cookies'], 3)}")
        if info["contacted"]:
            what.append("contacted")
        bits.append(f"{name} ({', '.join(what)})")
    evidence = _and_join(bits)
    ad = sorted(c for c, info in companies.items() if info["category"] == "advertising")
    return sorted(companies), ad, evidence


# ---------------------------------------------------------------------------
# The informational section: "Your site sets N cookies from M companies".
# ---------------------------------------------------------------------------

_CATEGORY_ORDER = {"advertising": 0, "analytics": 1, "functional": 2, "unknown": 3}


def build_summary(cookie_records, hosts, jurisdiction, consent_tools=(), banner_seen=False,
                  privacy_policy_url=None, pages_observed=1):
    companies = {}
    for c in cookie_records:
        e = companies.setdefault((c["company"], c["category"]), {"cookies": set(), "hosts": set()})
        e["cookies"].add(c["name"])
    for h in hosts:
        e = companies.setdefault((h["company"], h["category"]), {"cookies": set(), "hosts": set()})
        e["hosts"].add(h["host"])
    ordered = sorted(companies.items(), key=lambda kv: (_CATEGORY_ORDER.get(kv[0][1], 9), kv[0][0].lower()))
    listed = [
        {"name": name, "category": category, "cookies": sorted(v["cookies"]), "hosts": sorted(v["hosts"])}
        for (name, category), v in ordered
    ]
    n_cookies = len(cookie_records)
    cookie_companies = {c["company"] for c in cookie_records}
    contacted_only = {name for (name, _), v in companies.items() if not v["cookies"]} - cookie_companies
    headline = (
        f"Your site sets {n_cookies} cookie{'' if n_cookies == 1 else 's'} from "
        f"{len(cookie_companies)} compan{'y' if len(cookie_companies) == 1 else 'ies'}"
    )
    if contacted_only:
        headline += (
            f", and contacts {len(contacted_only)} more compan"
            f"{'y' if len(contacted_only) == 1 else 'ies'} without setting cookies"
        )
    headline += " — before a visitor clicks anything."
    return {
        "jurisdiction": jurisdiction,
        "written_for": JURISDICTION_LABELS[jurisdiction],
        "headline": headline,
        "note": (
            "What we saw on the pages we checked, before clicking or accepting anything. Categories "
            "come from GetBuggy's own list of common tools; \"unknown\" means we don't recognise it, "
            f"not that it's a problem. {NOT_LEGAL_ADVICE}"
        ),
        "cookie_count": n_cookies,
        "company_count": len(cookie_companies),
        "companies": listed,
        "consent_tools": list(consent_tools),
        "banner_seen": banner_seen,
        "privacy_policy_url": privacy_policy_url,
        "pages_observed": pages_observed,
        # raw records, so per-page snapshots can be merged in after the crawl
        "cookie_records": cookie_records,
        "hosts": hosts,
    }


def merge_page_snapshots(summary, snapshots):
    """Adds what the other crawled pages picked up on load to the
    homepage's summary (only the summary — findings stay homepage-based,
    which is the page every banner has to work on)."""
    if not summary:
        return summary
    records = {(c["name"], c["domain"]): c for c in summary["cookie_records"]}
    hosts = {(h["host"], h["company"]): h for h in summary["hosts"]}
    pages = summary.get("pages_observed", 1)
    for snap in snapshots:
        if not snap:
            continue
        pages += 1
        for c in snap.get("cookies") or []:
            records.setdefault((c["name"], c["domain"]), c)
        for h in snap.get("hosts") or []:
            hosts.setdefault((h["host"], h["company"]), h)
    return build_summary(
        list(records.values()), list(hosts.values()), summary["jurisdiction"],
        summary["consent_tools"], summary["banner_seen"], summary["privacy_policy_url"], pages,
    )


# ---------------------------------------------------------------------------
# Findings — wording depends on the jurisdiction.
# ---------------------------------------------------------------------------

def _finding(category, message, severity, confidence, who, legal=True):
    if legal:
        message = f"{message} {NOT_LEGAL_ADVICE}"
    return {
        "category": category,
        "message": message,
        "severity": severity,
        "confidence": confidence,
        "who_fixes": who,
        "topic": TOPIC,
    }


def _law_sentence(jurisdiction):
    if jurisdiction == "us":
        return "US state privacy laws (California's, for example) may require one"
    if jurisdiction == "eu_uk":
        return "EU and UK privacy rules (GDPR) may require one"
    return "US state privacy laws (California's, for example) and EU/UK rules (GDPR) may require one"


def no_banner_finding(jurisdiction, ad_companies, evidence):
    """Tracking with no banner. Under the US default this only fires for
    ADVERTISING trackers (state laws' opt-out of "sale or sharing"); plain
    analytics with no banner isn't a US finding. EU/UK: any tracking."""
    who = f"{WHO_WEB_PERSON} adds it; your lawyer can tell you which rules apply to you"
    if jurisdiction == "us":
        if not ad_companies:
            return None
        message = (
            f"Your homepage starts tracking visitors as soon as they arrive — we saw {evidence}, "
            f"including advertising trackers ({', '.join(ad_companies)}) — and we didn't see any "
            "cookie notice or way to opt out. Why it "
            "matters: in the US there's generally no single law requiring a cookie banner, but some "
            "state privacy laws (California's, for example) may require you to tell visitors about "
            "advertising tracking and let them opt out of it. How to fix: add a short cookie notice "
            "with an opt-out (tools like Cookiebot, Osano, CookieYes or Termly do this) and name these "
            f"companies in your privacy policy. Who fixes it: {who}."
        )
    else:
        message = (
            f"Your homepage starts tracking visitors as soon as they arrive — we saw {evidence} — "
            "and we didn't see a cookie banner asking first. Why it "
            "matters: if you have visitors in the EU or UK, the rules there (GDPR and the ePrivacy "
            "rules; the UK's PECR) may require asking before analytics or advertising cookies are "
            "set, and regulators have fined small businesses over it. How to fix: add a consent banner "
            "(tools like Cookiebot, Osano, CookieYes or Termly do this) that holds these tools back "
            f"until a visitor says yes."
        )
        if jurisdiction == "both":
            message += " US state laws may also require an opt-out for advertising tracking."
        message += f" Who fixes it: {who}."
    message += " Marked \"needs a look\" because a custom-built banner can be hard for us to recognise."
    return _finding("Tracking With No Cookie Notice", message, MEDIUM, NEEDS_LOOK, WHO_WEB_PERSON)


def before_consent_finding(jurisdiction, evidence):
    if jurisdiction == "us":
        return None  # US rules are opt-out: tracking before an answer isn't the issue there
    return _finding(
        "Tracking Starts Before Consent",
        "Your cookie banner shows up, but your banner isn't blocking anything: before we touched it, "
        f"we already saw {evidence}. Why it matters: in the EU and UK, consent may "
        "need to come before analytics and advertising cookies are set, so a banner that doesn't hold "
        "them back may not count as asking at all. How to fix: turn on your consent tool's blocking "
        "(often called \"auto-blocking\" or \"prior consent\"), or set Google tags to use Consent "
        f"Mode, so these only load after a visitor accepts. Who fixes it: {WHO_WEB_PERSON}.",
        MEDIUM, VERIFIED, WHO_WEB_PERSON,
    )


def reject_harder_finding(jurisdiction, banner):
    if jurisdiction == "us":
        return None
    kinds = _control_kinds(banner)
    accepts = [c for k, c in kinds if k == "accept"]
    if not accepts or any(k == "reject" for k, _ in kinds):
        return None
    others = [c.get("text") for k, c in kinds if k != "accept" and c.get("text")]
    how = (
        "the only other choices were " + " and ".join(f"\"{t}\"" for t in others[:3])
        if others else "there's no other choice at all"
    )
    return _finding(
        "Rejecting Cookies Is Harder Than Accepting",
        f"Your cookie banner offers \"{accepts[0].get('text') or 'Accept'}\", but no equally "
        f"easy way to say no on the first screen — {how}. Why it matters: in the EU and UK, regulators' "
        "guidance says refusing cookies may need to be as easy as accepting them; a hidden \"reject\" "
        "can make the consent not count. How to fix: add a \"Reject all\" button next to \"Accept\", "
        "the same size and style (usually a setting in your consent tool). Who fixes it: "
        f"{WHO_WEB_PERSON}. Marked \"needs a look\" because we judge the buttons by their wording.",
        LOW, NEEDS_LOOK, WHO_WEB_PERSON,
    )


def mobile_block_finding(mobile_banner):
    if not mobile_banner or mobile_banner.get("coverage", 0) < BANNER_BLOCKS_SCREEN_SHARE:
        return None
    if mobile_banner.get("scrollable"):
        return None
    if any(k in ("accept", "reject", "close") and c.get("inViewport") for k, c in _control_kinds(mobile_banner)):
        return None
    return _finding(
        "Cookie Banner Covers The Phone Screen",
        "On a phone-sized screen your cookie banner covers the whole screen, and we couldn't find a "
        "button on it to accept, reject or close it without going past the edge of the screen — "
        "visitors on phones may not be able to get into your site at all. Why it matters: most "
        "visitors to a small business site are on phones; if they can't get past the banner, they "
        "leave. How to fix: make the banner smaller on phones, or keep its buttons at the top where "
        f"they're always visible. Who fixes it: {WHO_WEB_PERSON}. Marked \"needs a look\": open "
        "your site on your phone to confirm.",
        LOW, NEEDS_LOOK, WHO_WEB_PERSON, legal=False,
    )


def privacy_findings(jurisdiction, policy, tracking_companies, today=None):
    """`policy` = {"url", "in_footer", "source": "homepage"|"sitemap"|None,
    "text": str|None}. `text` is None when the page couldn't be read (that
    goes in "couldn't check", decided by the caller)."""
    tracking = bool(tracking_companies)
    trackers_text = f" — and your site uses trackers ({', '.join(tracking_companies)})" if tracking else ""
    serious = MEDIUM if tracking else LOW
    out = []
    url = policy.get("url")
    if not url:
        out.append(_finding(
            "No Privacy Policy Found",
            "We couldn't find a privacy policy — no link to one on your homepage and none in your "
            f"sitemap{trackers_text}. Why it matters: a privacy policy tells visitors what you collect "
            f"and who you share it with; {_law_sentence(jurisdiction)}, and Google, Meta and most ad "
            "platforms require one in their own terms. How to fix: publish a privacy policy page (a "
            "generator like Termly or Iubenda can help, or your lawyer) and link it in your footer. "
            f"Who fixes it: {WHO_YOU_OR_LAWYER} write it; {WHO_WEB_PERSON} links it. Marked \"needs a "
            "look\" in case it's somewhere we didn't check.",
            serious, NEEDS_LOOK, WHO_YOU_OR_LAWYER,
        ))
        return out
    if not policy.get("in_footer"):
        where = (
            "we only found it in your sitemap, not linked from your homepage"
            if policy.get("source") == "sitemap"
            else "it's linked from your homepage, but not from the footer"
        )
        out.append(_finding(
            "Privacy Policy Not In Your Footer",
            f"Your privacy policy ({url}) isn't in your site's footer — {where}. Why it matters: the "
            "footer is where visitors, and ad platforms reviewing your site, look for it, and some "
            "privacy laws may expect it to be easy to find from every page. How to fix: add a "
            f"\"Privacy Policy\" link to your footer. Who fixes it: {WHO_WEB_PERSON}.",
            LOW, NEEDS_LOOK, WHO_WEB_PERSON,
        ))
    text = policy.get("text")
    if text is None:
        return out
    reason = placeholder_reason(text)
    if reason:
        out.append(_finding(
            "Privacy Policy Looks Like A Placeholder",
            f"Your privacy policy page ({url}) looks unfinished: {reason}{trackers_text}. Why it "
            "matters: a template that was never filled in may not count as a privacy policy at all. "
            "How to fix: replace it with a real policy that names your business, what you collect, and "
            f"the companies you share data with. Who fixes it: {WHO_YOU_OR_LAWYER}. Marked \"needs a "
            "look\" because we judge this from the page's wording.",
            serious, NEEDS_LOOK, WHO_YOU_OR_LAWYER,
        ))
        return out  # dating or naming trackers in a placeholder is beside the point
    today = today or datetime.date.today()
    dated = policy_date(text, today)
    if dated is None:
        out.append(_finding(
            "Privacy Policy Isn't Dated",
            f"Your privacy policy ({url}) doesn't say when it was last updated. Why it matters: the "
            "tools on your site change, some laws (California's, for example) may expect a policy to "
            "be reviewed every year, and a date shows visitors it's current. How to fix: add a \"Last "
            f"updated\" date at the top and review it once a year. Who fixes it: {WHO_YOU_OR_LAWYER}. "
            "Marked \"needs a look\" in case the date is written in a way we didn't recognise.",
            LOW, NEEDS_LOOK, WHO_YOU_OR_LAWYER,
        ))
    elif (today - dated).days > POLICY_MAX_AGE_DAYS:
        out.append(_finding(
            "Privacy Policy May Be Out Of Date",
            f"Your privacy policy ({url}) looks like it was last updated {dated.strftime('%B %Y')} — "
            "more than two years ago. Why it matters: the tools on your site have probably changed "
            "since then, and some laws (California's, for example) may expect a yearly review. How to "
            "fix: check it against what your site uses today (see the cookie list in this report) and "
            f"update the date. Who fixes it: {WHO_YOU_OR_LAWYER}. Marked \"needs a look\" because we "
            "read the date from the page's text.",
            LOW, NEEDS_LOOK, WHO_YOU_OR_LAWYER,
        ))
    entries = {e["company"]: e for e in load_trackers()["trackers"] if e.get("policy_terms")}
    missing = [c for c in tracking_companies if c in entries and not policy_mentions(text, entries[c])]
    if missing:
        out.append(_finding(
            "Privacy Policy Doesn't Mention Your Trackers",
            f"Your privacy policy ({url}) doesn't mention {_and_join(missing)}, but your site loads "
            f"{'it' if len(missing) == 1 else 'them'}. Why it matters: a policy that leaves out who you "
            "share visitor data with may not meet privacy rules, and ad platforms like Google and Meta "
            "require you to disclose them. How to fix: add a section naming each of these companies and "
            f"what they do for you (analytics, advertising). Who fixes it: {WHO_YOU_OR_LAWYER}. Marked "
            "\"needs a look\" because we search the policy's text for the company names.",
            MEDIUM, NEEDS_LOOK, WHO_YOU_OR_LAWYER,
        ))
    return out


# ---------------------------------------------------------------------------
# Browser side.
# ---------------------------------------------------------------------------

OBSERVE_JS = r"""
() => {
  const vw = window.innerWidth, vh = window.innerHeight;
  const CONSENT_TEXT = /(we|this (site|website)|our (site|website)) (use|uses)[^.]{0,60}cookies|cookies? (policy|settings|preferences|notice|consent)|accept (all )?cookies|use of cookies|\bconsent\b|gdpr|ccpa|tracking technolog|by (continuing|clicking|using|browsing)|your privacy/i;
  const NAME_RE = /cookie|consent|gdpr|\bcmp\b|onetrust|cybot|osano|cky-|termly|iubenda|usercentrics|cmplz|qc-cmp|truste/i;
  const els = [];
  const walk = (root) => {
    for (const el of root.querySelectorAll('*')) {
      els.push(el);
      if (el.shadowRoot) walk(el.shadowRoot);
      if (els.length > 20000) return;
    }
  };
  walk(document);
  // displayed: rendered at all (a preference-centre button hidden behind
  // "Settings" is not). shown: displayed AND on screen right now.
  const displayed = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    const s = getComputedStyle(el);
    return !(s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity) === 0);
  };
  const shown = (el) => {
    const r = el.getBoundingClientRect();
    return displayed(el) && r.bottom > 0 && r.right > 0 && r.top < vh && r.left < vw;
  };
  const inView = (r) => r.top >= -1 && r.left >= -1 && r.bottom <= vh + 1 && r.right <= vw + 1;
  const parentOf = (e) => {
    if (e.parentElement) return e.parentElement;
    const root = e.getRootNode && e.getRootNode();
    return root && root !== document && root.host ? root.host : null;
  };
  const pinned = (el) => {
    for (let e = el; e; e = parentOf(e)) {
      const p = getComputedStyle(e).position;
      if (p === 'fixed' || p === 'sticky') return true;
    }
    return false;
  };
  const nameOf = (el) => (el.id || '') + ' ' + (typeof el.className === 'string' ? el.className : '');
  const controlsOf = (el) => [...el.querySelectorAll('button, [role="button"], a[href], input[type="button"], input[type="submit"]')]
    .filter(displayed).slice(0, 40).map(c => ({
      text: ((c.innerText || c.value || '') + '').trim().replace(/\s+/g, ' ').slice(0, 80),
      aria: (c.getAttribute('aria-label') || c.getAttribute('title') || '').slice(0, 80),
      inViewport: inView(c.getBoundingClientRect()),
    }));
  const scrollable = (el) => [el, ...el.querySelectorAll('*')].slice(0, 500).some(e => {
    const s = getComputedStyle(e).overflowY;
    return (s === 'auto' || s === 'scroll') && e.scrollHeight > e.clientHeight + 4;
  });
  const area = (r) => Math.max(0, Math.min(r.right, vw) - Math.max(r.left, 0)) * Math.max(0, Math.min(r.bottom, vh) - Math.max(r.top, 0));
  const TAGS = new Set(['DIV', 'SECTION', 'ASIDE', 'DIALOG', 'FORM', 'ARTICLE', 'FOOTER']);
  let pinnedBest = null, namedBest = null;
  for (const el of els) {
    if (!TAGS.has(el.tagName) && !/dialog|alertdialog|region/.test(el.getAttribute('role') || '')) continue;
    const named = NAME_RE.test(nameOf(el));
    const isPinned = pinned(el);
    if (!named && !isPinned) continue;
    if (!named && el.closest && el.closest('header, nav')) continue;
    const text = ((el.innerText || el.textContent || '') + '').trim();
    if (!text || text.length > 4000 || !CONSENT_TEXT.test(text)) continue;
    if (!shown(el)) continue;
    const controls = controlsOf(el);
    if (!controls.length) continue;
    const a = area(el.getBoundingClientRect());
    const cand = { el, a, text: text.replace(/\s+/g, ' ').slice(0, 300), controls };
    // Pinned: the outermost (largest) block is the banner or its backdrop.
    // Named but not pinned: the most specific (smallest) block.
    if (isPinned) { if (!pinnedBest || a > pinnedBest.a) pinnedBest = cand; }
    else if (!namedBest || a < namedBest.a) namedBest = cand;
  }
  const best = pinnedBest || namedBest;
  const banner = best ? {
    text: best.text, controls: best.controls, coverage: best.a / (vw * vh),
    scrollable: scrollable(best.el), pinned: !!pinnedBest,
  } : null;
  const FOOTER_SEL = 'footer, [role="contentinfo"], #footer, .footer, [id*="footer" i], [class*="footer" i]';
  const hasFooter = !!document.querySelector(FOOTER_SEL);
  const docH = Math.max(document.documentElement.scrollHeight, 1);
  const links = [...document.querySelectorAll('a[href]')].slice(0, 3000).map(a => ({
    text: ((a.innerText || a.textContent || '') + '').trim().replace(/\s+/g, ' ').slice(0, 120),
    href: a.href,
    inFooter: hasFooter ? !!a.closest(FOOTER_SEL) : (a.getBoundingClientRect().top + window.scrollY) >= docH * 0.8,
  }));
  const scripts = [...document.querySelectorAll('script[src]')].slice(0, 300).map(s => s.src);
  return { banner, links, scripts, viewport: { w: vw, h: vh } };
}
"""


def _observe(browser, url, load_ms, site_domain, mobile=False):
    """One fresh visit (new browser context = no cookies, nothing clicked):
    the page loads, the network goes quiet (capped), then we read what it
    picked up. Returns the observation dict."""
    kwargs = {"viewport": MOBILE_VIEWPORT, "is_mobile": True, "has_touch": True} if mobile else {}
    context = browser.new_context(**kwargs)
    try:
        page = context.new_page()
        request_urls, responses = [], []
        page.on("request", lambda req: request_urls.append(req.url)
                if len(request_urls) < MAX_REQUESTS_RECORDED else None)
        page.on("response", lambda resp: responses.append(resp)
                if len(responses) < MAX_SET_COOKIE_RESPONSES
                and registrable_domain(urlparse(resp.url).hostname) == site_domain else None)
        page.goto(url, wait_until="load", timeout=load_ms)
        try:
            page.wait_for_load_state("networkidle", timeout=IDLE_WAIT_MS)
        except Exception:
            pass
        data = page.evaluate(OBSERVE_JS)
        set_cookies = []
        if not mobile:
            for resp in responses:
                try:
                    for h in resp.headers_array():
                        if h["name"].lower() == "set-cookie":
                            set_cookies.append(parse_set_cookie(h["value"]))
                except Exception:
                    continue
        banner = data.get("banner")
        if banner and not is_consent_banner(banner):
            banner = None
        return {
            "requests": list(request_urls),
            "cookies": context.cookies(),
            "set_cookies": [c for c in set_cookies if c],
            "banner": banner,
            "links": data.get("links") or [],
            "scripts": data.get("scripts") or [],
        }
    finally:
        context.close()


def _read_policy(browser, url, load_ms):
    context = browser.new_context()
    try:
        page = context.new_page()
        page.goto(url, wait_until="load", timeout=load_ms)
        try:
            page.wait_for_load_state("networkidle", timeout=IDLE_WAIT_MS)
        except Exception:
            pass
        return page.inner_text("body")
    finally:
        context.close()


def run_site_cookie_pass(browser, homepage_url, site_domain, is_safe, jurisdiction=DEFAULT_JURISDICTION,
                         sitemap_urls=(), site_is_https=False, platform=None, timeout_ms=60000):
    """The whole Step 7 pass, once per crawl, on the homepage. Returns
    {"findings": [...], "notes": [...], "summary": {...} | None}."""
    jurisdiction = normalize_jurisdiction(jurisdiction)
    findings, notes = [], []
    if cookie_checks_skipped():
        return {"findings": [], "notes": [
            "The cookie, consent-banner and privacy-policy checks were switched off for this run, so "
            "this report says nothing about them either way."
        ], "summary": None}
    if not is_safe(homepage_url):
        return {"findings": [], "notes": [
            "We couldn't check cookies or your privacy policy, because your homepage redirected to an "
            "address we don't open for safety reasons."
        ], "summary": None}

    started = time.time()
    load_ms = min(timeout_ms, LOAD_TIMEOUT_MS)

    def time_left():
        return SITE_PASS_BUDGET_SECONDS - (time.time() - started)

    try:
        desktop = _observe(browser, homepage_url, load_ms, site_domain)
    except Exception as e:
        return {"findings": [], "notes": [
            f"We couldn't load your homepage to check cookies and consent ({e.__class__.__name__}), so "
            "this report says nothing about cookies, your banner or your privacy policy."
        ], "summary": None}

    records = _cookie_records(desktop["cookies"], site_domain)
    hosts = _third_party_hosts(desktop["requests"], site_domain)
    tools = detect_consent_tools(desktop["requests"], desktop["scripts"])
    banner = desktop["banner"]
    companies, ad_companies, evidence = tracking_evidence(records, desktop["requests"], site_domain)

    if companies and not banner and not tools:
        f = no_banner_finding(jurisdiction, ad_companies, evidence)
        if f:
            findings.append(f)
    elif companies and not banner and tools:
        notes.append(
            f"Your site has {', '.join(tools)} installed, but no cookie banner showed up when we "
            "checked. It may only appear for visitors in some places (we check from the US), or hide "
            "from automated checks like ours — so we couldn't check whether it holds tracking back "
            "until a visitor agrees."
        )
    if banner and companies:
        f = before_consent_finding(jurisdiction, evidence)
        if f:
            findings.append(f)
    if banner:
        f = reject_harder_finding(jurisdiction, banner)
        if f:
            findings.append(f)
        if time_left() > load_ms / 1000:
            try:
                mobile = _observe(browser, homepage_url, load_ms, site_domain, mobile=True)
                f = mobile_block_finding(mobile["banner"])
                if f:
                    findings.append(f)
            except Exception as e:
                notes.append(
                    f"We couldn't load your homepage at phone size ({e.__class__.__name__}), so we "
                    "didn't check whether your cookie banner fits on a phone screen."
                )
        else:
            notes.append(
                "We ran out of time before checking whether your cookie banner fits on a phone screen."
            )

    # The site's own cookies' settings — not the ones a hosted platform sets
    # itself (the owner can't change them; same reasoning as skipping a
    # platform's own login form in core.check_forms). Judged per cookie as
    # well as per site: platform detection can miss (seen on cakesbody.com,
    # a Shopify store whose detection came back empty), but a "_shopify_*"
    # cookie is Shopify's whatever the detection said.
    set_cookies = desktop["set_cookies"]
    if platform in _HOSTED_PLATFORMS:
        owners = {platform} if set_cookies else set()
        set_cookies = []
    else:
        owners = set()
        kept = []
        for c in set_cookies:
            company, _ = classify_cookie(c["name"], urlparse(homepage_url).hostname, site_domain)
            if company in _HOSTED_PLATFORMS:
                owners.add(company)
            else:
                kept.append(c)
        set_cookies = kept
    if owners:
        notes.append(
            f"We didn't judge the security settings of the cookies {_and_join(sorted(owners))} sets "
            "itself — those are up to them, not you."
        )
    findings += cookie_attribute_findings(set_cookies, site_is_https)

    url, in_footer = find_privacy_link(desktop["links"])
    source = "homepage" if url else None
    if not url:
        url = privacy_url_from_sitemap(sitemap_urls)
        source = "sitemap" if url else None
    policy = {"url": url, "in_footer": in_footer, "source": source, "text": None}
    if url:
        if not is_safe(url):
            notes.append(
                "We found a link to your privacy policy but didn't open it, because it points to an "
                "address we don't open for safety reasons."
            )
        elif time_left() <= load_ms / 1000:
            notes.append("We ran out of time before reading your privacy policy, so we couldn't check what it says.")
        else:
            try:
                policy["text"] = _read_policy(browser, url, load_ms)
            except Exception as e:
                notes.append(
                    f"We couldn't open your privacy policy ({e.__class__.__name__}), so we couldn't "
                    "check whether it's dated or mentions the tools your site uses."
                )
    findings += privacy_findings(jurisdiction, policy, companies)

    summary = build_summary(
        records, hosts, jurisdiction, tools, banner is not None, url,
    )
    return {"findings": findings, "notes": notes, "summary": summary}
