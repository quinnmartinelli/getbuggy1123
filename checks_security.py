"""Passive security checks (GetBuggy Step 5): endpoints, transport, headers,
exposure in page source, platform/dependency versions, third-party scripts
and signs a site has been hacked.

Passive and read-only, per CLAUDE.md: everything here either reads what a
normal page load already gave us (headers, HTML, the scripts the page
loaded) or makes a plain GET to a fixed list of paths on the site the user
pasted. No payloads, no logins, no fuzzing, no port scans. Every request
built from site content goes through the caller's SSRF guard (`is_safe`).

Two kinds of finding come out of here:
  * security findings carry `"group": "security"` and are ownership-gated —
    server.py hides their details from the public report unless
    GETBUGGY_SHOW_SECURITY_DETAILS=true (see redact_security_details).
  * site-hygiene findings from the same endpoint checklist (robots.txt
    erroring, no sitemap, favicon, missing-page handling, www vs non-www,
    web manifest) aren't exposures, so they're ordinary public findings.

Self-contained like checks_seo.py: no import of core.py (core imports this).
"""

import json
import os
import re
import socket
import ssl
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import certifi
import requests

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
VERIFIED = "verified"
NEEDS_LOOK = "needs_look"

SECURITY_GROUP = "security"
SHOW_DETAILS_ENV_VAR = "GETBUGGY_SHOW_SECURITY_DETAILS"
SKIP_ENV_VAR = "GETBUGGY_SKIP_SECURITY_CHECKS"
SAFE_BROWSING_KEY_ENV_VAR = "GOOGLE_SAFE_BROWSING_API_KEY"

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_data")

PUBLIC_SECURITY_MESSAGE = (
    "We found {n} possible security exposure{s} on this site. "
    "Verify you own this site to see the details."
)

WHO_YOU = "you"
WHO_WEB_PERSON = "your web person"
WHO_HOST = "your host"

PROBE_TIMEOUT_SECONDS = 8
PROBE_MAX_BYTES = 256 * 1024
HOMEPAGE_MAX_BYTES = 3 * 1024 * 1024
SITE_PASS_BUDGET_SECONDS = 45
# How many of our GETs may be open against one site at once. Kept low on
# purpose: these land on small businesses' own servers.
MAX_PARALLEL_PROBES = 4


def show_security_details():
    return os.environ.get(SHOW_DETAILS_ENV_VAR, "").strip().lower() in ("1", "true", "yes")


def security_checks_skipped():
    return os.environ.get(SKIP_ENV_VAR, "").strip().lower() in ("1", "true", "yes")


def _finding(category, message, severity, who, confidence=VERIFIED, evidence=None, security=True):
    f = {
        "category": category,
        "message": f"{message} Who fixes it: {who}.",
        "severity": severity,
        "confidence": confidence,
        "who_fixes": who,
    }
    if security:
        f["group"] = SECURITY_GROUP
    if evidence is not None:
        f["evidence"] = evidence
    return f


# Every security category this module (and checks_seo's mixed-content
# split) can produce. The gate checks this as well as `group`, so a code
# path that rebuilds a finding and forgets to carry `group` along (as
# core.dedupe_site_problems once did) still can't leak one into a public
# report.
SECURITY_CATEGORIES = frozenset({
    "Mixed Content (Active)", "Mixed Content (Passive)", "No Security Headers",
    "Missing Security Headers", "Server Software Version Revealed", "Secret Key Exposed In Page Source",
    "Source Code Map Files Are Public", "Outdated JavaScript Library", "Exposed Sensitive File",
    "WordPress XML-RPC Is Open", "WordPress Usernames Are Public",
    "WordPress Version Has Known Security Problems", "WordPress Out Of Date",
    "WordPress Plugins Out Of Date", "Site Doesn't Use HTTPS", "Insecure Version Of Site Doesn't Redirect",
    "Security Certificate Problem", "Security Certificate Expiring Soon", "Page Not On HTTPS",
    "Folder Contents Are Public", "Site May Be Hacked", "Script From A Domain That No Longer Exists",
    "Shared-Server Scripts Without Integrity Check",
    # Step 7: the site's own cookies' settings (checks_cookies.COOKIE_SECURITY_CATEGORIES).
    "Cookies Not Marked Secure", "Login Cookie Readable By Scripts", "Cookies Missing SameSite Setting",
})


def is_security_finding(problem):
    return problem.get("group") == SECURITY_GROUP or problem.get("category") in SECURITY_CATEGORIES


# ---------------------------------------------------------------------------
# Gating — what the public report is allowed to show.
# ---------------------------------------------------------------------------

def _strip(problems):
    return [p for p in (problems or []) if not is_security_finding(p)]


def redact_security_details(payload):
    """Returns a copy of a job/result payload with every security finding's
    detail removed, replaced by a category-level count. Used on every
    public response unless SHOW_DETAILS_ENV_VAR is on. Works on a finished
    result, a partial one, and an in-progress job (pages streamed so far)."""
    payload = json.loads(json.dumps(payload))

    def scrub_result(result):
        if not isinstance(result, dict):
            return
        count = sum(is_security_finding(p) for p in result.get("unique_problems") or [])
        count += sum(is_security_finding(p) for p in result.get("site_findings") or [])
        if not result.get("unique_problems"):
            # partial/in-progress: count distinct (category, evidence) pairs
            seen = {
                (p["category"], p.get("evidence"))
                for page in result.get("pages") or []
                for p in page.get("problems") or []
                if is_security_finding(p)
            }
            count += len(seen)
        for key in ("unique_problems", "site_findings"):
            if key in result:
                result[key] = _strip(result[key])
        for page in result.get("pages") or []:
            page["problems"] = _strip(page.get("problems"))
            page.pop("third_party_scripts", None)
        result.pop("security_details", None)
        if count:
            result["security_summary"] = {
                "count": count,
                "message": PUBLIC_SECURITY_MESSAGE.format(n=count, s="" if count == 1 else "s"),
                "details_hidden": True,
            }

    scrub_result(payload)
    scrub_result(payload.get("result"))
    for page in payload.get("pages_done") or []:
        page["problems"] = _strip(page.get("problems"))
        page.pop("third_party_scripts", None)
    return payload


# ---------------------------------------------------------------------------
# Network helper — GET only, SSRF-guarded, size-capped, every probe logged.
# ---------------------------------------------------------------------------

class Probe:
    def __init__(self, url, status=None, headers=None, body=b"", final_url=None, error=None):
        self.url = url
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body
        self.final_url = final_url or url
        self.error = error

    @property
    def ok(self):
        return self.status == 200

    def text(self):
        return self.body.decode("utf-8", errors="replace")


def fetch(url, is_safe, headers, follow=False, max_bytes=PROBE_MAX_BYTES, log=None):
    """One GET. Never follows a redirect unless asked (a sensitive-file
    probe that redirects to the homepage is not an exposure). Returns a
    Probe; `.error` is set (and `.status` None) when the request couldn't
    be made or was refused by the SSRF guard."""
    if not is_safe(url):
        probe = Probe(url, error="unsafe")
    else:
        try:
            with requests.get(
                url, headers=headers, timeout=PROBE_TIMEOUT_SECONDS,
                allow_redirects=follow, stream=True,
            ) as resp:
                buf = bytearray()
                for chunk in resp.iter_content(65536):
                    buf += chunk
                    if len(buf) >= max_bytes:
                        break
                probe = Probe(url, resp.status_code, dict(resp.headers), bytes(buf[:max_bytes]), resp.url)
        except requests.RequestException as e:
            probe = Probe(url, error=e.__class__.__name__)
    # The path only — the funnel-log rule keeps raw site URLs out of logs,
    # and the full record lives in the report's (gated) security_details.
    path = urlparse(url).path or "/"
    print(f"SECURITY_PROBE GET {path} -> {probe.status or probe.error}", file=sys.stderr)
    if log is not None:
        log.append({"url": url, "status": probe.status, "error": probe.error})
    return probe


# ---------------------------------------------------------------------------
# Bundled data (security_data/, refreshed by update_security_data.py).
# ---------------------------------------------------------------------------

_data_cache = {}


def load_data(name):
    if name not in _data_cache:
        try:
            with open(os.path.join(DATA_DIR, name)) as f:
                _data_cache[name] = json.load(f)
        except (OSError, ValueError):
            _data_cache[name] = None
    return _data_cache[name]


def _version_parts(v):
    main, _, pre = str(v).strip().lstrip("vV").partition("-")
    parts = []
    for piece in main.split("."):
        m = re.match(r"(\d+)(.*)", piece)
        if m:
            parts.append(int(m.group(1)))
            if m.group(2):
                pre = pre or m.group(2)
        else:
            parts.append(0)
    return parts, pre


def compare_versions(a, b):
    """-1/0/1. Numeric segment by segment; a pre-release ("1.2.0-beta")
    sorts before its release."""
    pa, prea = _version_parts(a)
    pb, preb = _version_parts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    if pa != pb:
        return -1 if pa < pb else 1
    if prea == preb:
        return 0
    if not prea:
        return 1
    if not preb:
        return -1
    return -1 if prea < preb else 1


# ---------------------------------------------------------------------------
# Front-end libraries (Retire.js-style).
# ---------------------------------------------------------------------------

_VERSION_TOKEN = "§§version§§"
_VERSION_RE = r"[0-9][0-9.a-z_\-]+"
_compiled_retire = None
_SAFE_FUNC_RE = re.compile(r"^[\w$.()|\s'\"\[\]]+$")


def _retire():
    global _compiled_retire
    if _compiled_retire is None:
        data = load_data("retirejs.json") or {}
        compiled = {}
        for lib, spec in (data.get("libraries") or {}).items():
            ex = {}
            for kind in ("uri", "filename", "filecontent"):
                pats = []
                for p in spec["extractors"].get(kind, []):
                    try:
                        pats.append(re.compile(p.replace(_VERSION_TOKEN, _VERSION_RE)))
                    except re.error:
                        pass  # a JS-only regex feature; skip that one pattern
                ex[kind] = pats
            ex["func"] = [
                f for f in spec["extractors"].get("func", [])
                if "require(" not in f and _SAFE_FUNC_RE.match(f)
            ]
            compiled[lib] = (ex, spec["vulnerabilities"])
        _compiled_retire = compiled
    return _compiled_retire


def _first_group(pattern, text):
    m = pattern.search(text)
    if not m:
        return None
    version = (m.group(1) if m.groups() else m.group(0)).rstrip(".-")
    return version if re.match(r"^\d", version) else None


def detect_libraries_from_url(url):
    found = set()
    filename = urlparse(url).path.rsplit("/", 1)[-1]
    for lib, (ex, _) in _retire().items():
        for kind, target in (("uri", url), ("filename", filename)):
            for pat in ex[kind]:
                v = _first_group(pat, target)
                if v:
                    found.add((lib, v))
    return found


def detect_libraries_from_content(text):
    found = set()
    text = text[:300_000]
    for lib, (ex, _) in _retire().items():
        for pat in ex["filecontent"]:
            v = _first_group(pat, text)
            if v:
                found.add((lib, v))
                break
    return found


def library_probe_expressions():
    """(library, JS expression) pairs that read a loaded library's own
    version off the page (e.g. jQuery.fn.jquery). From the bundled data
    only, filtered to plain property reads."""
    return [(lib, f) for lib, (ex, _) in _retire().items() for f in ex["func"]]


LIBRARY_PROBE_JS = """(pairs) => pairs.map(([lib, expr]) => {
  try { const v = (new Function('return ' + expr))(); return [lib, typeof v === 'string' ? v : null]; }
  catch (e) { return [lib, null]; }
})"""


def known_library_vulnerabilities(lib, version):
    entry = _retire().get(lib)
    if not entry:
        return []
    hits = []
    for v in entry[1]:
        below, above = v.get("below"), v.get("atOrAbove")
        if below and compare_versions(version, below) >= 0:
            continue
        if above and compare_versions(version, above) < 0:
            continue
        hits.append(v)
    return hits


def library_findings(detected):
    findings = []
    for lib, version in sorted(detected):
        vulns = known_library_vulnerabilities(lib, version)
        if not vulns:
            continue
        cves = sorted({c for v in vulns for c in v.get("cve", [])})
        fixed_in = sorted({v["below"] for v in vulns if v.get("below")}, key=lambda x: _version_parts(x))
        ref = f" ({', '.join(cves[:3])}{' and more' if len(cves) > 3 else ''})" if cves else ""
        upgrade = f" Updating to {fixed_in[-1]} or newer fixes the known ones." if fixed_in else ""
        findings.append(_finding(
            "Outdated JavaScript Library",
            f"Your site loads {lib} version {version}, which has {len(vulns)} publicly known "
            f"security problem(s){ref}. Attackers look for sites running exactly these old "
            f"versions.{upgrade}",
            MEDIUM, WHO_WEB_PERSON, evidence=f"{lib}@{version}",
        ))
    return findings


# ---------------------------------------------------------------------------
# Platform detection.
# ---------------------------------------------------------------------------

_PLATFORM_SIGNATURES = (
    ("WordPress", (r"/wp-content/", r"/wp-includes/", r'name=["\']generator["\'][^>]*WordPress')),
    ("Shopify", (r"cdn\.shopify\.com", r"Shopify\.theme", r"myshopify\.com")),
    ("Wix", (r"static\.wixstatic\.com", r"parastorage\.com", r'name=["\']generator["\'][^>]*Wix\.com')),
    ("Squarespace", (r"static1\.squarespace\.com", r"Static\.SQUARESPACE_CONTEXT", r"squarespace-cdn\.com")),
    ("Webflow", (r"data-wf-site=", r"website-files\.com", r'name=["\']generator["\'][^>]*Webflow')),
    ("Joomla", (r'name=["\']generator["\'][^>]*Joomla', r"/media/jui/", r"/media/system/js/")),
    ("Drupal", (r'name=["\']generator["\'][^>]*Drupal', r"drupal-settings-json", r"/sites/default/files/")),
)
_PLATFORM_HEADERS = (
    ("Shopify", ("x-shopid", "x-shopify-stage")),
    ("Wix", ("x-wix-request-id",)),
    ("Drupal", ("x-drupal-cache", "x-drupal-dynamic-cache")),
)


def detect_platform(html, headers):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    for name, keys in _PLATFORM_HEADERS:
        if any(k in headers for k in keys):
            return name
    if "drupal" in (headers.get("x-generator") or "").lower():
        return "Drupal"
    if "squarespace" in (headers.get("server") or "").lower():
        return "Squarespace"
    for name, patterns in _PLATFORM_SIGNATURES:
        if any(re.search(p, html or "", re.I) for p in patterns):
            return name
    return None


_HOSTED_PLATFORMS = {"Shopify", "Wix", "Squarespace", "Webflow"}


def _platform_hint(platform, topic):
    """One extra sentence of platform-specific fix advice, or ""."""
    if platform in _HOSTED_PLATFORMS:
        if topic in ("headers", "transport"):
            return (f" Your site runs on {platform}, which controls these settings — "
                    f"contact {platform} support rather than changing anything yourself.")
        return f" Your site runs on {platform}; check {platform}'s own settings and support pages first."
    if platform == "WordPress":
        return {
            "headers": " On WordPress, a reputable security plugin or your host's control panel can add these.",
            "transport": " On WordPress, your host's control panel usually has a one-click 'force HTTPS' option.",
            "files": " On WordPress, also change your database password, since wp-config files hold it.",
        }.get(topic, "")
    return ""


# ---------------------------------------------------------------------------
# Headers.
# ---------------------------------------------------------------------------

_HEADER_EXPLANATIONS = (
    ("hsts", "Strict-Transport-Security (makes browsers always use the secure version)"),
    ("nosniff", "X-Content-Type-Options (stops browsers guessing file types)"),
    ("framing", "X-Frame-Options or a frame-ancestors rule (stops other sites embedding yours to trick clicks)"),
    ("referrer", "Referrer-Policy (limits what your page addresses tell other sites)"),
    ("permissions", "Permissions-Policy (limits camera, microphone and location access)"),
    ("csp", "Content-Security-Policy (limits which scripts can run)"),
)
_VERSION_LEAK_RE = re.compile(r"\d+\.\d+")


def analyze_security_headers(headers, is_https, platform=None):
    h = {k.lower(): (v or "") for k, v in (headers or {}).items()}
    csp = h.get("content-security-policy", "")
    present = {
        "hsts": "strict-transport-security" in h,
        "nosniff": "nosniff" in h.get("x-content-type-options", "").lower(),
        "framing": "x-frame-options" in h or "frame-ancestors" in csp.lower(),
        "referrer": "referrer-policy" in h,
        "permissions": "permissions-policy" in h,
        "csp": bool(csp.strip()),
    }
    applicable = [k for k, _ in _HEADER_EXPLANATIONS if k != "hsts" or is_https]
    missing = [k for k in applicable if not present[k]]
    findings = []
    hint = _platform_hint(platform, "headers")
    if missing and len(missing) == len(applicable):
        findings.append(_finding(
            "No Security Headers",
            "Your site sends none of the standard security settings browsers use to protect "
            "visitors (things like blocking other sites from embedding yours, or stopping "
            "unexpected scripts). Each one is a small setting on the server that closes off a "
            f"common kind of attack.{hint}",
            MEDIUM, WHO_WEB_PERSON if platform not in _HOSTED_PLATFORMS else WHO_HOST,
        ))
    elif missing:
        names = "; ".join(desc for k, desc in _HEADER_EXPLANATIONS if k in missing)
        findings.append(_finding(
            "Missing Security Headers",
            f"Your site is missing {len(missing)} standard security setting(s) browsers use to "
            f"protect visitors: {names}. Each is a small server setting.{hint}",
            LOW, WHO_WEB_PERSON if platform not in _HOSTED_PLATFORMS else WHO_HOST,
            evidence="|".join(missing),
        ))
    leaks = [
        f"{name.title()}: {h[name]}" for name in ("server", "x-powered-by")
        if _VERSION_LEAK_RE.search(h.get(name, ""))
    ]
    if leaks:
        findings.append(_finding(
            "Server Software Version Revealed",
            f"Your server announces exactly which software version it runs ({'; '.join(leaks)}). "
            "That tells attackers which known weaknesses to try. Hiding the version number is "
            "a one-line server setting.",
            LOW, WHO_HOST, evidence="|".join(leaks),
        ))
    return findings


# ---------------------------------------------------------------------------
# Secrets in page source.
# ---------------------------------------------------------------------------

SECRET_PATTERNS = (
    ("an Amazon Web Services access key", re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")),
    ("a Stripe secret key", re.compile(r"(?<![\w])(?:sk|rk)_live_[0-9a-zA-Z]{20,}")),
    ("a SendGrid API key", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")),
    ("a Mailgun API key", re.compile(r"(?<![\w])key-[0-9a-f]{32}(?![\w])")),
    ("a Twilio auth token", re.compile(
        r"twilio[\w\s\"':=.\-]{0,40}?(?:auth_?token|secret)[\"'\s:=]{1,6}([0-9a-f]{32})(?![\w])", re.I)),
    ("a private encryption key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("an email server (SMTP) password", re.compile(
        r"smtps?://[^\s:/@\"']+:([^\s@/\"']{3,})@[\w.\-]+", re.I)),
    ("an email server (SMTP) password", re.compile(
        r"(?:smtp|mail)_?pass(?:word)?[\"'\s]*[:=]\s*[\"']([^\"'\s]{4,})[\"']", re.I)),
)


def mask_secret(value):
    """Enough to recognise which key it is, never enough to use it."""
    value = value.strip()
    if value.startswith("-----BEGIN"):
        return "-----BEGIN … PRIVATE KEY----- (contents hidden)"
    keep = 4 if len(value) > 12 else 2
    return value[:keep] + "•" * 8


def find_secrets(text):
    """[(kind, masked)] — never returns the raw value."""
    hits = []
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text or ""):
            raw = m.group(1) if m.groups() else m.group(0)
            masked = mask_secret(raw)
            if (kind, masked) not in hits:
                hits.append((kind, masked))
    return hits


def secret_findings(hits, where):
    return [
        _finding(
            "Secret Key Exposed In Page Source",
            f"The code of {where} contains what looks like {kind} ({masked}). Anyone can read "
            "a page's code, and a live key lets them use your account — send email as you, "
            "charge cards, or read your data. Cancel (\"rotate\") the key in that service's "
            "dashboard today, then have it removed from the site's code.",
            HIGH, f"{WHO_YOU} (rotate the key), then {WHO_WEB_PERSON}", evidence=f"{kind}|{masked}",
        )
        for kind, masked in hits
    ]


_SOURCE_MAP_RE = re.compile(r"[#@]\s*sourceMappingURL=([^\s'\"*]+\.map)\s*(?:\*/)?\s*$")


def source_map_url(script_url, body_tail, headers=None):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    ref = headers.get("sourcemap") or headers.get("x-sourcemap")
    if not ref:
        m = _SOURCE_MAP_RE.search((body_tail or "")[-500:])
        ref = m.group(1) if m else None
    if not ref or ref.startswith("data:"):
        return None
    return urljoin(script_url, ref)


def looks_like_source_map(body):
    head = (body or b"")[:4096].lstrip()
    return head.startswith(b"{") and (b'"mappings"' in head or b'"sources"' in head)


# ---------------------------------------------------------------------------
# Sensitive files.
# ---------------------------------------------------------------------------

def _not_html(body):
    head = body[:512].lstrip().lower()
    return not (head.startswith(b"<!doctype") or head.startswith(b"<html") or b"<body" in head)


def _env_file(body):
    lines = [l for l in body.decode("utf-8", "replace").splitlines() if l.strip() and not l.startswith("#")]
    return _not_html(body) and sum(bool(re.match(r"^[A-Z][A-Z0-9_]*\s*=", l)) for l in lines) >= 2


SENSITIVE_FILES = (
    ("/.env", "your site's settings file (.env), which usually holds passwords and API keys", _env_file),
    ("/.git/HEAD", "your site's code history (.git folder)",
     lambda b: bool(re.match(rb"^(ref: refs/|[0-9a-f]{40}\s*$)", b.strip()))),
    ("/.git/config", "your site's code history settings (.git/config)",
     lambda b: _not_html(b) and b"[core]" in b),
    ("/wp-config.php.bak", "a backup of your WordPress settings file, which holds your database password",
     lambda b: _not_html(b) and (b"DB_PASSWORD" in b or b"DB_NAME" in b)),
    ("/backup.zip", "a downloadable backup of your site", lambda b: b.startswith(b"PK\x03\x04")),
    ("/phpinfo.php", "a diagnostics page (phpinfo) that lists your server's full configuration",
     lambda b: b"phpinfo()" in b or (b"PHP Version" in b and b"PHP License" in b)),
    ("/.DS_Store", "a Mac folder-index file (.DS_Store) that lists your site's hidden file names",
     lambda b: b[4:8] == b"Bud1"),
)


def sensitive_file_finding(path, description, platform):
    return _finding(
        "Exposed Sensitive File",
        f"Anyone can download {description} from your site at {path}. That can hand an "
        "attacker passwords, keys or a map of your site. Remove the file from the web server "
        "(or block it), and change any passwords or keys it contains — assume they're "
        f"already known.{_platform_hint(platform, 'files')}",
        HIGH, WHO_WEB_PERSON, evidence=path,
    )


# ---------------------------------------------------------------------------
# Page-content signals.
# ---------------------------------------------------------------------------

def looks_like_directory_listing(title, html):
    t = (title or "").strip().lower()
    return t.startswith("index of /") or t.startswith("directory listing for /") or bool(
        re.search(r"<h1>\s*(index of|directory listing for) /", html or "", re.I)
    )


_RAW_ERROR_SIGNATURES = (
    r"<hr>\s*<center>\s*nginx", r"<address>Apache/[\d.]+", r"Apache/[\d.]+ \([^)]*\) Server at",
    r"<h2>404 - File or directory not found\.</h2>", r"Error response</h1>\s*<p>Error code: 404",
    r"<title>404 Not Found</title>\s*</head>\s*<body>\s*<h1>Not Found</h1>",
    r"Whitelabel Error Page", r"<center><h1>404 Not Found</h1></center>",
)


def looks_like_raw_server_error(html):
    return any(re.search(p, html or "", re.I) for p in _RAW_ERROR_SIGNATURES)


class _MetaRefreshParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refresh = []
        self.inline_scripts = []
        self._in_script = False
        self._script_has_src = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "meta" and (a.get("http-equiv") or "").lower() == "refresh":
            self.refresh.append(a.get("content") or "")
        if tag == "script":
            self._in_script = True
            self._script_has_src = bool(a.get("src"))
            if not self._script_has_src:
                self.inline_scripts.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and not self._script_has_src and self.inline_scripts:
            self.inline_scripts[-1] += data


def parse_page_source(html):
    p = _MetaRefreshParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    return p.refresh, p.inline_scripts


def _registrable(host, registrable_domain):
    return registrable_domain(host or "") if host else ""


def offsite_meta_refresh(refresh_values, page_url, site_domain, registrable_domain):
    for content in refresh_values:
        m = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.I)
        if not m:
            continue
        target = urljoin(page_url, m.group(1))
        host = urlparse(target).hostname
        if host and _registrable(host, registrable_domain) != site_domain:
            return target
    return None


_JS_REDIRECT_RE = re.compile(
    r"(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*['\"](https?://[^'\"]+)",
    re.I,
)


def offsite_js_redirects(inline_scripts, site_domain, registrable_domain):
    targets = []
    for script in inline_scripts:
        for m in _JS_REDIRECT_RE.finditer(script):
            host = urlparse(m.group(1)).hostname
            if host and _registrable(host, registrable_domain) != site_domain:
                targets.append(m.group(1))
    return targets


_OBFUSCATION_EXEC_RE = re.compile(r"\beval\s*\(|new\s+Function\s*\(|document\.write\s*\(\s*unescape", re.I)
_OBFUSCATION_DECODE_RE = re.compile(r"atob\s*\(|unescape\s*\(|String\.fromCharCode|\\x[0-9a-f]{2}", re.I)
_ENCODED_RUN_RE = re.compile(r"(?:[A-Za-z0-9+/]{300,}={0,2})|(?:(?:\\x[0-9a-fA-F]{2}){80,})|(?:(?:%[0-9a-fA-F]{2}){100,})")


def obfuscated_inline_scripts(inline_scripts):
    """Inline scripts that decode a large hidden blob and execute it — the
    shape injected malware usually takes. Ordinary minified code doesn't
    combine all three (execute + decode + a long encoded run)."""
    return [
        s for s in inline_scripts
        if _OBFUSCATION_EXEC_RE.search(s) and _OBFUSCATION_DECODE_RE.search(s) and _ENCODED_RUN_RE.search(s)
    ]


SPAM_KEYWORDS_RE = re.compile(
    r"\b(viagra|cialis|levitra|casino|slot gacor|judi online|togel|payday loans?|replica watches|"
    r"porn|xxx|escort service|cheap essays?|buy followers)\b",
    re.I,
)

HIDDEN_LINKS_JS = """() => {
  const out = [];
  const hidden = (el) => {
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity) === 0) return true;
      if (parseFloat(s.fontSize) === 0) return true;
      const r = n.getBoundingClientRect();
      if (s.position === 'absolute' && (r.right < -500 || r.bottom < -500 || r.left > 10000)) return true;
    }
    return false;
  };
  for (const a of document.querySelectorAll('a[href]')) {
    if (out.length >= 200) break;
    if (hidden(a)) out.push({href: a.href, text: (a.textContent || '').trim().slice(0, 120)});
  }
  return out;
}"""


def hidden_spam_links(hidden_links, site_domain, registrable_domain):
    spam = []
    for link in hidden_links or []:
        host = urlparse(link.get("href") or "").hostname
        if not host or _registrable(host, registrable_domain) == site_domain:
            continue
        if SPAM_KEYWORDS_RE.search(link.get("text") or "") or SPAM_KEYWORDS_RE.search(link.get("href") or ""):
            spam.append(link)
    return spam if len(spam) >= 2 else []


def _words(text):
    return set(re.findall(r"[a-z]{3,}", (text or "").lower()))


def html_to_text(html):
    html = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html or "")
    return re.sub(r"<[^>]+>", " ", html)


def cloaked_spam(server_html, rendered_text):
    """Server HTML carrying spam words that a real browser never shows,
    on a page where what the server sent and what renders barely overlap.
    Both conditions, not just one: plenty of honest sites render very
    differently from their raw HTML (app-style sites built in the
    browser), so a difference alone proves nothing."""
    server_words = _words(html_to_text(server_html))
    rendered_words = _words(rendered_text)
    if len(server_words) < 50 or len(rendered_words) < 20:
        return []
    overlap = len(server_words & rendered_words) / max(len(server_words), 1)
    if overlap >= 0.3:
        return []
    only_server = " ".join(sorted(server_words - rendered_words))
    return sorted({m.group(0).lower() for m in SPAM_KEYWORDS_RE.finditer(only_server)})


def hacked_finding(kind, detail):
    return _finding(
        "Site May Be Hacked",
        f"We found a sign your site may have been hacked: {detail} This is a common pattern "
        "for break-ins that use your site to promote spam or send visitors elsewhere. Ask your "
        "web person to check it today, change your site and hosting passwords, and restore "
        "from a clean backup if it's confirmed.",
        HIGH, f"{WHO_WEB_PERSON} and {WHO_HOST}", confidence=NEEDS_LOOK, evidence=kind,
    )


# ---------------------------------------------------------------------------
# Third-party scripts.
# ---------------------------------------------------------------------------

CDN_HOSTS = {
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "code.jquery.com",
    "ajax.googleapis.com", "ajax.aspnetcdn.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "cdn.datatables.net", "cdn.rawgit.com", "rawgit.com",
    "cdn.statically.io",
}

_dns_cache = {}


def host_resolves(host):
    """True / False (definitely doesn't exist) / None (couldn't tell)."""
    if host not in _dns_cache:
        try:
            socket.getaddrinfo(host, None)
            _dns_cache[host] = True
        except socket.gaierror as e:
            no_such = getattr(socket, "EAI_NONAME", -2), getattr(socket, "EAI_NODATA", -5)
            _dns_cache[host] = False if e.errno in no_such else None
        except Exception:
            _dns_cache[host] = None
    return _dns_cache[host]


def unresolvable_script_finding(host):
    return _finding(
        "Script From A Domain That No Longer Exists",
        f"Your site loads code from {host}, but that address no longer exists on the internet. "
        "If its domain has expired, anyone could register it and run their own code on your "
        "pages. Remove the script tag, or point it at a working source.",
        HIGH, WHO_WEB_PERSON, confidence=NEEDS_LOOK, evidence=host,
    )


def missing_sri_finding(srcs):
    return _finding(
        "Shared-Server Scripts Without Integrity Check",
        f"Your site loads {len(srcs)} script(s) from shared public code servers without an "
        "\"integrity\" check (e.g. "
        + ", ".join(s.rsplit("/", 1)[-1] for s in srcs[:3])
        + "). If that server were ever tampered with, the changed code would run on your site "
        "unnoticed. Adding the integrity attribute makes the browser refuse altered files.",
        LOW, WHO_WEB_PERSON, evidence="|".join(sorted(srcs)),
    )


# ---------------------------------------------------------------------------
# WordPress versions.
# ---------------------------------------------------------------------------

_WP_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)', re.I)
_WP_CORE_ASSET_RE = re.compile(r"wp-(?:emoji-release\.min\.js|includes/css/dist/block-library/style\.min\.css)\?ver=([\d.]+)")
_WP_PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9\-_]+)/[^\"'\s?]+\?ver=([\d.]+)", re.I)


def wordpress_versions(html):
    """({core_version, from_generator}, {plugin_slug: version})."""
    core, exact = None, False
    m = _WP_GENERATOR_RE.search(html or "")
    if m:
        core, exact = m.group(1), True
    else:
        m = _WP_CORE_ASSET_RE.search(html or "")
        core = m.group(1) if m else None
    plugins = {}
    for slug, ver in _WP_PLUGIN_RE.findall(html or ""):
        plugins.setdefault(slug.lower(), ver)
    return {"version": core, "from_generator": exact}, plugins


def wordpress_findings(html):
    """(findings, notes)."""
    findings, notes = [], []
    core, plugins = wordpress_versions(html)
    core_data = (load_data("wordpress_core.json") or {}).get("versions") or {}
    if core["version"]:
        status = core_data.get(core["version"])
        confidence = VERIFIED if core["from_generator"] else NEEDS_LOOK
        latest = next((v for v, s in core_data.items() if s == "latest"), None)
        if status == "insecure":
            findings.append(_finding(
                "WordPress Version Has Known Security Problems",
                f"Your site runs WordPress {core['version']}, which WordPress.org itself lists as "
                f"insecure — there are published security fixes it doesn't have. Update WordPress "
                f"to the latest version ({latest or 'see wordpress.org'}) from your WordPress "
                "dashboard, after taking a backup.",
                HIGH, WHO_WEB_PERSON, confidence=confidence, evidence=f"wordpress@{core['version']}",
            ))
        elif status == "outdated":
            findings.append(_finding(
                "WordPress Out Of Date",
                f"Your site runs WordPress {core['version']}; the latest is {latest}. It has no "
                "known security problems yet, but older versions stop getting fixes. Update from "
                "your WordPress dashboard after taking a backup.",
                MEDIUM, WHO_WEB_PERSON, confidence=confidence, evidence=f"wordpress@{core['version']}",
            ))
        elif status is None:
            notes.append(
                f"We saw WordPress version {core['version']} but couldn't find it in our bundled "
                "list of WordPress releases, so we couldn't tell whether it's up to date."
            )
    plugin_data = (load_data("wordpress_plugins.json") or {}).get("plugins") or {}
    outdated = []
    for slug, ver in sorted(plugins.items()):
        info = plugin_data.get(slug)
        if info and compare_versions(ver, info["latest"]) < 0:
            outdated.append(f"{info['name']} {ver} (latest {info['latest']})")
    if outdated:
        findings.append(_finding(
            "WordPress Plugins Out Of Date",
            f"{len(outdated)} WordPress plugin(s) on your site look out of date: "
            f"{'; '.join(outdated[:5])}{' …' if len(outdated) > 5 else ''}. Out-of-date plugins "
            "are the most common way WordPress sites get broken into. Update them from the "
            "Plugins screen in your dashboard, after taking a backup.",
            MEDIUM, WHO_WEB_PERSON, confidence=NEEDS_LOOK, evidence="|".join(sorted(outdated)),
        ))
    if plugins:
        notes.append(
            "We compared your WordPress plugins against their latest released versions, but we "
            "don't have a list of known plugin security problems bundled yet, so we couldn't "
            "check them for specific known vulnerabilities."
        )
    return findings, notes


# ---------------------------------------------------------------------------
# Certificate.
# ---------------------------------------------------------------------------

_CERT_PROBLEMS = {
    9: ("is not valid yet", "Your site's security certificate isn't valid yet"),
    10: ("has expired", "Your site's security certificate has expired"),
    18: ("is self-signed", "Your site's security certificate is self-signed (not issued by a trusted authority)"),
    19: ("is self-signed", "Your site's security certificate chain includes a self-signed certificate"),
    20: ("chain is incomplete", "Your site's security certificate chain is incomplete"),
    21: ("chain is incomplete", "Your site's security certificate chain is incomplete"),
    62: ("doesn't match", "Your site's security certificate is for a different address"),
}


def check_certificate(host, port=443, timeout=PROBE_TIMEOUT_SECONDS, cafile=None):
    """Opens the same TLS connection an https:// GET does, sends that GET,
    and reports what the certificate looked like. Returns
    {"ok": bool, "problem": str|None, "message": str|None, "days_left": int|None, "error": str|None}."""
    ctx = ssl.create_default_context(cafile=cafile or certifi.where())
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                tls.sendall(
                    f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: GetBuggyBot/1.0\r\n"
                    "Connection: close\r\n\r\n".encode()
                )
                try:
                    tls.recv(512)
                except (OSError, ssl.SSLError):
                    pass
        not_after = (cert or {}).get("notAfter")
        days_left = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400) if not_after else None
        return {"ok": True, "problem": None, "message": None, "days_left": days_left, "error": None}
    except ssl.SSLCertVerificationError as e:
        problem, message = _CERT_PROBLEMS.get(
            getattr(e, "verify_code", None),
            ("isn't trusted", "Browsers don't trust your site's security certificate"),
        )
        return {"ok": False, "problem": problem, "message": message, "days_left": None,
                "error": getattr(e, "verify_message", str(e))}
    except (OSError, ssl.SSLError) as e:
        return {"ok": None, "problem": None, "message": None, "days_left": None, "error": e.__class__.__name__}


def certificate_findings(cert, platform=None):
    if cert["ok"] is False:
        return [_finding(
            "Security Certificate Problem",
            f"{cert['message']}. Visitors' browsers show a full-page \"Your connection is not "
            "private\" warning instead of your site, and most people leave. Your host or "
            "whoever set up the certificate can reissue it — many hosts do it free."
            f"{_platform_hint(platform, 'transport')}",
            HIGH, WHO_HOST, evidence=cert["problem"],
        )]
    if cert["ok"] and cert["days_left"] is not None and cert["days_left"] < 30:
        days = cert["days_left"]
        return [_finding(
            "Security Certificate Expiring Soon",
            f"Your site's security certificate expires in {days} day(s). When it does, visitors "
            "will see a full-page security warning instead of your site. Ask your host to renew "
            "it (or check that automatic renewal is actually working).",
            HIGH if days < 14 else MEDIUM, WHO_HOST, evidence="expiring",
        )]
    return []


# ---------------------------------------------------------------------------
# Small HTML helpers for the homepage.
# ---------------------------------------------------------------------------

class _LinkTagParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.icons, self.manifests = [], []

    def handle_starttag(self, tag, attrs):
        if tag != "link":
            return
        a = dict(attrs)
        rel = (a.get("rel") or "").lower().split()
        href = a.get("href")
        if not href:
            return
        if "icon" in rel:
            self.icons.append(href)
        if "manifest" in rel:
            self.manifests.append(href)


def head_links(html):
    p = _LinkTagParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    return p.icons, p.manifests


def _other_www_host(host):
    if not host or re.match(r"^[\d.]+$", host) or ":" in host:
        return None
    return host[4:] if host.startswith("www.") else f"www.{host}"


# ---------------------------------------------------------------------------
# The site-level pass: one run per crawl, against the URL the user pasted.
# ---------------------------------------------------------------------------

def run_site_security_pass(homepage_url, is_safe, headers, robots_status=None):
    """Returns {"findings", "notes", "platform", "probes", "favicon_ico_ok",
    "homepage_ok"}. Findings already carry `group: security` where they're
    exposures; the rest are ordinary public findings."""
    out = {"findings": [], "notes": [], "platform": None, "probes": [],
           "favicon_ico_ok": False, "homepage_ok": False}
    if security_checks_skipped():
        out["notes"].append(
            "Security and site-setup checks were switched off on this server for this run, so "
            "none of them ran."
        )
        return out

    deadline = time.time() + SITE_PASS_BUDGET_SECONDS
    log = out["probes"]
    findings, notes = out["findings"], out["notes"]
    parsed = urlparse(homepage_url)
    host, scheme = parsed.hostname, parsed.scheme
    root = f"{scheme}://{parsed.netloc}/"
    is_https = scheme == "https"

    def get(url, follow=False, max_bytes=PROBE_MAX_BYTES):
        return fetch(url, is_safe, headers, follow=follow, max_bytes=max_bytes, log=log)

    home = get(homepage_url, follow=True, max_bytes=HOMEPAGE_MAX_BYTES)
    html = home.text() if home.status else ""
    out["homepage_ok"] = home.status is not None and home.status < 400
    platform = detect_platform(html, home.headers)
    out["platform"] = platform

    # robots.txt erroring: Google treats a 5xx robots.txt as "keep out of
    # the whole site" until it recovers.
    if robots_status is not None and robots_status >= 500:
        findings.append(_finding(
            "robots.txt Is Erroring",
            f"Your site's robots.txt file answers with a server error (HTTP {robots_status}). "
            "Google treats that as \"stay out of the whole site\" until it's fixed, so your pages "
            "can drop out of search results. Ask your web person or host to make robots.txt load "
            "normally (or return 'not found').",
            HIGH, f"{WHO_WEB_PERSON} or {WHO_HOST}", security=False,
        ))

    if out["homepage_ok"]:
        findings.extend(analyze_security_headers(home.headers, is_https, platform))

    tasks = {}
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_PROBES) as pool:
        for path, _desc, _check in SENSITIVE_FILES:
            tasks[("file", path)] = pool.submit(get, urljoin(root, path))
        missing_url = urljoin(root, f"/getbuggy-missing-{uuid.uuid4().hex[:10]}")
        tasks[("missing", None)] = pool.submit(get, missing_url)
        icons, manifests = head_links(html)
        icon = next((i for i in icons if not i.startswith("data:")), None)
        if icon or not icons:
            tasks[("favicon", None)] = pool.submit(get, urljoin(home.final_url, icon or "/favicon.ico"))
        if manifests:
            tasks[("manifest", None)] = pool.submit(get, urljoin(home.final_url, manifests[0]))
        if platform == "WordPress":
            tasks[("wp", "xmlrpc")] = pool.submit(get, urljoin(root, "/xmlrpc.php"))
            tasks[("wp", "users")] = pool.submit(get, urljoin(root, "/wp-json/wp/v2/users"))
            tasks[("wp", "author")] = pool.submit(get, urljoin(root, "/?author=1"))
        if is_https:
            tasks[("http_root", None)] = pool.submit(get, f"http://{parsed.netloc}/")
        else:
            tasks[("https_root", None)] = pool.submit(get, f"https://{parsed.netloc}/")
        other = _other_www_host(host)
        if other:
            tasks[("www", other)] = pool.submit(get, f"{scheme}://{other}/")
        cert_task = pool.submit(check_certificate, host, parsed.port or 443) if is_https else None

        results = {}
        for key, fut in tasks.items():
            try:
                results[key] = fut.result(timeout=max(1, deadline - time.time()))
            except Exception:
                results[key] = None
                notes.append("One of the site-setup checks ran out of time and was skipped.")
        cert = None
        if cert_task:
            try:
                cert = cert_task.result(timeout=max(1, deadline - time.time()))
            except Exception:
                cert = None

    unchecked = 0
    for path, desc, check in SENSITIVE_FILES:
        probe = results.get(("file", path))
        if probe is None or probe.status is None:
            unchecked += 1
        elif probe.status == 200 and check(probe.body):
            findings.append(sensitive_file_finding(path, desc, platform))
    if unchecked:
        notes.append(
            f"We couldn't reach {unchecked} of the {len(SENSITIVE_FILES)} addresses where sites "
            "most often leave private files exposed, so those weren't checked."
        )

    missing = results.get(("missing", None))
    if missing is None or missing.status is None:
        notes.append("We couldn't check how your site answers addresses that don't exist.")
    elif missing.status == 200:
        findings.append(_finding(
            "Missing Pages Don't Say \"Not Found\"",
            "When someone visits an address on your site that doesn't exist, your server answers "
            "as if it were a real page instead of saying \"not found\". Google can end up listing "
            "junk addresses as real pages, and visitors never learn the link was wrong. Ask your "
            "web person to make missing pages return a proper 404 \"not found\" response.",
            MEDIUM, WHO_WEB_PERSON, security=False,
        ))
    elif missing and missing.status and missing.status >= 400 and looks_like_raw_server_error(missing.text()):
        findings.append(_finding(
            "Plain Server Error Page",
            "When a visitor hits a missing page, they see your server's bare built-in error page "
            "rather than one that matches your site, with no way back to your homepage. A "
            "friendly custom \"page not found\" page keeps them on your site.",
            LOW, WHO_WEB_PERSON, security=False,
        ))

    fav = results.get(("favicon", None))
    if fav is not None:
        if icon and fav.status != 200 and fav.error != "unsafe":
            findings.append(_finding(
                "Favicon Doesn't Load",
                "Your pages point to a favicon (the little icon in the browser tab), but that file "
                "doesn't load, so browsers show a blank icon instead.",
                LOW, WHO_WEB_PERSON, security=False,
            ))
        if not icon and fav.status == 200:
            out["favicon_ico_ok"] = True

    man = results.get(("manifest", None))
    if man is not None and man.status != 200 and man.error != "unsafe":
        findings.append(_finding(
            "Web App Manifest Missing",
            "Your pages point to a web app manifest (the file phones use when someone adds your "
            "site to their home screen), but that file doesn't load. Home-screen shortcuts will "
            "fall back to a generic name and icon.",
            LOW, WHO_WEB_PERSON, security=False,
        ))

    if platform == "WordPress":
        xmlrpc = results.get(("wp", "xmlrpc"))
        if xmlrpc and xmlrpc.status in (200, 405) and b"XML-RPC server accepts POST requests only" in xmlrpc.body:
            findings.append(_finding(
                "WordPress XML-RPC Is Open",
                "Your WordPress site's XML-RPC feature (xmlrpc.php) is switched on. Almost no "
                "modern site needs it, and attackers use it to try thousands of passwords at once. "
                "A security plugin or your host can switch it off.",
                MEDIUM, WHO_WEB_PERSON,
            ))
        exposed = []
        users = results.get(("wp", "users"))
        if users and users.status == 200:
            try:
                data = json.loads(users.text())
                if isinstance(data, list) and any(isinstance(u, dict) and u.get("slug") for u in data):
                    exposed.append("/wp-json/wp/v2/users")
            except ValueError:
                pass
        author = results.get(("wp", "author"))
        if author and author.status in (301, 302) and "/author/" in (author.headers.get("location") or ""):
            exposed.append("/?author=1")
        if exposed:
            findings.append(_finding(
                "WordPress Usernames Are Public",
                "Anyone can look up the login usernames on your WordPress site (via "
                f"{' and '.join(exposed)}). That gives attackers half of what they need to break "
                "in. A security plugin can hide them; also make sure every account has a strong, "
                "unique password.",
                MEDIUM, WHO_WEB_PERSON, evidence="|".join(exposed),
            ))
        wp_findings, wp_notes = wordpress_findings(html)
        findings.extend(wp_findings)
        notes.extend(wp_notes)

    transport_hint = _platform_hint(platform, "transport")
    if is_https:
        http_root = results.get(("http_root", None))
        if http_root and http_root.status == 200:
            findings.append(_finding(
                "Insecure Version Of Site Doesn't Redirect",
                f"Typing your address without https:// (http://{host}) opens an unprotected copy "
                "of your site instead of sending visitors to the secure one. Anything they type "
                "there — including contact or payment details — travels unencrypted. Ask your host "
                f"to redirect all http:// traffic to https://.{transport_hint}",
                HIGH, WHO_HOST,
            ))
        if cert:
            findings.extend(certificate_findings(cert, platform))
        elif cert is None:
            notes.append("We couldn't connect to check your site's security certificate.")
    else:
        https_root = results.get(("https_root", None))
        has_https = https_root is not None and https_root.status is not None and https_root.status < 400
        findings.append(_finding(
            "Site Doesn't Use HTTPS",
            (f"Your site works at https://{host}, but visitors who go to http://{host} stay on "
             "the unprotected version." if has_https else
             f"Your site ({host}) doesn't offer a secure https:// connection.")
            + " Browsers label it \"Not secure\", and anything visitors type travels unencrypted. "
            f"Ask your host to turn on HTTPS (usually free) and redirect everyone to it.{transport_hint}",
            HIGH, WHO_HOST,
        ))

    if other:
        www = results.get(("www", other))
        if www and www.status == 200 and b"<" in www.body[:2048]:
            findings.append(_finding(
                "Site Answers On Both www And Non-www",
                f"Your site loads both at {host} and at {other} without sending one to the other. "
                "Google can treat them as two copies of the same site, splitting your search "
                "ranking. Ask your web person or host to redirect one to the other.",
                LOW, f"{WHO_WEB_PERSON} or {WHO_HOST}", security=False,
            ))

    notes.append(
        "We don't test which older encryption versions (TLS 1.0/1.1) your server still accepts — "
        "that needs connection attempts beyond the plain page requests we limit ourselves to."
    )
    safe_browsing(homepage_url, findings, notes)
    return out


def safe_browsing(url, findings, notes):
    key = os.environ.get(SAFE_BROWSING_KEY_ENV_VAR, "").strip()
    if not key:
        notes.append(
            "We didn't check Google's list of known dangerous sites (Safe Browsing isn't set up "
            "on this server)."
        )
        return
    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json={
                "client": {"clientId": "getbuggy", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                    "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=PROBE_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        if resp.json().get("matches"):
            findings.append(hacked_finding(
                "safe-browsing",
                "Google Safe Browsing lists your site as dangerous, so Chrome and other browsers may "
                "be showing visitors a red warning page instead of your site.",
            ))
    except (requests.RequestException, ValueError):
        notes.append("We couldn't reach Google Safe Browsing to check whether your site is listed as dangerous.")


# ---------------------------------------------------------------------------
# The per-page pass: runs against a page the browser already loaded.
# ---------------------------------------------------------------------------

MAX_SCRIPT_BODIES = 20
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_SOURCE_MAP_PROBES = 3


def check_page_security(page, main_response, script_responses, problems, could_not_check,
                        site_domain, is_safe, headers, registrable_domain, site_is_https=None,
                        extras=None):
    """Per-page checks against an already-loaded page. `script_responses`
    is the list of Playwright script responses the page loaded (captured
    by core's response listener) — read in place, no extra download."""
    if security_checks_skipped():
        return
    try:
        _check_page_security(page, main_response, script_responses, problems, could_not_check,
                             site_domain, is_safe, headers, registrable_domain, site_is_https, extras)
    except Exception as e:
        could_not_check.append(
            f"The security checks on this page couldn't finish ({e.__class__.__name__})."
        )


def _check_page_security(page, main_response, script_responses, problems, could_not_check,
                         site_domain, is_safe, headers, registrable_domain, site_is_https, extras):
    page_url = page.url
    try:
        server_html = main_response.text() if main_response is not None else ""
    except Exception:
        server_html = ""
    rendered_html = page.content()
    title = page.title()

    if site_is_https and page_url.startswith("http://"):
        problems.append(_finding(
            "Page Not On HTTPS",
            "This page opens over an unprotected http:// connection even though the rest of your "
            "site is secure. Browsers mark it \"Not secure\". Ask your web person to link to and "
            "redirect it to the https:// version.",
            MEDIUM, WHO_WEB_PERSON, evidence=page_url,
        ))

    if looks_like_directory_listing(title, rendered_html):
        problems.append(_finding(
            "Folder Contents Are Public",
            "This address shows a raw list of the files in one of your site's folders. That can "
            "expose files you never meant to publish (backups, drafts, private documents). Ask "
            "your web person or host to switch off \"directory listing\".",
            MEDIUM, f"{WHO_WEB_PERSON} or {WHO_HOST}", evidence=page_url,
        ))

    # Secrets: the server's HTML, the live page, and the page's own scripts.
    secret_hits = find_secrets(server_html) + find_secrets(rendered_html)
    first_party_bodies = []
    third_party_hosts = set()
    detected_libs = set()
    for resp in script_responses[:MAX_SCRIPT_BODIES * 3]:
        url = resp.url
        host = urlparse(url).hostname or ""
        detected_libs |= detect_libraries_from_url(url)
        same_site = _registrable(host, registrable_domain) == site_domain
        if not same_site and host:
            third_party_hosts.add(host)
        if len(first_party_bodies) >= MAX_SCRIPT_BODIES or not (200 <= resp.status < 300):
            continue
        try:
            body = resp.body()
        except Exception:
            continue
        if len(body) > MAX_SCRIPT_BYTES:
            continue
        text = body.decode("utf-8", errors="replace")
        detected_libs |= detect_libraries_from_content(text)
        if same_site:
            first_party_bodies.append((url, text, dict(resp.headers)))
            secret_hits += find_secrets(text)

    seen = []
    for hit in secret_hits:
        if hit not in seen:
            seen.append(hit)
    problems.extend(secret_findings(seen, "this page"))

    # Public source maps (first-party scripts only; a CDN's own maps are theirs).
    map_probes = 0
    for url, text, resp_headers in first_party_bodies:
        if map_probes >= MAX_SOURCE_MAP_PROBES:
            break
        map_url = source_map_url(url, text, resp_headers)
        if not map_url:
            continue
        map_probes += 1
        probe = fetch(map_url, is_safe, headers, max_bytes=4096)
        if probe.status == 200 and looks_like_source_map(probe.body):
            problems.append(_finding(
                "Source Code Map Files Are Public",
                "Your site publishes \"source map\" files, which hand anyone an easy-to-read copy of "
                "your site's original code, comments and all. They're for developers and usually "
                "shouldn't be on the live site. Ask your web person to stop publishing them.",
                LOW, WHO_WEB_PERSON, evidence=urlparse(map_url).path.rsplit("/", 1)[-1],
            ))
            break

    # Library versions the page itself reports (e.g. jQuery.fn.jquery).
    try:
        for lib, version in page.evaluate(LIBRARY_PROBE_JS, [list(p) for p in library_probe_expressions()]):
            if version and re.match(r"^\d+(\.\d+)*", version):
                detected_libs.add((lib, version))
    except Exception:
        pass
    problems.extend(library_findings(_collapse_versions(detected_libs)))

    # Third-party scripts: inventory, dead domains, CDN integrity.
    dom_scripts = page.evaluate(
        "() => Array.from(document.querySelectorAll('script[src]')).map(s => ({src: s.src, integrity: s.integrity || ''}))"
    )
    no_sri = []
    for s in dom_scripts:
        host = urlparse(s["src"]).hostname or ""
        if host and _registrable(host, registrable_domain) != site_domain:
            third_party_hosts.add(host)
            if host in CDN_HOSTS and not s["integrity"]:
                no_sri.append(s["src"])
    for host in sorted(third_party_hosts):
        if host_resolves(host) is False:
            problems.append(unresolvable_script_finding(host))
    if no_sri:
        problems.append(missing_sri_finding(sorted(set(no_sri))))
    if extras is not None:
        extras["third_party_scripts"] = sorted(third_party_hosts)

    # Signs of a break-in.
    refresh, inline_scripts = parse_page_source(server_html)
    target = offsite_meta_refresh(refresh, page_url, site_domain, registrable_domain)
    if target:
        problems.append(hacked_finding(
            "meta-refresh",
            f"this page automatically sends visitors to another website ({urlparse(target).hostname}).",
        ))
    js_targets = offsite_js_redirects(inline_scripts, site_domain, registrable_domain)
    if js_targets:
        problems.append(hacked_finding(
            "js-redirect",
            f"code on this page sends visitors to another website ({urlparse(js_targets[0]).hostname}).",
        ))
    if obfuscated_inline_scripts(inline_scripts):
        problems.append(hacked_finding(
            "obfuscated-script",
            "this page contains deliberately scrambled code that unpacks and runs itself — "
            "legitimate site code almost never does that.",
        ))
    try:
        spam = hidden_spam_links(page.evaluate(HIDDEN_LINKS_JS), site_domain, registrable_domain)
    except Exception:
        spam = []
    if spam:
        problems.append(hacked_finding(
            "hidden-spam-links",
            f"this page contains {len(spam)} hidden links to spam websites that visitors can't "
            "see but search engines can.",
        ))
    try:
        rendered_text = page.inner_text("body")
    except Exception:
        rendered_text = ""
    spam_words = cloaked_spam(server_html, rendered_text)
    if spam_words:
        problems.append(hacked_finding(
            "cloaked-content",
            "the page your server sends contains spam text (e.g. "
            f"\"{spam_words[0]}\") that never shows up for a real visitor.",
        ))


def _collapse_versions(detected):
    """One version per library — the same file can match several patterns
    with slightly different captures ("3.5.1" and "3.5.1.min")."""
    best = {}
    for lib, version in detected:
        m = re.match(r"^\d[\d.]*(?:-[\w.]+)?", version)
        version = m.group(0).rstrip(".") if m else None
        if version and (lib not in best or len(version) > len(best[lib])):
            best[lib] = version
    return set(best.items())
