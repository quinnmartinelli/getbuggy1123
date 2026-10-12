"""Pure-logic helpers for the whole-site crawl (GetBuggy Step 4): URL
canonicalization, robots.txt parsing, sitemap parsing (plain, index, and
gzipped), page selection under the page cap, and the soft-404 fingerprint.

Deliberately free of any browser, network, or `core.py` dependency so all of
it is unit-testable in milliseconds (see tests/test_crawl_utils.py) and so
`core.py`/`checks_links.py` can both import it without a circular import.
Anything that has to touch the network (fetching a sitemap, probing a link)
lives in `core.py`/`checks_links.py`, where the SSRF guard also lives.
"""
import hashlib
import re
import xml.etree.ElementTree as ET
import zlib
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Query parameters that only identify *where a visitor came from*, never
# which page they're on — stripped before deduplicating URLs so a link
# with "?utm_source=newsletter" isn't counted (and checked) as a second
# copy of the same page.
TRACKING_PARAMS = {"fbclid", "gclid", "mc_cid"}
TRACKING_PREFIXES = ("utm_",)

# Suffixes where the registrable domain is three labels, not two
# ("example.co.uk" -> "example.co.uk", not "co.uk"). Not the full Public
# Suffix List — a short list of the ones small businesses actually use, so
# no new dependency. Anything missing degrades to the old last-two-labels
# behavior, never to something worse.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz", "govt.nz",
    "co.za", "org.za", "co.jp", "or.jp", "ne.jp", "co.kr", "co.in", "net.in",
    "org.in", "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.co",
    "com.sg", "com.hk", "com.tw", "com.cn", "com.tr", "com.ua", "co.il",
    "co.id", "co.th", "com.my", "com.ph", "com.vn", "com.pk", "com.ng",
}

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# File types that are downloads/assets rather than pages a person reads.
# Sitemaps sometimes list them; the crawler shouldn't spend a page-cap slot
# (a full browser load plus every check) on a PDF or an image.
NON_PAGE_EXTENSIONS = {
    ".pdf", ".zip", ".gz", ".rar", ".7z", ".tar", ".dmg", ".exe", ".msi", ".apk",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".webm", ".xml", ".json",
}

# Pages a business owner would most hate to have broken — checked first
# when the page cap forces a choice (matched on the URL path).
PRIORITY_PATH_RE = re.compile(r"(contact|pricing|book|order|shop)", re.I)

MAX_SITEMAP_BYTES = 10 * 1024 * 1024


def registrable_domain(hostname):
    """The 'site' a hostname belongs to — treats "www.x.com", "shop.x.com"
    and "x.com" as one site, and understands common two-part suffixes."""
    if not hostname:
        return ""
    host = hostname.lower().rstrip(".")
    if _IPV4_RE.match(host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def normalize_host(hostname):
    """Lowercased host with a leading "www." dropped — 'www and apex are
    one site' for de-duplication and for 'is this another host' checks."""
    host = (hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def is_tracking_param(name):
    n = name.lower()
    return n in TRACKING_PARAMS or n.startswith(TRACKING_PREFIXES)


def is_hash_route(fragment):
    """'#/about' and '#!/about' are single-page-app routes, not
    in-page anchors: the whole 'site' is one real page as far as a
    server (and this crawler) can tell."""
    return bool(fragment) and (fragment.startswith("/") or fragment.startswith("!/"))


def clean_url(url):
    """The URL we'd actually visit: fragment dropped (so '#section' and
    hash routes collapse into the same page) and tracking parameters
    removed. Host/scheme/path stay exactly as written."""
    p = urlparse(url.strip())
    query = urlencode([(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                       if not is_tracking_param(k)])
    return urlunparse((p.scheme, p.netloc, p.path, p.params, query, ""))


def page_key(url):
    """Identity of a page for de-duplication: ignores scheme (http vs
    https of one page), a leading www., a trailing slash, the fragment,
    and tracking parameters. Never used as the URL to fetch — see
    clean_url for that."""
    p = urlparse(url.strip())
    host = normalize_host(p.hostname)
    port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
    path = p.path.rstrip("/") or "/"
    query = urlencode([(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                       if not is_tracking_param(k)])
    return f"{host}{port}{path}" + (f"?{query}" if query else "")


def is_same_site(url, site_domain):
    return registrable_domain(urlparse(url).hostname) == site_domain


def looks_like_non_page(url):
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in NON_PAGE_EXTENSIONS)


# ---------------------------------------------------------------------------
# robots.txt
# ---------------------------------------------------------------------------

def parse_robots(text):
    """Returns {"sitemaps": [...], "blocks_all_agents": bool,
    "blocks_googlebot": bool}. "Blocks" means a group for that agent
    contains `Disallow: /` (the whole site) with no `Allow: /` to undo it.
    Googlebot uses its own group if one exists, otherwise the '*' group —
    same rule real crawlers follow."""
    sitemaps = []
    groups = []
    current = None
    reading_agents = False
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "sitemap":
            if value:
                sitemaps.append(value)
        elif field == "user-agent":
            if current is None or not reading_agents:
                current = {"agents": [], "disallow": [], "allow": []}
                groups.append(current)
            current["agents"].append(value.lower())
            reading_agents = True
        elif field in ("disallow", "allow"):
            reading_agents = False
            if current is not None:
                current[field].append(value)
        else:
            reading_agents = False

    def blocks_all(group):
        return any(v in ("/", "/*") for v in group["disallow"]) and not any(
            v in ("/", "/*") for v in group["allow"]
        )

    star = any(blocks_all(g) for g in groups if "*" in g["agents"])
    google_groups = [g for g in groups if "googlebot" in g["agents"]]
    googlebot = any(blocks_all(g) for g in google_groups) if google_groups else star
    return {"sitemaps": sitemaps, "blocks_all_agents": star, "blocks_googlebot": googlebot}


# ---------------------------------------------------------------------------
# sitemaps
# ---------------------------------------------------------------------------

def sitemap_candidates(site_root, robots_sitemaps):
    """Discovery order (Step 4 spec): sitemaps named in robots.txt first
    (as one group — a robots.txt can list several), then the conventional
    locations. Returns a list of groups; the caller stops at the first
    group that yields any page URLs."""
    def at(path):
        return site_root.rstrip("/") + path

    groups = []
    if robots_sitemaps:
        groups.append(list(dict.fromkeys(robots_sitemaps)))
    for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/wp-sitemap.xml"):
        if at(path) not in (robots_sitemaps or []):
            groups.append([at(path)])
    return groups


def _gunzip_bounded(content):
    try:
        out = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(content, MAX_SITEMAP_BYTES + 1)
    except zlib.error:
        return None
    return out if len(out) <= MAX_SITEMAP_BYTES else None


def parse_sitemap(content):
    """Parses sitemap bytes (plain XML or gzipped — sniffed by magic
    number, since servers label .xml.gz files inconsistently). Returns
    ("urlset" | "sitemapindex", [loc, ...]) or None if it isn't a sitemap.
    Namespace-agnostic: the sitemap namespace URI has varied over the
    years and some sites omit it."""
    if not content:
        return None
    if content[:2] == b"\x1f\x8b":
        content = _gunzip_bounded(content)
        if content is None:
            return None
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return None
    kind = root.tag.rsplit("}", 1)[-1]
    if kind not in ("urlset", "sitemapindex"):
        return None
    locs = []
    for child in root:
        for el in child:
            if el.tag.rsplit("}", 1)[-1] == "loc" and el.text and el.text.strip():
                locs.append(el.text.strip())
                break
    return kind, locs


def classify_sitemap_urls(sitemap_urls, site_host, site_scheme):
    """Splits sitemap URLs into the ones that are on another host and the
    ones using http:// on a site that's served over https. Pure string
    logic — no fetching."""
    other_host, insecure = [], []
    for u in sitemap_urls:
        p = urlparse(u)
        if p.scheme not in ("http", "https") or not p.hostname:
            continue
        if normalize_host(p.hostname) != normalize_host(site_host):
            other_host.append(u)
        elif p.scheme == "http" and site_scheme == "https":
            insecure.append(u)
    return other_host, insecure


# ---------------------------------------------------------------------------
# page selection
# ---------------------------------------------------------------------------

def select_pages(homepage_url, nav_urls, sitemap_urls, other_urls, page_cap):
    """Chooses which pages to check when the page cap can't cover the
    whole site. Priority (Step 4 spec): homepage → primary-nav pages →
    pages whose path matches contact/pricing/book/order/shop → everything
    else in sitemap order (then any remaining homepage links).

    Every input is a list of URLs already filtered for scope/safety by the
    caller. Returns (selected, skipped, total): `total` counts every
    distinct page found, `selected` is the first `page_cap` of the
    priority order, `skipped` is the rest (still in priority order)."""
    ordered, seen = [], set()

    def add(u):
        key = page_key(u)
        if key not in seen:
            seen.add(key)
            ordered.append(u)

    add(homepage_url)
    for u in nav_urls:
        add(u)
    for u in list(sitemap_urls) + list(other_urls):
        if PRIORITY_PATH_RE.search(urlparse(u).path):
            add(u)
    for u in sitemap_urls:
        add(u)
    for u in other_urls:
        add(u)
    return ordered[:page_cap], ordered[page_cap:], len(ordered)


# ---------------------------------------------------------------------------
# soft 404
# ---------------------------------------------------------------------------

def make_fingerprint(title, text, url=""):
    """Words on the page, minus any that merely echo the page's own
    address — 404 pages often say "we couldn't find /old-service", and
    that slug must not make two identical error pages look different."""
    words = re.findall(r"[a-z0-9']+", (text or "").lower())
    if url:
        echoed = set(re.findall(r"[a-z0-9']+", urlparse(url).path.lower()))
        words = [w for w in words if w not in echoed]
    return {
        "title": (title or "").strip().lower(),
        "words": frozenset(words),
        "hash": hashlib.sha1(" ".join(words).encode()).hexdigest(),
    }


def fingerprint_similarity(a, b):
    if a["hash"] == b["hash"] and a["words"]:
        return 1.0
    union = a["words"] | b["words"]
    if not union:
        return 0.0
    return len(a["words"] & b["words"]) / len(union)


SOFT_404_SIMILARITY = 0.9


def matches_soft_404(page_fp, probe_fp):
    """(is_match, exact). A page 'matches' when it reads essentially the
    same as what the site shows for an address that cannot exist — same
    words, give or take a slug echoed back in the message."""
    if not page_fp["words"]:
        return False, False
    sim = fingerprint_similarity(page_fp, probe_fp)
    return sim >= SOFT_404_SIMILARITY, sim == 1.0
