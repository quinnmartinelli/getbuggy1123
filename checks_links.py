"""Link extraction, classification and checking (GetBuggy Step 4).

Replaces the old one-link-at-a-time loop in `core._check_single_page`:
links are read from the *rendered* DOM after the network goes idle (so
links that only exist once scripts run are seen), diffed against the raw
server HTML, classified (internal / external / download / in-page anchor /
javascript placeholder / social profile), and the ones that need a network
probe are checked in parallel with one crawl-wide cache so a nav link that
appears on every page is only fetched once per crawl.

Self-contained like `checks_seo.py`: appends finding dicts to the shared
`problems` list, keeps its own severity constants, and imports nothing from
`core.py` (core imports this module). Anything that needs `core`'s SSRF
guard or browser headers receives it as an argument instead.
"""
import concurrent.futures
import re
import threading
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from crawl_utils import (
    clean_url,
    is_hash_route,
    is_same_site,
    page_key,
    registrable_domain,
)

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
VERIFIED = "verified"
NEEDS_LOOK = "needs_look"

MAX_LINKS_PER_PAGE = 100
MAX_BROWSER_RECHECKS_PER_PAGE = 5
PROBE_WORKERS = 8
PROBE_TIMEOUT_SECONDS = 5
MAX_REDIRECTS = 5
REDIRECT_CHAIN_FLAG_AT = 3
NETWORK_IDLE_WAIT_MS = 4000

# "Under 20% of the rendered set" (Step 4 spec) — with a small floor so a
# page with three links total doesn't trip it.
STATIC_LINK_SHARE_THRESHOLD = 0.20
MIN_RENDERED_LINKS_FOR_STATIC_DIFF = 5

SOCIAL_DOMAINS = {
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "tiktok.com", "youtube.com", "youtu.be", "pinterest.com", "threads.net",
    "snapchat.com", "reddit.com", "t.me", "fb.com",
}
# Share buttons and embeds are actions, not profile pages — never probed as
# "is this profile alive".
_SOCIAL_NON_PROFILE_RE = re.compile(
    r"^/(sharer|share|intent|dialog|plugins|hashtag|watch|embed|tr|login|oauth|events)\b", re.I
)

# Sites that routinely answer automated requests with 403/429 no matter
# what — a real visitor's browser is fine. Tolerated rather than reported.
KNOWN_BOT_BLOCKING_DOMAINS = SOCIAL_DOMAINS | {
    "google.com", "goo.gl", "amazon.com", "amzn.to", "cloudflare.com",
    "medium.com", "quora.com", "yelp.com", "tripadvisor.com", "ebay.com",
    "walmart.com", "etsy.com", "glassdoor.com", "indeed.com", "zillow.com",
    "nytimes.com", "wsj.com", "bloomberg.com", "paypal.com", "shopify.com",
}
BOT_BLOCK_STATUSES = {403, 406, 429, 999}

DOWNLOAD_EXTENSIONS = {
    ".pdf", ".zip", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
    ".dmg", ".exe", ".msi", ".apk", ".mp3", ".mp4", ".mov", ".rar", ".7z",
}

VAGUE_LINK_TEXTS = {"click here", "here", "read more", "more", "this link", "link", "click"}
_BARE_URL_RE = re.compile(r"^(https?://|www\.)\S+$", re.I)

RENDERED_LINKS_JS = """
() => {
  const navSel = 'nav, header, [role="navigation"]';
  const links = [...document.querySelectorAll('a[href]')].slice(0, 3000).map(a => {
    const img = a.querySelector('img[alt]');
    return {
      href: a.getAttribute('href'),
      resolved: a.href,
      text: (a.innerText || a.textContent || '').trim().slice(0, 200),
      aria: (a.getAttribute('aria-label') || '').trim() || (img ? (img.getAttribute('alt') || '').trim() : ''),
      download: a.hasAttribute('download'),
      inNav: !!a.closest(navSel),
    };
  });
  const ids = new Set([...document.querySelectorAll('[id]')].map(e => e.id));
  document.querySelectorAll('a[name]').forEach(a => ids.add(a.getAttribute('name')));
  return { links, ids: [...ids] };
}
"""


def extract_rendered_links(page, wait_for_idle=True):
    """Links (and every id on the page) from the live DOM. Waits for the
    network to go quiet first, but never longer than NETWORK_IDLE_WAIT_MS —
    a page with a chat widget that polls forever must not stall the crawl."""
    if wait_for_idle:
        try:
            page.wait_for_load_state("networkidle", timeout=NETWORK_IDLE_WAIT_MS)
        except Exception:
            pass
    return page.evaluate(RENDERED_LINKS_JS)


class _StaticLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)


def extract_static_links(html, base_url):
    """Distinct link identities (see crawl_utils.page_key) present in the
    raw server HTML — what a visitor or search engine sees *without*
    running scripts."""
    parser = _StaticLinkParser()
    try:
        parser.feed(html or "")
    except Exception:
        pass
    return _http_keys(parser.hrefs, base_url)


def _http_keys(hrefs, base_url):
    keys = set()
    for href in hrefs:
        if not href or href.startswith(("#", "mailto:", "tel:", "sms:", "javascript:")):
            continue
        absolute = urljoin(base_url, href)
        if urlparse(absolute).scheme in ("http", "https"):
            keys.add(page_key(absolute))
    return keys


def static_share_of_rendered(static_keys, rendered_keys):
    if not rendered_keys:
        return 1.0
    return len(static_keys & rendered_keys) / len(rendered_keys)


def link_text_is_vague(text, aria_label=""):
    """'Click here', 'read more' and bare URLs tell a screen-reader user
    (and Google) nothing about where the link goes. An aria-label supplies
    the missing meaning, so those don't count."""
    if aria_label:
        return False
    t = re.sub(r"\s+", " ", (text or "").strip().lower()).strip(" .!»>→…")
    if not t:
        return False
    return t in VAGUE_LINK_TEXTS or bool(_BARE_URL_RE.match(t))


def classify_link(link, page_url, site_domain, ids):
    """One rendered link -> a kind string. Kinds: skip, hash_route,
    anchor_ok, anchor_missing, js_void, download, social, internal,
    external."""
    href = (link.get("href") or "").strip()
    resolved = link.get("resolved") or ""
    low = href.lower()

    if not href or low.startswith(("mailto:", "tel:", "sms:", "data:", "blob:")):
        return "skip"
    if low.startswith("javascript:"):
        body = re.sub(r"\s+", "", low[len("javascript:"):])
        return "js_void" if body in ("", ";", "void(0)", "void(0);", "void0", "void(0);return false") else "skip"

    if href.startswith("#"):
        frag = href[1:]
        if is_hash_route(frag):
            return "hash_route"
        return "anchor_ok" if frag in ("", "top") or frag in ids else "anchor_missing"

    parsed = urlparse(resolved)
    if parsed.scheme not in ("http", "https"):
        return "skip"
    if parsed.fragment:
        if is_hash_route(parsed.fragment):
            # "https://site/#/about" — a route inside the single page we're
            # already on (or its sibling); not a separate address to fetch.
            return "hash_route"
        if page_key(resolved) == page_key(page_url):
            return "anchor_ok" if parsed.fragment in ids else "anchor_missing"

    host_domain = registrable_domain(parsed.hostname)
    if host_domain in SOCIAL_DOMAINS and not _SOCIAL_NON_PROFILE_RE.match(parsed.path or "/"):
        if parsed.path.strip("/"):  # a bare "facebook.com" is a homepage, not a profile
            return "social"
    ext = "." + parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path.rsplit("/", 1)[-1] else ""
    if link.get("download") or ext in DOWNLOAD_EXTENSIONS:
        return "download"
    return "internal" if host_domain == site_domain else "external"


class LinkCache:
    """Results of link probes, shared by every page of one crawl (pages run
    in threads of one process). A nav/footer link on all 5 pages costs one
    request, not five — the biggest single crawl-speed win."""

    def __init__(self):
        self._lock = threading.Lock()
        self._results = {}
        self._safe_hosts = {}

    def get(self, url):
        with self._lock:
            return self._results.get(url)

    def put(self, url, result):
        with self._lock:
            self._results[url] = result

    def is_safe(self, url, guard):
        host = urlparse(url).hostname or ""
        with self._lock:
            if host in self._safe_hosts:
                return self._safe_hosts[host]
        ok = guard(url)
        with self._lock:
            self._safe_hosts[host] = ok
        return ok


def probe_url(url, headers, timeout=PROBE_TIMEOUT_SECONDS):
    """One link probe: HEAD, and for anything that looks broken a GET before
    believing it (plenty of servers refuse HEAD but serve GET fine — a
    long-standing source of false 'broken link' reports). Returns
    {"status", "hops", "error"}; `error` is one of None, "timeout",
    "too_many_redirects", or "unreachable:<ExceptionName>"."""
    try:
        with requests.Session() as s:
            s.max_redirects = MAX_REDIRECTS
            resp = s.head(url, allow_redirects=True, timeout=timeout, headers=headers)
            status, hops = resp.status_code, len(resp.history)
            if status >= 400 and status != 401:
                get = s.get(url, allow_redirects=True, timeout=timeout, headers=headers, stream=True)
                try:
                    status, hops = get.status_code, len(get.history)
                finally:
                    get.close()
            return {"status": status, "hops": hops, "error": None}
    except requests.Timeout:
        return {"status": None, "hops": 0, "error": "timeout"}
    except requests.TooManyRedirects:
        return {"status": None, "hops": MAX_REDIRECTS + 1, "error": "too_many_redirects"}
    except requests.RequestException as e:
        return {"status": None, "hops": 0, "error": f"unreachable:{e.__class__.__name__}"}


def _browser_status(page, url):
    """Second opinion through the real browser's own request context (a
    genuine browser fingerprint). Returns the status, or None if even that
    failed."""
    try:
        return page.request.head(url, timeout=10000).status
    except Exception:
        return None


def _examples(items, n=3):
    shown = ", ".join(items[:n])
    return shown + (f" (+{len(items) - n} more)" if len(items) > n else "")


def check_page_links(
    page,
    main_response,
    page_url,
    site_domain,
    problems,
    could_not_check,
    cache,
    is_safe,
    headers,
):
    """Runs every link check for one already-loaded page. `is_safe(url)` is
    core's SSRF guard, `headers` is core's browser-like request headers."""
    try:
        data = extract_rendered_links(page)
    except Exception as e:
        could_not_check.append(
            f"Couldn't read the links on this page ({e.__class__.__name__}), so links weren't checked."
        )
        return
    links, ids = data["links"], set(data["ids"])

    # --- what only exists after scripts run ---
    rendered_keys = _http_keys([l["href"] for l in links], page_url)
    try:
        static_html = main_response.text() if main_response is not None else None
    except Exception:
        static_html = None
    if static_html is None:
        could_not_check.append(
            "Couldn't compare this page's links before and after scripts run (the page's "
            "original HTML wasn't available)."
        )
    elif len(rendered_keys) >= MIN_RENDERED_LINKS_FOR_STATIC_DIFF:
        static_keys = extract_static_links(static_html, page_url)
        if static_share_of_rendered(static_keys, rendered_keys) < STATIC_LINK_SHARE_THRESHOLD:
            problems.append({
                "category": "Links Only Appear After Scripts Run",
                "message": (
                    f"Most of this page's links ({len(rendered_keys) - len(static_keys & rendered_keys)} "
                    f"of {len(rendered_keys)}) only appear after the page's scripts run — they aren't in "
                    "the page's original HTML. Search engines and some visitors' browsers may not see "
                    "them, so parts of your site may not get found. Ask your web person whether the "
                    "menu and page links can be built into the page itself."
                ),
                "severity": LOW,
                "confidence": VERIFIED,
            })

    # --- classify ---
    kinds = {}
    missing_anchors, js_void, vague = [], [], []
    hash_routes = set()
    to_probe = {}  # clean url -> (kind, original)
    for link in links:
        kind = classify_link(link, page_url, site_domain, ids)
        href = link["href"]
        if kind == "anchor_missing":
            missing_anchors.append(href)
        elif kind == "js_void":
            js_void.append(link)
        elif kind == "hash_route":
            hash_routes.add(href)
        elif kind in ("internal", "external", "download", "social"):
            url = clean_url(link["resolved"])
            if page_key(url) != page_key(page_url):
                to_probe.setdefault(url, kind)
        if kind not in ("skip",) and link_text_is_vague(link.get("text"), link.get("aria")):
            vague.append(link)
        kinds[kind] = kinds.get(kind, 0) + 1

    if len(hash_routes) >= 2:
        could_not_check.append(
            f"This page uses #-style addresses ({len(hash_routes)} different ones, like "
            f"{sorted(hash_routes)[0]}) — the sign of a single-page app. They all load the same "
            "page, so GetBuggy checks them together as one page instead of one at a time."
        )

    if missing_anchors:
        uniq = list(dict.fromkeys(missing_anchors))
        problems.append({
            "category": "Broken In-Page Link",
            "message": (
                f"{len(uniq)} link(s) on this page jump to a spot on the page that doesn't exist "
                f"({_examples(uniq)}), so clicking them does nothing. Ask your web person to fix "
                "or remove them."
            ),
            "severity": LOW,
            "confidence": VERIFIED,
            "evidence": "|".join(sorted(uniq)),
        })

    if js_void:
        problems.append({
            "category": "Placeholder Links",
            "message": (
                f"{len(js_void)} link(s) on this page use 'javascript:void(0)' instead of a real "
                "address. They only work while the page's scripts are running, can't be opened in a "
                "new tab, and search engines can't follow them. If they open a menu or a pop-up "
                "that's fine; if they're meant to go to another page, your web person should give "
                "them real addresses."
            ),
            "severity": MEDIUM,
            "confidence": NEEDS_LOOK,
        })

    if vague:
        labels = list(dict.fromkeys((l["text"] or "").strip()[:40] or "(link)" for l in vague))
        problems.append({
            "category": "Vague Link Text",
            "message": (
                f"{len(vague)} link(s) say things like {_examples([repr(x) for x in labels])} instead "
                "of describing where they go. People using screen readers, and Google, rely on the "
                "link's own words. Ask your web person to rewrite them (for example, 'Read our "
                "pricing guide' instead of 'Read more')."
            ),
            "severity": LOW,
            "confidence": VERIFIED,
            "evidence": "|".join(sorted(labels)),
        })

    # --- network probes ---
    order = {"internal": 0, "download": 1, "social": 2, "external": 3}
    urls = sorted(to_probe, key=lambda u: order[to_probe[u]])
    if len(urls) > MAX_LINKS_PER_PAGE:
        could_not_check.append(
            f"This page has {len(urls)} distinct links; only the first {MAX_LINKS_PER_PAGE} were "
            "checked to keep the check fast."
        )
        urls = urls[:MAX_LINKS_PER_PAGE]

    unsafe = [u for u in urls if not cache.is_safe(u, is_safe)]
    if unsafe:
        could_not_check.append(
            f"{len(unsafe)} link(s) point to a private/internal address and weren't checked "
            f"({_examples(unsafe)})."
        )
    urls = [u for u in urls if u not in set(unsafe)]

    pending = [u for u in urls if cache.get(u) is None]
    if pending:
        with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
            for u, res in zip(pending, ex.map(lambda x: probe_url(x, headers), pending)):
                cache.put(u, res)

    timed_out, blocked_tolerated, long_chains = [], [], []
    rechecks = 0
    for url in urls:
        kind = to_probe[url]
        res = cache.get(url)
        domain = registrable_domain(urlparse(url).hostname)
        status, error = res["status"], res["error"]

        if error == "timeout":
            timed_out.append(url)
            continue
        if error == "too_many_redirects":
            problems.append({
                "category": "Broken Link",
                "message": (
                    f"Link to {url} redirects more than {MAX_REDIRECTS} times in a row, which "
                    "browsers and search engines may give up on. Ask your web person to point it "
                    "straight at the final page."
                ),
                "severity": MEDIUM,
                "confidence": NEEDS_LOOK,
                "evidence": url,
            })
            continue
        if error:
            problems.append({
                "category": "Broken Link",
                "message": (
                    f"Link to {url} is unreachable ({error.split(':', 1)[1]}) — visitors who click "
                    "it will hit an error. Ask your web person to fix or remove it."
                ),
                "severity": MEDIUM,
                "confidence": NEEDS_LOOK,
                "evidence": url,
            })
            continue
        if status == 401:
            could_not_check.append(
                f"{url} — looks like it requires a login (HTTP 401), so we can't tell whether "
                "it's actually broken."
            )
            continue

        if res["hops"] >= REDIRECT_CHAIN_FLAG_AT:
            long_chains.append((url, res["hops"]))

        if status < 400:
            continue

        blocked = status in BOT_BLOCK_STATUSES
        known_blocker = domain in KNOWN_BOT_BLOCKING_DOMAINS
        if blocked and known_blocker and kind != "social":
            blocked_tolerated.append(url)
            continue

        # An internal link that returns 404/410 gets the same "second
        # opinion from a real browser" treatment social/blocked links
        # already get — not because we distrust the first probe, but
        # because a page the business's own site controls, confirmed
        # broken by two independent methods, deserves to be reported as
        # confirmed (HIGH/verified below), not hedged as needs_look
        # forever just because it's a "single probe from our server."
        # External links keep the single-probe needs_look treatment
        # regardless (see the final fallback below) — we have no second,
        # more-authoritative way to check someone else's site.
        if kind == "social" or blocked or (kind == "internal" and status in (404, 410)):
            # A second opinion from the real browser before saying anything.
            if rechecks >= MAX_BROWSER_RECHECKS_PER_PAGE:
                could_not_check.append(f"{url} — couldn't be confirmed (too many links to re-verify on this page).")
                continue
            rechecks += 1
            second = _browser_status(page, url)
            if second is not None and second < 400:
                continue  # fine for a real browser
            final = second if second is not None else status
            if kind == "social" and final in (404, 410) and status in (404, 410):
                problems.append({
                    "category": "Broken Social Link",
                    "message": (
                        f"Your link to {url} leads to a page that doesn't exist. A dead social "
                        "profile link makes a business look abandoned. Update it to your current "
                        "profile, or remove it. (You or your web person can fix this.)"
                    ),
                    "severity": HIGH,
                    "confidence": VERIFIED,
                    "evidence": url,
                })
            elif kind == "internal" and final in (404, 410) and status in (404, 410):
                # Confirmed by both the server probe AND a real browser —
                # this is your own site, and it's genuinely broken.
                problems.append({
                    "category": "Broken Link",
                    "message": (
                        f"Link to {url} returned HTTP {final} — confirmed with a real browser, "
                        "not just our first check. Visitors who click it hit a dead end. Ask your "
                        "web person to fix or remove it."
                    ),
                    "severity": HIGH,
                    "confidence": VERIFIED,
                    "evidence": url,
                })
            elif final in (404, 410):
                problems.append({
                    "category": "Broken Link",
                    "message": f"Link to {url} returned HTTP {final} — visitors who click it hit a dead end. Ask your web person to fix or remove it.",
                    "severity": MEDIUM,
                    "confidence": NEEDS_LOOK,
                    "evidence": url,
                })
            else:
                problems.append({
                    "category": "Link Needs A Look",
                    "message": (
                        f"We couldn't tell whether {url} works: it refused our automated check "
                        f"(HTTP {final}), even from a real browser. It's probably fine for real "
                        "visitors — click it yourself to be sure."
                    ),
                    "severity": LOW,
                    "confidence": NEEDS_LOOK,
                    "evidence": url,
                })
            continue

        problems.append({
            "category": "Broken Link",
            "message": f"Link to {url} returned HTTP {status} — visitors who click it hit a dead end. Ask your web person to fix or remove it.",
            "severity": MEDIUM,
            "confidence": NEEDS_LOOK,
            "evidence": url,
        })

    if long_chains:
        problems.append({
            "category": "Redirect Chain",
            "message": (
                f"{len(long_chains)} link(s) on this page pass through {REDIRECT_CHAIN_FLAG_AT} or "
                f"more redirects before reaching their page ({_examples([f'{u} ({h} hops)' for u, h in long_chains])}). "
                "Each hop slows the visitor down a little. Ask your web person to link straight to "
                "the final address."
            ),
            "severity": LOW,
            "confidence": VERIFIED,
        })
    if timed_out:
        could_not_check.append(
            f"{len(timed_out)} link(s) timed out, so we can't tell whether they're broken "
            f"({_examples(timed_out)})."
        )
    if blocked_tolerated:
        could_not_check.append(
            f"{len(blocked_tolerated)} link(s) go to sites that block automated checks "
            f"({_examples(blocked_tolerated)}) — they're almost certainly fine for real visitors."
        )
