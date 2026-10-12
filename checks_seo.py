"""SEO and basic front-end security checks: page title, meta description,
H1 heading, favicon presence, and mixed-content (http:// resources loaded
on an https:// page) detection.

Self-contained, following the same shape as core.py's img/a[href] loops at
the bottom of run_check() — operates on the already-loaded main `page`
object (no fresh navigation of its own) and appends plain-English problem
dicts ({"category", "message", "severity", "confidence"}) to the shared
`problems` list. Not yet wired into core.py's run_check() — someone else
does that.

Every check here reads a fact directly off the already-loaded DOM (a tag
is present or absent, an attribute has a value or doesn't) — there's no
timing, network-liveness, or bot-blocking involved, so every finding is
`confidence: verified`.
"""

import re

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

VERIFIED = "verified"


def _check_title(page, problems):
    """Flags a missing <title>, an empty one, or more than one in <head>.
    Title text directly drives how the page shows up as a clickable
    headline in Google search results and as the browser tab/bookmark
    name, so getting it wrong is a real (not cosmetic) SEO issue."""
    try:
        titles = page.query_selector_all("head title")

        if not titles:
            problems.append(
                {
                    "category": "Missing Page Title",
                    "message": (
                        "This page has no <title> tag. The title is what "
                        "shows up as the clickable headline in Google search "
                        "results and as the tab/bookmark name in the "
                        "browser — without one, search engines and visitors "
                        "have nothing meaningful to go on."
                    ),
                    "severity": MEDIUM,
                    "confidence": VERIFIED,
                }
            )
            return

        text = (titles[0].text_content() or "").strip()
        if not text:
            problems.append(
                {
                    "category": "Missing Page Title",
                    "message": (
                        "This page has a <title> tag, but it's empty. The "
                        "title is what shows up as the clickable headline in "
                        "Google search results and as the browser tab "
                        "name — an empty one means search engines and "
                        "visitors see nothing useful there."
                    ),
                    "severity": MEDIUM,
                    "confidence": VERIFIED,
                }
            )
        elif len(titles) > 1:
            problems.append(
                {
                    "category": "Missing Page Title",
                    "message": (
                        f"This page has {len(titles)} <title> tags instead "
                        "of one. Browsers and search engines only use one of "
                        "them, so the extra tag(s) can cause an unexpected "
                        "or inconsistent title to show up in search results "
                        "and browser tabs."
                    ),
                    "severity": MEDIUM,
                    "confidence": VERIFIED,
                }
            )
    except Exception:
        # An unusual head structure shouldn't take down the rest of the
        # checks in this module.
        pass


def _check_meta_description(page, problems):
    """Flags a missing (or empty) <meta name="description">. This is the
    short summary text Google shows under the title in search results, and
    what messaging apps/social sites show when the link is shared."""
    try:
        meta = page.query_selector("head meta[name='description' i]")
        content = meta.get_attribute("content") if meta else None

        if meta is None or not (content or "").strip():
            problems.append(
                {
                    "category": "Missing Meta Description",
                    "message": (
                        "This page has no meta description (or it's empty). "
                        "That's the short summary text that shows up under "
                        "the page's title in Google search results and when "
                        "the link is shared on social media or messaging "
                        "apps — without one, those services fall back to "
                        "picking a snippet of body text at random, which "
                        "often looks awkward or unhelpful."
                    ),
                    "severity": LOW,
                    "confidence": VERIFIED,
                }
            )
    except Exception:
        pass


def _check_h1(page, problems):
    """Flags zero <h1> elements (no clear main heading for visitors or
    search engines) or more than one (dilutes which heading is actually
    "the" topic of the page, and confuses screen-reader users who navigate
    by heading structure)."""
    try:
        h1s = page.query_selector_all("h1")

        if len(h1s) == 0:
            problems.append(
                {
                    "category": "Missing H1 Heading",
                    "message": (
                        "This page has no <h1> heading. The H1 tells both "
                        "visitors and search engines what the page is "
                        "actually about at a glance — without one, the "
                        "page's main topic is less clear to Google, and "
                        "screen-reader users lose the usual way of jumping "
                        "straight to the main content."
                    ),
                    "severity": LOW,
                    "confidence": VERIFIED,
                }
            )
        elif len(h1s) > 1:
            problems.append(
                {
                    "category": "Multiple H1 Headings",
                    "message": (
                        f"This page has {len(h1s)} <h1> headings instead of "
                        "one. Having multiple top-level headings makes it "
                        "unclear to search engines which one is actually "
                        "the page's main topic, and can confuse "
                        "screen-reader users who rely on headings to "
                        "understand how the page is structured."
                    ),
                    "severity": LOW,
                    "confidence": VERIFIED,
                }
            )
    except Exception:
        pass


def _check_favicon(page, problems):
    """Flags a missing <link rel="icon"> (or rel="shortcut icon"). Without
    one, browsers show a generic blank/placeholder icon in tabs, bookmarks,
    and history."""
    try:
        has_favicon = False
        for link in page.query_selector_all("head link[rel]"):
            rel_tokens = (link.get_attribute("rel") or "").lower().split()
            if "icon" in rel_tokens:
                has_favicon = True
                break

        if not has_favicon:
            problems.append(
                {
                    "category": "Missing Favicon",
                    "message": (
                        'This page has no favicon link (<link rel="icon">). '
                        "Without one, the site shows a generic blank or "
                        "placeholder icon in browser tabs, bookmarks, and "
                        "browsing history, which can make it look less "
                        "polished and harder for visitors to spot among "
                        "other open tabs."
                    ),
                    "severity": LOW,
                    "confidence": VERIFIED,
                }
            )
    except Exception:
        pass


# Elements/attributes that cause a real browser to fetch a sub-resource.
# Anchor tags (<a href>) are deliberately excluded — a plain link to an
# http:// page is a navigation, not a mixed-content browser warning.
_MIXED_CONTENT_SELECTOR = (
    "img[src^='http://'], "
    "script[src^='http://'], "
    "link[rel='stylesheet' i][href^='http://'], "
    "iframe[src^='http://'], "
    "source[src^='http://'], "
    "video[src^='http://'], "
    "audio[src^='http://'], "
    "embed[src^='http://'], "
    "object[data^='http://']"
)


def find_mixed_content_urls(page):
    """Pure DOM scan for elements that hardcode an http:// resource
    reference, regardless of what protocol the page itself loaded over.

    Deliberately split out from _check_mixed_content/check_seo_and_security
    so this specific piece of logic can be exercised on its own (e.g. fed a
    page whose content was set directly) without needing a real https://
    navigation to test it — see verify_seo_checks.py.
    """
    return [url for url, _active in find_mixed_content(page)]


# Active content can rewrite the whole page (scripts, frames, plugins,
# stylesheets); passive content can only be looked at (images, media).
# Browsers block active mixed content outright and only warn about passive
# — which is also why one is MEDIUM and the other LOW.
_ACTIVE_MIXED_TAGS = {"script", "iframe", "link", "embed", "object"}


def find_mixed_content(page):
    """[(url, is_active)] for every hardcoded http:// sub-resource."""
    found = []
    for el in page.query_selector_all(_MIXED_CONTENT_SELECTOR):
        url = (
            el.get_attribute("src")
            or el.get_attribute("href")
            or el.get_attribute("data")
        )
        if url:
            tag = el.evaluate("e => e.tagName.toLowerCase()")
            found.append((url, tag in _ACTIVE_MIXED_TAGS))
    return found


def _check_mixed_content(page, problems):
    """Flags hardcoded http:// resource references on a page that itself
    loaded over https://. Only applicable when the page is https — an
    already-insecure http:// page has nothing "mixed" about it (that
    whole-site problem is checks_security's "Site Doesn't Use HTTPS").

    Split by kind (GetBuggy Step 5): active content (scripts, frames,
    stylesheets) MEDIUM, passive (images, media) LOW. Both are security
    findings, ownership-gated like the rest of checks_security.py."""
    try:
        if not page.url.startswith("https://"):
            return

        found = find_mixed_content(page)
        for active in (True, False):
            urls = [u for u, a in found if a == active]
            if not urls:
                continue
            sample = ", ".join(urls[:3])
            extra = len(urls) - 3
            more = f" (+{extra} more)" if extra > 0 else ""
            if active:
                what = (
                    "loads code (scripts, frames or styles) over plain http:// "
                    f"instead of https://: {sample}{more}. Browsers block these "
                    "outright, so parts of the page may silently not work — and "
                    "if one did load, anyone on the same network could tamper "
                    "with it."
                )
            else:
                what = (
                    "shows images or media over plain http:// instead of "
                    f"https://: {sample}{more}. Browsers show a \"not fully "
                    "secure\" warning for this, which makes the site look "
                    "less trustworthy."
                )
            problems.append(
                {
                    "category": "Mixed Content (Active)" if active else "Mixed Content (Passive)",
                    "message": (
                        f"This page loads over a secure https:// connection, but {what} "
                        "Changing those addresses to https:// fixes it. "
                        "Who fixes it: your web person."
                    ),
                    "severity": MEDIUM if active else LOW,
                    "confidence": VERIFIED,
                    "who_fixes": "your web person",
                    "group": "security",
                    "evidence": "|".join(sorted(urls)),
                }
            )
    except Exception:
        pass


def check_seo_and_security(page, problems, skip_discoverability=False, skip_favicon=False):
    """Run all SEO/basic-security checks against the already-loaded main
    page. Meant to be called right after core.py's page.goto() for the
    main page, the same way the img/a[href] loops in run_check() operate
    on the already-loaded page rather than a fresh navigation — so
    page.url reflects the final URL after any redirects, and the DOM is
    fully available.

    `skip_favicon=True` (set by a crawl once it has confirmed the site's
    /favicon.ico loads — see checks_security.run_site_security_pass):
    browsers fetch /favicon.ico on their own, so a missing <link> tag
    isn't a missing favicon there.

    `skip_discoverability=True` (set by core.py for a utility page — a
    cart, checkout, account, login, or search page: see
    core._is_utility_page) skips title/meta-description/H1, since none
    of those are real problems on a page that isn't meant to be found via
    search in the first place — a missing meta description on a cart
    page isn't an SEO issue. Favicon and mixed-content still run
    everywhere: a favicon is site-wide regardless of which page loaded
    it, and mixed content is a security concern independent of the
    page's purpose.

    Each individual check is wrapped in its own try/except (see the
    helpers above) so one unusual page structure can't take down the
    others.
    """
    if not skip_discoverability:
        _check_title(page, problems)
        _check_meta_description(page, problems)
        _check_h1(page, problems)
    if not skip_favicon:
        _check_favicon(page, problems)
    _check_mixed_content(page, problems)


_NOINDEX_TOKEN_RE = re.compile(r"(^|[\s,])(noindex|none)($|[\s,])")


def has_noindex_directive(value):
    """True if a robots directive string (a meta tag's content or an
    X-Robots-Tag header value) tells search engines not to index the page.
    A directive scoped to some *other* crawler ("bingbot: noindex" is
    still search-relevant, "otherbot: noindex" isn't) is judged on the
    directive part alone — good enough for a passive heads-up."""
    v = (value or "").lower()
    if ":" in v:
        agent, _, rest = v.partition(":")
        if agent.strip() not in ("googlebot", "bingbot", "robots", "*"):
            return False
        v = rest
    return bool(_NOINDEX_TOKEN_RE.search(v))


def check_indexability(page, response, problems, is_homepage):
    """Flags a page that tells search engines to stay away ('noindex', via a
    meta tag or the X-Robots-Tag response header). On the homepage that
    can make the whole business invisible on Google (HIGH); on another page
    it may be deliberate (a thank-you or login page), so MEDIUM."""
    try:
        sources = []
        header = (response.headers.get("x-robots-tag") if response is not None else None) or ""
        if has_noindex_directive(header):
            sources.append("the page's response headers (X-Robots-Tag)")
        for meta in page.query_selector_all("meta[name]"):
            name = (meta.get_attribute("name") or "").lower()
            if name in ("robots", "googlebot") and has_noindex_directive(
                meta.get_attribute("content")
            ):
                sources.append(f'a <meta name="{name}"> tag')
                break
        if not sources:
            return
        where = " and ".join(sources)
        if is_homepage:
            message = (
                f"Your homepage tells search engines not to list it ('noindex', set in {where}). "
                "Google will drop it from search results, so people searching for your business "
                "won't find it. If this is a site still being built, that's fine — otherwise ask "
                "your web person to remove it right away."
            )
        else:
            message = (
                f"This page tells search engines not to list it ('noindex', set in {where}). That's "
                "right for private pages like thank-you or login pages, but if you want this page "
                "found on Google, ask your web person to remove the setting."
            )
        problems.append({
            "category": "Page Blocked From Search (noindex)",
            "message": message,
            "severity": HIGH if is_homepage else MEDIUM,
            "confidence": VERIFIED,
        })
    except Exception:
        pass
