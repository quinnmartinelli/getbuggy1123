"""Unit tests for checks_links.py (link classification, static-vs-rendered
diff, link-text quality) and checks_seo.has_noindex_directive. No browser
or network."""
from checks_links import (
    classify_link,
    extract_static_links,
    link_text_is_vague,
    static_share_of_rendered,
)
from checks_seo import has_noindex_directive

PAGE = "https://site.com/page"


def link(href, resolved=None, **kw):
    return {"href": href, "resolved": resolved or href, **kw}


def kind(href, resolved=None, ids=(), **kw):
    return classify_link(link(href, resolved, **kw), PAGE, "site.com", set(ids))


# --- classification ---

def test_internal_and_external():
    assert kind("/about", "https://site.com/about") == "internal"
    assert kind("https://www.site.com/x") == "internal"
    assert kind("https://other.com/x") == "external"


def test_in_page_anchors_verify_the_target_exists():
    assert kind("#features", ids=["features"]) == "anchor_ok"
    assert kind("#missing", ids=["features"]) == "anchor_missing"
    assert kind("#") == "anchor_ok"
    assert kind("#top") == "anchor_ok"


def test_same_page_absolute_anchor_is_an_anchor():
    assert kind("https://site.com/page#nope", ids=[]) == "anchor_missing"
    assert kind("https://site.com/page#yes", ids=["yes"]) == "anchor_ok"


def test_hash_routes_are_not_anchors():
    assert kind("#/about") == "hash_route"
    assert kind("#!/contact") == "hash_route"
    assert kind("https://site.com/#/pricing") == "hash_route"


def test_javascript_void():
    assert kind("javascript:void(0)") == "js_void"
    assert kind("javascript:void(0);") == "js_void"
    assert kind("javascript:;") == "js_void"
    assert kind("javascript:openMenu()") == "skip"


def test_mailto_and_tel_are_skipped():
    assert kind("mailto:a@b.com") == "skip"
    assert kind("tel:+15555555555") == "skip"


def test_downloads():
    assert kind("https://site.com/menu.pdf") == "download"
    assert kind("/files/report", "https://site.com/files/report", download=True) == "download"


def test_social_profiles_but_not_share_buttons():
    assert kind("https://www.instagram.com/mybakery/") == "social"
    assert kind("https://facebook.com/mybakery") == "social"
    assert kind("https://www.facebook.com/sharer/sharer.php?u=x") == "external"
    assert kind("https://twitter.com/intent/tweet?text=x") == "external"
    assert kind("https://facebook.com/") == "external"  # a bare homepage isn't a profile


# --- link text ---

def test_vague_link_text():
    assert link_text_is_vague("Click here")
    assert link_text_is_vague("  Read more »")
    assert link_text_is_vague("here.")
    assert link_text_is_vague("https://example.com/some/long/url")
    assert link_text_is_vague("www.example.com")


def test_descriptive_link_text_is_fine():
    assert not link_text_is_vague("Read our pricing guide")
    assert not link_text_is_vague("Contact us")
    assert not link_text_is_vague("")


def test_aria_label_rescues_vague_text():
    assert not link_text_is_vague("Read more", aria_label="Read more about our bakery")


# --- static vs rendered ---

def test_static_links_extracted_from_raw_html():
    html = '<a href="/a">A</a><a href="#top">t</a><a href="mailto:x@y.z">m</a><a href="https://o.com/b#f">B</a>'
    keys = extract_static_links(html, "https://site.com/")
    assert keys == {"site.com/a", "o.com/b"}


def test_static_share_of_rendered():
    rendered = {f"site.com/{i}" for i in range(10)}
    assert static_share_of_rendered({"site.com/0"}, rendered) == 0.1
    assert static_share_of_rendered(rendered, rendered) == 1.0
    assert static_share_of_rendered(set(), set()) == 1.0


# --- noindex ---

def test_noindex_directives():
    assert has_noindex_directive("noindex, follow")
    assert has_noindex_directive("NOINDEX")
    assert has_noindex_directive("none")
    assert has_noindex_directive("googlebot: noindex")


def test_not_noindex():
    assert not has_noindex_directive("index, follow")
    assert not has_noindex_directive("nofollow")
    assert not has_noindex_directive("")
    assert not has_noindex_directive(None)
    assert not has_noindex_directive("otherbot: noindex")
