"""Unit tests for crawl_utils.py — URL canonicalization, robots.txt
parsing, sitemap parsing (plain, index, gzip), page selection, and the
soft-404 fingerprint. No browser, no network."""
import gzip

from crawl_utils import (
    MAX_SITEMAP_BYTES,
    classify_sitemap_urls,
    clean_url,
    make_fingerprint,
    matches_soft_404,
    page_key,
    parse_robots,
    parse_sitemap,
    registrable_domain,
    select_pages,
    sitemap_candidates,
)


# --- scope / dedup ---

def test_www_and_apex_are_one_page():
    assert page_key("https://www.example.com/about") == page_key("https://example.com/about/")


def test_http_and_https_are_one_page():
    assert page_key("http://example.com/x") == page_key("https://example.com/x")


def test_fragments_and_hash_routes_collapse():
    assert page_key("https://x.com/#/about") == page_key("https://x.com/")
    assert page_key("https://x.com/#!/contact") == page_key("https://x.com")
    assert page_key("https://x.com/a#section") == page_key("https://x.com/a")


def test_tracking_params_are_stripped_before_dedup():
    url = "https://x.com/p?utm_source=a&utm_medium=b&fbclid=1&gclid=2&mc_cid=3&id=7"
    assert page_key(url) == page_key("https://x.com/p?id=7")
    assert clean_url(url) == "https://x.com/p?id=7"


def test_real_query_params_are_kept():
    assert page_key("https://x.com/p?id=1") != page_key("https://x.com/p?id=2")


def test_registrable_domain_handles_two_part_suffixes():
    assert registrable_domain("www.bakery.co.uk") == "bakery.co.uk"
    assert registrable_domain("shop.bakery.co.uk") == "bakery.co.uk"
    assert registrable_domain("cdn.shopify.com") == "shopify.com"
    assert registrable_domain("127.0.0.1") == "127.0.0.1"


# --- robots.txt ---

def test_robots_disallow_all_for_everyone():
    r = parse_robots("User-agent: *\nDisallow: /\n")
    assert r["blocks_all_agents"] and r["blocks_googlebot"]


def test_robots_disallow_all_for_googlebot_only():
    r = parse_robots("User-agent: Googlebot\nDisallow: /\n\nUser-agent: *\nDisallow:\n")
    assert r["blocks_googlebot"] and not r["blocks_all_agents"]


def test_robots_partial_disallow_is_not_a_block():
    r = parse_robots("User-agent: *\nDisallow: /admin/\nDisallow: /cart\n")
    assert not r["blocks_all_agents"] and not r["blocks_googlebot"]


def test_robots_empty_disallow_and_allow_root_do_not_block():
    assert not parse_robots("User-agent: *\nDisallow:\n")["blocks_all_agents"]
    assert not parse_robots("User-agent: *\nDisallow: /\nAllow: /\n")["blocks_all_agents"]


def test_robots_googlebot_own_group_overrides_star():
    r = parse_robots("User-agent: *\nDisallow: /\n\nUser-agent: Googlebot\nDisallow: /private\n")
    assert r["blocks_all_agents"] and not r["blocks_googlebot"]


def test_robots_sitemap_directives_and_comments():
    r = parse_robots("# hi\nSitemap: https://x.com/a.xml  # main\nUser-agent: *\nDisallow:\nsitemap: https://x.com/b.xml\n")
    assert r["sitemaps"] == ["https://x.com/a.xml", "https://x.com/b.xml"]


# --- sitemap discovery order + parsing ---

def test_sitemap_discovery_order():
    groups = sitemap_candidates("https://x.com/", ["https://x.com/custom.xml"])
    assert groups == [
        ["https://x.com/custom.xml"],
        ["https://x.com/sitemap.xml"],
        ["https://x.com/sitemap_index.xml"],
        ["https://x.com/sitemap-index.xml"],
        ["https://x.com/wp-sitemap.xml"],
    ]


def test_sitemap_discovery_order_without_robots_directive():
    groups = sitemap_candidates("https://x.com", [])
    assert [g[0] for g in groups][0] == "https://x.com/sitemap.xml"
    assert len(groups) == 4


URLSET = b'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://x.com/a</loc></url><url><loc> https://x.com/b </loc></url></urlset>'
INDEX = b'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://x.com/s1.xml</loc></sitemap><sitemap><loc>https://x.com/s2.xml.gz</loc></sitemap></sitemapindex>'


def test_parse_urlset():
    assert parse_sitemap(URLSET) == ("urlset", ["https://x.com/a", "https://x.com/b"])


def test_parse_sitemap_index():
    assert parse_sitemap(INDEX) == ("sitemapindex", ["https://x.com/s1.xml", "https://x.com/s2.xml.gz"])


def test_parse_gzipped_sitemap():
    assert parse_sitemap(gzip.compress(URLSET)) == ("urlset", ["https://x.com/a", "https://x.com/b"])


def test_parse_sitemap_without_namespace():
    assert parse_sitemap(b"<urlset><url><loc>https://x.com/a</loc></url></urlset>") == ("urlset", ["https://x.com/a"])


def test_parse_sitemap_rejects_junk():
    assert parse_sitemap(b"<html><body>404</body></html>") is None
    assert parse_sitemap(b"not xml at all") is None
    assert parse_sitemap(b"") is None
    assert parse_sitemap(b"\x1f\x8bnot really gzip") is None


def test_parse_sitemap_rejects_decompression_bomb():
    bomb = gzip.compress(b"<urlset>" + b"a" * (MAX_SITEMAP_BYTES + 10) + b"</urlset>")
    assert parse_sitemap(bomb) is None


def test_classify_sitemap_urls_other_host_and_insecure():
    other, insecure = classify_sitemap_urls(
        [
            "https://www.x.com/a",          # www == apex: fine
            "https://x.com/b",
            "http://x.com/c",               # insecure
            "https://blog.x.com/d",         # a different host
            "https://other.example/e",      # a different site
        ],
        "x.com", "https",
    )
    assert other == ["https://blog.x.com/d", "https://other.example/e"]
    assert insecure == ["http://x.com/c"]


def test_http_is_not_flagged_when_the_site_itself_is_http():
    assert classify_sitemap_urls(["http://x.com/a"], "x.com", "http") == ([], [])


# --- page selection ---

def test_page_selection_priority_order():
    home = "https://x.com/"
    nav = ["https://x.com/services", "https://x.com/team"]
    sitemap = [
        "https://x.com/", "https://x.com/blog/1", "https://x.com/blog/2",
        "https://x.com/pricing", "https://x.com/contact-us", "https://x.com/services",
    ]
    selected, skipped, total = select_pages(home, nav, sitemap, [], 5)
    # homepage, then menu pages, then contact/pricing matches, then sitemap order
    assert selected == [
        "https://x.com/", "https://x.com/services", "https://x.com/team",
        "https://x.com/pricing", "https://x.com/contact-us",
    ]
    assert skipped == ["https://x.com/blog/1", "https://x.com/blog/2"]
    assert total == 7


def test_page_selection_priority_words():
    home = "https://x.com/"
    sitemap = [f"https://x.com/p{i}" for i in range(5)] + [
        "https://x.com/book-now", "https://x.com/order", "https://x.com/shop/all",
    ]
    selected, _, _ = select_pages(home, [], sitemap, [], 4)
    assert selected == ["https://x.com/", "https://x.com/book-now", "https://x.com/order", "https://x.com/shop/all"]


def test_page_selection_dedups_by_page_key():
    selected, skipped, total = select_pages(
        "https://x.com/", ["https://www.x.com/a?utm_source=z"], ["https://x.com/a/", "https://x.com/#/route"], [], 10
    )
    assert selected == ["https://x.com/", "https://www.x.com/a?utm_source=z"]
    assert total == 2 and skipped == []


def test_page_selection_when_everything_fits():
    selected, skipped, total = select_pages("https://x.com/", [], ["https://x.com/a"], [], 5)
    assert (selected, skipped, total) == (["https://x.com/", "https://x.com/a"], [], 2)


# --- soft 404 ---

NOT_FOUND = "Sorry, we could not find the page you were looking for. Home About Contact Menu Footer text " * 3


def test_identical_page_matches_soft_404_exactly():
    probe = make_fingerprint("Page not found", NOT_FOUND)
    assert matches_soft_404(make_fingerprint("Page not found", NOT_FOUND), probe) == (True, True)


def test_page_echoing_its_own_address_still_matches():
    probe = make_fingerprint("Not found", NOT_FOUND + " getbuggy-missing-abc123", "https://x.com/getbuggy-missing-abc123")
    page = make_fingerprint("Not found", NOT_FOUND + " old-service", "https://x.com/old-service.html")
    match, exact = matches_soft_404(page, probe)
    assert match and exact


def test_real_page_with_shared_chrome_does_not_match():
    probe = make_fingerprint("Page not found", NOT_FOUND)
    real = make_fingerprint("About", "Home About Contact Menu Footer text " + "We are a small family bakery that started in 1987 and bakes bread every morning. " * 2)
    assert matches_soft_404(real, probe) == (False, False)


def test_empty_page_never_matches():
    assert matches_soft_404(make_fingerprint("", ""), make_fingerprint("x", "y")) == (False, False)
