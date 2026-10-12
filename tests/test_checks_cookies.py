"""Unit tests for checks_cookies.py (GetBuggy Step 7): classification,
banner wording, the privacy-policy reader, jurisdiction-dependent findings,
the security gate for cookie settings, and the server's `jurisdiction`
field. The browser side is covered by the regression harness's three
cookie fixtures (no banner, banner not blocking, compliant)."""
import datetime
import time

import pytest
from fastapi.testclient import TestClient

import checks_cookies as cc
import checks_security as cs
import server

TODAY = datetime.date(2026, 10, 11)


# --- jurisdiction ----------------------------------------------------------

def test_jurisdiction_defaults_to_us_and_rejects_unknown_values():
    assert cc.normalize_jurisdiction(None) == "us"
    assert cc.normalize_jurisdiction("") == "us"
    assert cc.normalize_jurisdiction(" EU_UK ") == "eu_uk"
    assert cc.normalize_jurisdiction("both") == "both"
    with pytest.raises(ValueError):
        cc.normalize_jurisdiction("mars")


# --- classification ----------------------------------------------------------

def test_cookies_classified_by_name_then_domain_never_guessed():
    assert cc.classify_cookie("_ga", "bakery.com", "bakery.com") == ("Google Analytics", "analytics")
    assert cc.classify_cookie("_ga_ABC123", "bakery.com", "bakery.com") == ("Google Analytics", "analytics")
    assert cc.classify_cookie("_fbp", "bakery.com", "bakery.com") == ("Meta / Facebook", "advertising")
    assert cc.classify_cookie("IDE", ".doubleclick.net", "bakery.com") == ("Google Ads", "advertising")
    assert cc.classify_cookie("whatever", "ads.criteo.com", "bakery.com") == ("Criteo", "advertising")
    assert cc.classify_cookie("cart_pref", "www.bakery.com", "bakery.com") == ("Your own site", "unknown")
    assert cc.classify_cookie("x", "tracker.example.net", "bakery.com") == ("example.net", "unknown")


def test_request_classification_respects_path_scoped_entries():
    assert cc.classify_request("https://www.google.com/recaptcha/api.js")["company"] == "Google reCAPTCHA"
    assert cc.classify_request("https://www.google.com/search?q=x") is None
    assert cc.classify_request("https://region1.google-analytics.com/g/collect")["category"] == "analytics"
    assert cc.classify_request("https://cdn.jsdelivr.net/npm/x.js")["category"] == "functional"


def test_test_tracker_alias_is_off_unless_set(monkeypatch):
    monkeypatch.delenv(cc.TEST_TRACKER_ALIAS_ENV_VAR, raising=False)
    assert cc.classify_request("http://localhost:8991/tracker.js") is None
    monkeypatch.setenv(cc.TEST_TRACKER_ALIAS_ENV_VAR, "localhost=static.hotjar.com")
    assert cc.classify_request("http://localhost:8991/tracker.js")["company"] == "Hotjar"


def test_consent_mode_denied_pings_are_not_tracking():
    assert cc.is_consent_mode_denied_ping("https://www.google-analytics.com/g/collect?v=2&gcs=G100")
    assert cc.is_consent_mode_denied_ping("https://www.google-analytics.com/g/collect?gcs=G1--")
    assert not cc.is_consent_mode_denied_ping("https://www.google-analytics.com/g/collect?gcs=G111")
    assert not cc.is_consent_mode_denied_ping("https://www.google-analytics.com/g/collect?v=2")
    companies, ads, _ = cc.tracking_evidence(
        [], ["https://www.google-analytics.com/g/collect?v=2&gcs=G100"], "bakery.com"
    )
    assert companies == [] and ads == []


def test_tracking_evidence_names_companies_and_advertisers():
    records = cc._cookie_records(
        [{"name": "_ga", "domain": "bakery.com"}, {"name": "theme", "domain": "bakery.com"}], "bakery.com"
    )
    companies, ads, evidence = cc.tracking_evidence(
        records, ["https://connect.facebook.net/en_US/fbevents.js"], "bakery.com"
    )
    assert companies == ["Google Analytics", "Meta / Facebook"]
    assert ads == ["Meta / Facebook"]
    assert 'Google Analytics (cookie "_ga")' in evidence and "Meta / Facebook (contacted)" in evidence


def test_consent_tools_detected_by_script_address():
    tools = cc.detect_consent_tools(
        ["https://consent.cookiebot.com/uc.js", "https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"]
    )
    assert tools == ["Cookiebot", "OneTrust"]
    assert cc.detect_consent_tools(["https://bakery.com/app.js"]) == []


# --- the site's own cookie settings (security, gated) -------------------------

def test_set_cookie_parsing():
    c = cc.parse_set_cookie("sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert c == {"name": "sessionid", "secure": True, "httponly": True, "samesite": "Lax"}
    assert cc.parse_set_cookie("garbage") is None


def test_cookie_attribute_findings():
    cookies = [
        cc.parse_set_cookie("sessionid=a; Path=/"),
        cc.parse_set_cookie("csrftoken=b; Path=/; SameSite=Lax"),
        cc.parse_set_cookie("theme=dark; Path=/; Secure; SameSite=Lax"),
    ]
    https = {f["category"]: f for f in cc.cookie_attribute_findings(cookies, site_is_https=True)}
    assert set(https) == set(cc.COOKIE_SECURITY_CATEGORIES)
    assert https["Login Cookie Readable By Scripts"]["evidence"] == "sessionid"  # csrf is meant to be readable
    assert https["Login Cookie Readable By Scripts"]["severity"] == cc.MEDIUM
    assert https["Cookies Not Marked Secure"]["severity"] == cc.LOW
    assert https["Cookies Missing SameSite Setting"]["evidence"] == "sessionid"
    # On a plain-http site "Secure" can't be set at all — "Site Doesn't Use
    # HTTPS" already covers that.
    http = {f["category"] for f in cc.cookie_attribute_findings(cookies, site_is_https=False)}
    assert "Cookies Not Marked Secure" not in http
    assert all(f["group"] == cs.SECURITY_GROUP for f in cc.cookie_attribute_findings(cookies, True))


def test_cookie_security_categories_are_gated():
    assert set(cc.COOKIE_SECURITY_CATEGORIES) <= cs.SECURITY_CATEGORIES
    findings = cc.cookie_attribute_findings([cc.parse_set_cookie("sessionid=a")], False)
    assert len(findings) == 2  # readable by scripts + no SameSite
    public = cs.redact_security_details({"result": {"site_findings": findings, "pages": []}})
    assert public["result"]["site_findings"] == []
    assert public["result"]["security_summary"]["count"] == 2
    assert "sessionid" not in str(public)


def test_platform_cookies_are_attributed_to_the_platform():
    # What the per-cookie skip in run_site_cookie_pass relies on: Shopify's
    # own cookies classify as Shopify even when platform detection missed.
    for name in ("_shopify_essential", "cart_currency", "localization", "_shopify_marketing"):
        assert cc.classify_cookie(name, "cakesbody.com", "cakesbody.com")[0] in cs._HOSTED_PLATFORMS


def test_tracker_cookies_are_never_called_logins():
    assert not cc.looks_like_auth_cookie("_uetsid")
    assert not cc.looks_like_auth_cookie("XSRF-TOKEN")
    assert cc.looks_like_auth_cookie("PHPSESSID")
    assert cc.looks_like_auth_cookie("auth_token")


# --- the banner ----------------------------------------------------------------

@pytest.mark.parametrize("text,kind", [
    ("Accept all", "accept"),
    ("Got it!", "accept"),
    ("Allow selection", "accept"),
    ("Reject all", "reject"),
    ("Continue without accepting", "reject"),
    ("Necessary cookies only", "reject"),
    ("Manage settings", "settings"),
    ("Cookie policy", "settings"),
    ("×", "close"),
    ("Order cookies", None),
])
def test_banner_buttons_classified_by_wording(text, kind):
    assert cc.classify_control(text) == kind


def test_icon_button_uses_its_label():
    assert cc.classify_control("", "Close cookie banner") == "close"


def test_a_header_about_baked_cookies_is_not_a_banner():
    header = {"controls": [{"text": "Order cookies"}, {"text": "About us"}]}
    assert not cc.is_consent_banner(header)
    assert cc.is_consent_banner({"controls": [{"text": "OK"}]})


def test_reject_harder_only_when_accept_has_no_reject_beside_it():
    accept_only = {"controls": [{"text": "Accept all"}, {"text": "Manage settings"}]}
    f = cc.reject_harder_finding("eu_uk", accept_only)
    assert f["severity"] == cc.LOW and '"Manage settings"' in f["message"]
    assert cc.reject_harder_finding("eu_uk", {"controls": [{"text": "Accept"}, {"text": "Reject"}]}) is None
    assert cc.reject_harder_finding("us", accept_only) is None


def test_mobile_block_needs_full_cover_and_no_reachable_dismiss():
    blocked = {"coverage": 1.0, "scrollable": False, "controls": [{"text": "Accept", "inViewport": False}]}
    assert cc.mobile_block_finding(blocked)["category"] == "Cookie Banner Covers The Phone Screen"
    assert cc.mobile_block_finding(dict(blocked, scrollable=True)) is None
    assert cc.mobile_block_finding(dict(blocked, coverage=0.4)) is None
    reachable = dict(blocked, controls=[{"text": "Accept", "inViewport": True}])
    assert cc.mobile_block_finding(reachable) is None


# --- jurisdiction changes which findings show ------------------------------------

def test_no_banner_finding_by_jurisdiction():
    # US: analytics alone with no banner is not a finding; advertising is.
    assert cc.no_banner_finding("us", [], "Google Analytics (cookie \"_ga\")") is None
    us = cc.no_banner_finding("us", ["Meta / Facebook"], "Meta / Facebook (contacted)")
    assert us["severity"] == cc.MEDIUM and "opt out" in us["message"] and "GDPR" not in us["message"]
    eu = cc.no_banner_finding("eu_uk", [], "Google Analytics (cookie \"_ga\")")
    assert eu["severity"] == cc.MEDIUM and "GDPR" in eu["message"]
    both = cc.no_banner_finding("both", [], "Google Analytics (cookie \"_ga\")")
    assert "GDPR" in both["message"] and "US state laws" in both["message"]


def test_tracking_before_consent_is_eu_uk_only():
    assert cc.before_consent_finding("us", "x") is None
    f = cc.before_consent_finding("eu_uk", "Google Analytics (cookie \"_ga\")")
    assert f["severity"] == cc.MEDIUM and "your banner isn't blocking anything" in f["message"]
    assert cc.before_consent_finding("both", "x") is not None


# --- privacy policy ----------------------------------------------------------------

def test_privacy_link_prefers_the_footer_and_skips_choice_buttons():
    links = [
        {"text": "Your Privacy Choices", "href": "https://b.com/#choices", "inFooter": True},
        {"text": "Privacy", "href": "https://b.com/privacy", "inFooter": False},
        {"text": "Privacy Policy", "href": "https://b.com/legal/privacy-policy", "inFooter": True},
    ]
    assert cc.find_privacy_link(links) == ("https://b.com/legal/privacy-policy", True)
    assert cc.find_privacy_link(links[:2]) == ("https://b.com/privacy", False)
    assert cc.find_privacy_link([]) == (None, False)
    assert cc.privacy_url_from_sitemap(["https://b.com/", "https://b.com/privacy-policy"]) == "https://b.com/privacy-policy"


@pytest.mark.parametrize("text,expected", [
    ("Last updated: March 3, 2019. We collect...", datetime.date(2019, 3, 3)),
    ("Effective 5 January 2026", datetime.date(2026, 1, 5)),
    ("Revised 2025-06-30", datetime.date(2025, 6, 30)),
    ("Last updated 2023", datetime.date(2023, 12, 31)),
    ("Founded 1998. Last updated: July 2024.", datetime.date(2024, 7, 28)),
    ("No dates here at all.", None),
])
def test_policy_date(text, expected):
    assert cc.policy_date(text, TODAY) == expected


def test_policy_placeholder():
    assert "template text" in cc.placeholder_reason("Lorem ipsum dolor sit amet " * 50)
    assert "template text" in cc.placeholder_reason("[Your Company Name] collects data. " * 40)
    assert "words long" in cc.placeholder_reason("We respect your privacy.")
    assert cc.placeholder_reason("We respect your privacy and explain what we collect. " * 20) is None


REAL_POLICY = (
    "Last updated: June 1, 2026. "
    + "Sunrise Bakery explains what information we collect from visitors and why we need it. " * 10
    + "We use Google Analytics to count visits."
)


def _cats(findings):
    return {f["category"]: f for f in findings}


def test_privacy_findings():
    missing = _cats(cc.privacy_findings("us", {"url": None}, ["Google Analytics"]))
    assert missing["No Privacy Policy Found"]["severity"] == cc.MEDIUM  # tracking present
    assert _cats(cc.privacy_findings("us", {"url": None}, []))["No Privacy Policy Found"]["severity"] == cc.LOW

    good = {"url": "https://b.com/privacy", "in_footer": True, "source": "homepage", "text": REAL_POLICY}
    assert cc.privacy_findings("us", good, ["Google Analytics"], TODAY) == []

    unmentioned = _cats(cc.privacy_findings("us", good, ["Google Analytics", "TikTok"], TODAY))
    f = unmentioned["Privacy Policy Doesn't Mention Your Trackers"]
    assert f["severity"] == cc.MEDIUM and "TikTok" in f["message"] and "Google Analytics" not in f["message"]

    old = dict(good, text=REAL_POLICY.replace("June 1, 2026", "June 1, 2020"))
    assert "Privacy Policy May Be Out Of Date" in _cats(cc.privacy_findings("us", old, [], TODAY))

    undated = dict(good, text=REAL_POLICY.replace("Last updated: June 1, 2026. ", ""))
    assert "Privacy Policy Isn't Dated" in _cats(cc.privacy_findings("us", undated, [], TODAY))

    not_footer = dict(good, in_footer=False, source="sitemap")
    assert "only found it in your sitemap" in _cats(
        cc.privacy_findings("us", not_footer, [], TODAY)
    )["Privacy Policy Not In Your Footer"]["message"]

    placeholder = _cats(cc.privacy_findings("us", dict(good, text="Lorem ipsum " * 80), ["Hotjar"], TODAY))
    assert set(placeholder) == {"Privacy Policy Looks Like A Placeholder"}

    unread = dict(good, text=None)  # couldn't open it: no content findings, just the caller's note
    assert cc.privacy_findings("us", unread, ["TikTok"], TODAY) == []


def test_every_compliance_finding_says_may_and_not_legal_advice():
    findings = [
        cc.no_banner_finding("us", ["Meta / Facebook"], "x"),
        cc.no_banner_finding("eu_uk", [], "x"),
        cc.before_consent_finding("eu_uk", "x"),
        cc.reject_harder_finding("eu_uk", {"controls": [{"text": "Accept"}]}),
        *cc.privacy_findings("both", {"url": None}, ["Meta / Facebook"]),
        *cc.privacy_findings("both", {"url": "https://b.com/p", "in_footer": False, "text": REAL_POLICY},
                             ["TikTok"], TODAY),
    ]
    for f in findings:
        assert f["topic"] == cc.TOPIC
        assert " may " in f["message"], f["category"]
        assert cc.NOT_LEGAL_ADVICE in f["message"], f["category"]
        assert "Who fixes it:" in f["message"], f["category"]


# --- the informational section --------------------------------------------------------

def test_summary_counts_and_page_merge():
    records = cc._cookie_records(
        [{"name": "_ga", "domain": "b.com"}, {"name": "sid", "domain": "b.com"}], "b.com"
    )
    hosts = cc._third_party_hosts(["https://static.hotjar.com/c/hotjar.js", "https://b.com/app.js"], "b.com")
    s = cc.build_summary(records, hosts, "us", banner_seen=False)
    assert (s["cookie_count"], s["company_count"]) == (2, 2)
    assert s["headline"].startswith("Your site sets 2 cookies from 2 companies, and contacts 1 more company")
    assert cc.NOT_LEGAL_ADVICE in s["note"]
    snap = {"cookies": cc._cookie_records([{"name": "_ttp", "domain": "b.com"}], "b.com"), "hosts": []}
    merged = cc.merge_page_snapshots(s, [snap, None])
    assert (merged["cookie_count"], merged["company_count"], merged["pages_observed"]) == (3, 3, 2)
    assert merged["companies"][0]["name"] == "TikTok"  # advertising is listed first


# --- server: the `jurisdiction` field ----------------------------------------------

@pytest.fixture
def no_crawl(monkeypatch):
    started = []

    def fake_job(job_id, url, page_cap, **kwargs):
        started.append(kwargs.get("jurisdiction"))
        release = getattr(server, "_release_slot", None) or server._check_semaphore.release
        release()

    monkeypatch.setattr(server, "_run_crawl_job", fake_job)
    monkeypatch.setattr(server, "validate_public_url", lambda url: None)
    server._global_run_times.clear()
    server._ip_run_times.clear()
    yield started
    server._global_run_times.clear()
    server._ip_run_times.clear()


def _wait_for(started, n):
    deadline = time.time() + 5
    while len(started) < n and time.time() < deadline:
        time.sleep(0.01)  # the crawl job starts on its own thread


def test_check_jurisdiction_defaults_to_us(no_crawl):
    client = TestClient(server.app)
    r = client.post("/api/check", json={"url": "https://example.com", "authorized": True})
    assert r.status_code == 200
    _wait_for(no_crawl, 1)
    assert no_crawl == ["us"]
    r = client.post("/api/check", json={"url": "https://example.com", "authorized": True, "jurisdiction": "both"})
    assert r.status_code == 200
    _wait_for(no_crawl, 2)
    assert no_crawl[-1] == "both"


def test_check_rejects_unknown_jurisdiction_in_plain_english(no_crawl):
    client = TestClient(server.app)
    r = client.post("/api/check", json={"url": "https://example.com", "authorized": True, "jurisdiction": "mars"})
    assert r.status_code == 400
    assert "where your visitors are" in r.json()["detail"]
    assert no_crawl == []
