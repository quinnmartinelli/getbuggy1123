"""Unit tests for checks_security.py (GetBuggy Step 5) — pure logic plus a
local TLS server for the certificate check. No live site involved.

Key-shaped test strings are assembled from pieces, never written out whole:
GitHub push protection blocks a push containing anything that looks like a
live key, fake or not."""
import itertools
import re
import shutil
import socket
import ssl
import subprocess
import threading

import pytest
from fastapi.testclient import TestClient

import checks_security as cs
import server

FAKE_STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc0"
FAKE_AWS = "AKIA" + "QX7GETBUGGYFAKE1"
FAKE_SENDGRID = "SG." + "A" * 22 + "." + "B" * 43
REG = lambda host: ".".join(host.split(".")[-2:])  # noqa: E731 — simple stand-in for registrable_domain


# --- gating -----------------------------------------------------------------

def _sec(category, evidence=None):
    return cs._finding(category, "detail with /.env path", cs.HIGH, cs.WHO_WEB_PERSON, evidence=evidence)


def _pub(category):
    return {"category": category, "message": "m", "severity": "low", "confidence": "verified"}


def test_redaction_keeps_public_findings_and_counts_hidden_ones():
    result = {
        "unique_problems": [_sec("Exposed Sensitive File", "/.env"), _pub("Missing Alt Text")],
        "site_findings": [_sec("No Security Headers"), _pub("No Sitemap Found")],
        "pages": [{"url": "u", "problems": [_sec("Exposed Sensitive File", "/.env"), _pub("Missing Alt Text")],
                   "third_party_scripts": ["x.example"]}],
        "security_details": {"probes": [{"url": "https://site/.env", "status": 200}]},
    }
    out = cs.redact_security_details({"status": "done", "result": result})["result"]
    assert [p["category"] for p in out["unique_problems"]] == ["Missing Alt Text"]
    assert [p["category"] for p in out["site_findings"]] == ["No Sitemap Found"]
    assert [p["category"] for p in out["pages"][0]["problems"]] == ["Missing Alt Text"]
    assert "third_party_scripts" not in out["pages"][0]
    assert "security_details" not in out
    assert out["security_summary"]["count"] == 2
    assert out["security_summary"]["message"] == (
        "We found 2 possible security exposures on this site. Verify you own this site to see the details."
    )
    assert "/.env" not in str(out)
    assert result["site_findings"][0]["category"] == "No Security Headers"  # original untouched


def test_deduplicated_security_findings_stay_gated():
    import core
    finding = _sec("Secret Key Exposed In Page Source", "a Stripe secret key|sk_l••••••••")
    pages = [{"url": "https://a", "problems": [dict(finding)]}, {"url": "https://b", "problems": [dict(finding)]}]
    unique = core.dedupe_site_problems(pages)
    assert unique[0]["group"] == cs.SECURITY_GROUP  # dedup must carry the tag
    out = cs.redact_security_details({"result": {"unique_problems": unique, "pages": pages}})["result"]
    assert out["unique_problems"] == [] and "sk_l" not in str(out)
    untagged = {k: v for k, v in finding.items() if k != "group"}
    assert cs.is_security_finding(untagged)  # second line of defence: by category


def test_every_security_finding_category_is_in_the_gate_list():
    import inspect
    import checks_seo
    src = inspect.getsource(cs) + inspect.getsource(checks_seo)
    produced = {m.replace('\\"', '"') for m in re.findall(r'(?<!\w)_finding\(\s*"((?:[^"\\]|\\.)+)"', src)} | set(re.findall(r'"(Mixed Content \(\w+\))"', src))
    public = {"robots.txt Is Erroring", 'Missing Pages Don\'t Say "Not Found"', "Plain Server Error Page",
              "Favicon Doesn't Load", "Web App Manifest Missing", "Site Answers On Both www And Non-www"}
    assert produced - public <= cs.SECURITY_CATEGORIES


def test_redaction_of_in_progress_pages_and_clean_results():
    job = {"status": "running", "pages_done": [{"problems": [_sec("Site May Be Hacked", "meta-refresh")]}]}
    assert cs.redact_security_details(job)["pages_done"][0]["problems"] == []
    clean = {"status": "done", "result": {"summary": "ok"}}
    assert cs.redact_security_details(clean) == clean  # nothing hidden -> nothing added


def test_check_status_gates_details_unless_flag_is_set(monkeypatch):
    finding = _sec("Exposed Sensitive File", "/.env")
    with server._jobs_lock:
        server._jobs["sec-job"] = {
            "status": "done", "created_at": 0,
            "result": {"unique_problems": [finding], "site_findings": [], "pages": []},
        }
    client = TestClient(server.app)
    try:
        monkeypatch.delenv(cs.SHOW_DETAILS_ENV_VAR, raising=False)
        hidden = client.get("/api/check-status/sec-job").json()["result"]
        assert hidden["unique_problems"] == [] and hidden["security_summary"]["count"] == 1
        monkeypatch.setenv(cs.SHOW_DETAILS_ENV_VAR, "true")
        shown = client.get("/api/check-status/sec-job").json()["result"]
        assert shown["unique_problems"][0]["evidence"] == "/.env"
    finally:
        with server._jobs_lock:
            server._jobs.pop("sec-job", None)


# --- secrets ----------------------------------------------------------------

def test_secrets_are_found_and_masked():
    text = f'var a = "{FAKE_STRIPE}"; var b = "{FAKE_AWS}"; key="{FAKE_SENDGRID}"'
    hits = cs.find_secrets(text)
    kinds = {k for k, _ in hits}
    assert kinds == {"a Stripe secret key", "an Amazon Web Services access key", "a SendGrid API key"}
    rendered = str(cs.secret_findings(hits, "this page"))
    for raw in (FAKE_STRIPE, FAKE_AWS, FAKE_SENDGRID):
        assert raw not in rendered
        assert raw[6:] not in rendered


def test_publishable_and_analytics_keys_are_not_secrets():
    assert cs.find_secrets('Stripe("pk_' + 'live_' + 'abcdefghijklmnopqrstuvwx"); gtag("G-ABC123"); "AIza' + 'Sy' + 'x' * 33 + '"') == []


def test_private_key_and_smtp_password():
    hits = cs.find_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\nsmtp://mailer:hunter2pass@smtp.example.com")
    assert {k for k, _ in hits} == {"a private encryption key", "an email server (SMTP) password"}
    assert "hunter2pass" not in str(hits)


# --- headers ----------------------------------------------------------------

def test_no_security_headers_is_medium_and_hsts_only_counts_on_https():
    [f] = cs.analyze_security_headers({}, is_https=False)
    assert (f["category"], f["severity"]) == ("No Security Headers", cs.MEDIUM)
    present = {
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()", "Content-Security-Policy": "default-src 'self'",
    }
    assert cs.analyze_security_headers(present, is_https=False) == []
    [missing_hsts] = cs.analyze_security_headers(present, is_https=True)
    assert missing_hsts["severity"] == cs.LOW and missing_hsts["evidence"] == "hsts"


def test_frame_ancestors_counts_as_framing_protection_and_version_leak():
    findings = cs.analyze_security_headers(
        {"Content-Security-Policy": "frame-ancestors 'none'", "Server": "Apache/2.4.29 (Ubuntu)"}, is_https=False
    )
    missing = next(f for f in findings if f["category"] == "Missing Security Headers")
    assert "framing" not in missing["evidence"] and "csp" not in missing["evidence"]
    assert any(f["category"] == "Server Software Version Revealed" for f in findings)
    assert not any(f["category"] == "Server Software Version Revealed"
                   for f in cs.analyze_security_headers({"Server": "cloudflare"}, is_https=False))


# --- endpoints --------------------------------------------------------------

@pytest.mark.parametrize("path,body,exposed", [
    ("/.env", b"DB_HOST=x\nDB_PASSWORD=y\n", True),
    ("/.env", b"<!DOCTYPE html><html><body>Home</body></html>", False),
    ("/.git/HEAD", b"ref: refs/heads/main\n", True),
    ("/.git/HEAD", b"<html>not found</html>", False),
    ("/.git/config", b"[core]\n\tbare = false\n", True),
    ("/wp-config.php.bak", b"define('DB_PASSWORD', 'x');", True),
    ("/backup.zip", b"PK\x03\x04rest", True),
    ("/backup.zip", b"<html>", False),
    ("/phpinfo.php", b"<title>phpinfo()</title>", True),
    ("/.DS_Store", b"\x00\x00\x00\x01Bud1\x00", True),
])
def test_sensitive_file_plausibility(path, body, exposed):
    check = next(c for p, _desc, c in cs.SENSITIVE_FILES if p == path)
    assert bool(check(body)) is exposed


def test_directory_listing_and_raw_error_pages():
    assert cs.looks_like_directory_listing("Index of /uploads", "")
    assert cs.looks_like_directory_listing("", "<h1>Directory listing for /</h1>")
    assert not cs.looks_like_directory_listing("Our index of recipes", "<h1>Recipes</h1>")
    assert cs.looks_like_raw_server_error("<center><h1>404 Not Found</h1></center><hr><center>nginx</center>")
    assert not cs.looks_like_raw_server_error("<h1>Sorry, that page is gone</h1><a href='/'>Home</a>")


def test_www_partner_host():
    assert cs._other_www_host("example.com") == "www.example.com"
    assert cs._other_www_host("www.example.com") == "example.com"
    assert cs._other_www_host("127.0.0.1") is None


# --- versions ---------------------------------------------------------------

def test_compare_versions():
    assert cs.compare_versions("1.8.3", "1.9.0") == -1
    assert cs.compare_versions("3.5.1", "3.5.1") == 0
    assert cs.compare_versions("1.10", "1.9") == 1
    assert cs.compare_versions("2.0.0-beta1", "2.0.0") == -1
    assert cs.compare_versions("v4.0", "4.0.0") == 0


def test_library_detection_and_known_vulnerabilities():
    assert ("jquery", "1.8.3") in cs._collapse_versions(
        cs.detect_libraries_from_url("https://code.jquery.com/jquery-1.8.3.min.js")
    )
    assert cs.detect_libraries_from_content("/*! jQuery v1.8.3 jquery.com */") == {("jquery", "1.8.3")}
    [f] = cs.library_findings({("jquery", "1.8.3")})
    assert f["severity"] == cs.MEDIUM and "CVE-" in f["message"] and f["group"] == cs.SECURITY_GROUP
    assert cs.library_findings({("jquery", "3.7.1")}) == []
    assert all("require(" not in expr for _lib, expr in cs.library_probe_expressions())


def test_wordpress_core_and_plugins():
    html = ('<meta name="generator" content="WordPress 5.8.1">'
            '<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.4"></script>')
    findings, notes = cs.wordpress_findings(html)
    cats = {f["category"]: f for f in findings}
    assert cats["WordPress Version Has Known Security Problems"]["severity"] == cs.HIGH
    assert cats["WordPress Plugins Out Of Date"]["severity"] == cs.MEDIUM
    assert any("plugin security problems" in n for n in notes)  # says what it couldn't check
    latest = next(v for v, s in cs.load_data("wordpress_core.json")["versions"].items() if s == "latest")
    assert cs.wordpress_findings(f'<meta name="generator" content="WordPress {latest}">')[0] == []


@pytest.mark.parametrize("html,headers,platform", [
    ('<link href="/wp-content/themes/x/style.css">', {}, "WordPress"),
    ('<script src="//cdn.shopify.com/s/files/x.js">', {}, "Shopify"),
    ("", {"X-Wix-Request-Id": "1"}, "Wix"),
    ('<link href="https://static1.squarespace.com/x.css">', {}, "Squarespace"),
    ('<html data-wf-site="abc">', {}, "Webflow"),
    ('<meta name="generator" content="Joomla! - Open Source">', {}, "Joomla"),
    ('<meta name="Generator" content="Drupal 10">', {}, "Drupal"),
    ("<h1>Plain site</h1>", {"Server": "nginx"}, None),
])
def test_platform_detection(html, headers, platform):
    assert cs.detect_platform(html, headers) == platform


# --- compromise signals -----------------------------------------------------

def test_offsite_redirects_only_count_when_they_leave_the_site():
    refresh, scripts = cs.parse_page_source(
        '<meta http-equiv="refresh" content="0;url=https://spam.example.net/x">'
        '<script>location.href = "https://www.bakery.com/menu";</script>'
        '<script>window.location.replace("https://evil.example.org/");</script>'
    )
    assert cs.offsite_meta_refresh(refresh, "https://bakery.com/", "bakery.com", REG) == "https://spam.example.net/x"
    assert cs.offsite_js_redirects(scripts, "bakery.com", REG) == ["https://evil.example.org/"]
    same_site, _ = cs.parse_page_source('<meta http-equiv="refresh" content="5;url=/home">')
    assert cs.offsite_meta_refresh(same_site, "https://bakery.com/", "bakery.com", REG) is None


def test_obfuscation_needs_execute_decode_and_a_long_blob():
    assert cs.obfuscated_inline_scripts(['eval(atob("' + "QUJD" * 100 + '"))'])
    assert not cs.obfuscated_inline_scripts(['var data = "' + "QUJD" * 100 + '";'])  # no execute
    assert not cs.obfuscated_inline_scripts(["eval(atob('aGk='))"])  # no long blob
    assert not cs.obfuscated_inline_scripts(["window.dataLayer=window.dataLayer||[];function gtag(){}"])


def test_hidden_spam_links_need_two_offsite_spammy_links():
    links = [{"href": "https://casino.example.net/", "text": "best casino"},
             {"href": "https://x.example.org/viagra", "text": "click"}]
    assert len(cs.hidden_spam_links(links, "bakery.com", REG)) == 2
    assert cs.hidden_spam_links(links[:1], "bakery.com", REG) == []
    assert cs.hidden_spam_links([{"href": "https://bakery.com/casino-night", "text": "casino night"}] * 2,
                                "bakery.com", REG) == []


def test_cloaked_spam_needs_both_a_mismatch_and_spam_words():
    words = ["".join(t) for t in itertools.product("bcdfgk", "aeiou", "lmnrst")]  # 180 distinct
    visible = " ".join(words[:30])
    spammy = "<p>" + visible + "</p>" + "<div>" + " ".join(
        ["casino", "viagra", "payday", "loans"] + words[30:150]) + "</div>"
    assert "casino" in cs.cloaked_spam(spammy, visible)
    app_shell = "<p>" + " ".join(words[30:150]) + "</p>"
    assert cs.cloaked_spam(app_shell, visible) == []  # very different, but no spam


# --- third-party scripts ----------------------------------------------------

def test_unresolvable_hosts_and_sri():
    assert cs.host_resolves("getbuggy-test.invalid") is False
    f = cs.missing_sri_finding(["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"])
    assert f["severity"] == cs.LOW and "jquery.min.js" in f["message"]


# --- certificate ------------------------------------------------------------

def test_certificate_findings_thresholds():
    assert cs.certificate_findings({"ok": True, "days_left": 90})[:1] == []
    assert cs.certificate_findings({"ok": True, "days_left": 20})[0]["severity"] == cs.MEDIUM
    assert cs.certificate_findings({"ok": True, "days_left": 5})[0]["severity"] == cs.HIGH
    bad = cs.certificate_findings({"ok": False, "problem": "has expired", "message": "It has expired"})
    assert bad[0]["severity"] == cs.HIGH and bad[0]["category"] == "Security Certificate Problem"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl to make a test certificate")
def test_self_signed_certificate_is_reported(tmp_path):
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def serve_once():
        conn, _ = listener.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1024)
        except (ssl.SSLError, OSError):
            pass  # the client rejects the certificate mid-handshake — expected

    threading.Thread(target=serve_once, daemon=True).start()
    try:
        result = cs.check_certificate("localhost", port, timeout=5)
    finally:
        listener.close()
    assert result["ok"] is False and result["problem"] == "is self-signed"
