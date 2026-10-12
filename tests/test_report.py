"""Step 8: the report score, finding schema, report areas, partial labels,
re-check delta and the "send to your web person" export (report.py,
finding_guide.py). Pure logic — no browser."""
import copy
import re

import pytest

import finding_guide
import report

SCHEMA_FIELDS = {"id", "category", "severity", "confidence", "title", "why_it_matters",
                 "how_to_fix", "who_fixes", "pages", "evidence", "check_version"}


def f(category, severity="low", confidence="verified", **extra):
    return dict({"category": category, "message": f"{category} on this site.",
                 "severity": severity, "confidence": confidence}, **extra)


def result(unique=(), site=(), pages=None, **extra):
    pages = pages if pages is not None else [{"url": "https://x.com/", "problems": [], "could_not_check": []}]
    return dict({"pages_found_total": len(pages), "pages_planned": len(pages),
                 "pages_checked": len(pages), "pages": pages, "site_findings": list(site),
                 "unique_problems": list(unique), "site_could_not_check": [], "partial": False}, **extra)


def finalized(*args, previous=None, **kwargs):
    return report.finalize_report(result(*args, **kwargs), url="https://x.com/", report_id="r" * 22,
                                  checked_at="2026-10-11T12:00:00+00:00", previous=previous)


# --- score -------------------------------------------------------------------

def test_clean_site_scores_100():
    s = finalized()["score"]
    assert s["value"] == 100 and s["band"] == "In good shape" and s["deductions"] == []


def test_points_per_severity():
    s = finalized(unique=[f("Broken Form", "high"), f("Missing Page Title", "medium"),
                          f("Missing Favicon", "low")])["score"]
    assert s["value"] == 100 - 15 - 5 - 1


def test_needs_look_and_informational_findings_never_count():
    s = finalized(unique=[
        f("Broken Link", "high", "needs_look"),
        f("Embedded Form", "low", informational=True),
    ])["score"]
    assert s["value"] == 100
    assert s["needs_look_not_counted"] == 1


def test_one_area_can_take_off_at_most_its_cap():
    many = [f("Broken Form", "high", evidence=str(i)) for i in range(10)]  # 150 points, one area
    s = finalized(unique=many)["score"]
    assert s["value"] == 100 - report.AREA_CAP_POINTS
    (forms,) = s["deductions"]
    assert forms["area"] == "forms" and forms["capped"] and forms["uncapped_points"] == 150


def test_score_never_goes_below_zero():
    areas = ["Broken Form", "Broken Link", "Failed Network Request", "Render-Blocking Scripts",
             "Mobile Horizontal Scroll", "Missing Page Title", "Hard-to-Read Text (Low Contrast)",
             "Sitemap Lists Missing Pages"]
    unique = [f(c, "high", evidence=str(i)) for c in areas for i in range(3)]
    assert finalized(unique=unique)["score"]["value"] == 0


def test_security_and_accessibility_go_to_their_own_areas_by_field():
    s = finalized(unique=[f("Anything", "high", group="security"),
                          f("Something Else", "medium", topic="accessibility")])["score"]
    assert {d["area"]: d["points"] for d in s["deductions"]} == {"accessibility": 5, "security": 15}


def test_site_wide_findings_count_too():
    assert finalized(site=[f("Site Blocked From Search (robots.txt)", "high")])["score"]["value"] == 85


def test_no_score_without_an_opened_page():
    s = finalized(pages=[{"url": "https://x.com/", "problems": [], "could_not_check": [],
                          "could_not_load": True}])["score"]
    assert s["value"] is None and "couldn't open any pages" in s["reason"]


def test_same_input_same_score_regardless_of_order():
    unique = [f("Broken Form", "high"), f("Missing Favicon"), f("Heavy Page", "low"),
              f("Missing Page Title", "medium")]
    a = finalized(unique=copy.deepcopy(unique))["score"]
    b = finalized(unique=list(reversed(copy.deepcopy(unique))))["score"]
    assert a["value"] == b["value"] and report.scores_match(a, b)


def test_timing_tolerance_only_forgives_timing_findings():
    base = [f("Broken Form", "high")]
    a = finalized(unique=copy.deepcopy(base))["score"]
    slow = finalized(unique=copy.deepcopy(base) + [f("Slow Server Response", "medium")])["score"]
    assert slow["value"] == a["value"] - 5 and slow["timing_sensitive_points"] == 5
    assert report.scores_match(a, slow)  # differs only by a timing finding
    broken = finalized(unique=copy.deepcopy(base) + [f("Missing Page Title", "medium")])["score"]
    assert not report.scores_match(a, broken)


# --- finding schema ----------------------------------------------------------

def test_every_finding_gets_the_standard_schema():
    r = finalized(
        unique=[f("Broken Form", "high", evidence="form#contact", pages=["https://x.com/contact"])],
        site=[f("No Sitemap Found")],
        pages=[{"url": "https://x.com/", "problems": [f("Missing Favicon")], "could_not_check": []}],
    )
    for finding in r["unique_problems"] + r["site_findings"] + r["pages"][0]["problems"]:
        assert SCHEMA_FIELDS <= set(finding), SCHEMA_FIELDS - set(finding)
        assert finding["who_fixes"] in finding_guide.WHO_VALUES
        assert re.match(r"^f-[0-9a-f]{12}$", finding["id"])
    assert r["unique_problems"][0]["pages"] == ["https://x.com/contact"]
    assert r["site_findings"][0]["pages"] == []  # site-wide
    assert r["pages"][0]["problems"][0]["pages"] == ["https://x.com/"]
    assert r["unique_problems"][0]["check_version"].startswith("forms/")


def test_finding_id_is_stable_and_follows_dedup_identity():
    a = report.finding_id({"category": "Broken Link", "evidence": "https://x.com/a"})
    assert a == report.finding_id({"category": "Broken Link", "evidence": "https://x.com/a"})
    assert a != report.finding_id({"category": "Broken Link", "evidence": "https://x.com/b"})


def test_evidence_is_masked_and_capped():
    key = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
    masked = report.mask_evidence(f"token {key} in page")
    assert key not in masked and "sk_l" in masked
    assert len(report.mask_evidence("x" * 1000)) == report.MAX_EVIDENCE_CHARS
    assert report.mask_evidence(3_400_000) == "3400000"


def test_hosted_platform_gets_a_platform_note_for_host_fixes():
    r = finalized(site=[f("Site Answers On Both www And Non-www")], platform="Shopify")
    assert "Shopify support" in r["site_findings"][0]["platform_note"]
    assert "platform_note" not in finalized(site=[f("No Sitemap Found")])["site_findings"][0]


def _category_literals():
    """Every category name the pre-Step-7 check modules can emit."""
    names = set()
    for path in ("core.py", "checks_seo.py", "checks_links.py", "checks_performance.py",
                 "checks_security.py", "checks_accessibility.py"):
        src = open(path, encoding="utf-8").read()
        names |= set(re.findall(r'"category":\s*"([^"]+)"', src))
        names |= set(re.findall(r'_finding\(\s*"([A-Z][^"]+)"', src))
        names |= set(re.findall(r'classify\([^)]*"(JavaScript [^"]+)"\)', src))
    names.add("Mixed Content (Passive)")
    names.add('Missing Pages Don\'t Say "Not Found"')
    names.discard("Missing Pages Don't Say \\")  # regex artefact of the escaped quote
    return names


def test_every_category_has_written_guidance():
    missing = sorted(c for c in _category_literals() if c not in finding_guide.GUIDE)
    assert not missing, f"add these to finding_guide.GUIDE: {missing}"


def test_unknown_category_still_gets_honest_generic_guidance():
    g = finding_guide.guide_for("Something New", "high")
    assert g["why"] and g["how"] and g["who"] == finding_guide.WEB_PERSON


# --- report areas ------------------------------------------------------------

def test_clean_areas_say_so_and_areas_with_findings_count_them():
    r = finalized(unique=[f("Broken Form", "high"), f("Form Needs A Look", "medium", "needs_look")])
    by_area = {s["area"]: s for s in r["sections"]}
    assert by_area["forms"]["status"] == "issues" and by_area["forms"]["count"] == 2
    assert "1 of them needs a look" in by_area["forms"]["line"]
    assert by_area["security"]["status"] == "clean"
    assert by_area["security"]["line"] == "No exposed files or hacked-site signals found on the pages we checked."
    assert by_area["setup"]["line"] == "No problems with robots.txt, your sitemap or redirects."


def test_sections_never_carry_finding_text():
    r = finalized(unique=[f("Exposed Sensitive File", "high", group="security", evidence="/.env")])
    sec = next(s for s in r["sections"] if s["area"] == "security")
    assert sec["line"] == "1 possible security exposure found."
    assert ".env" not in str(r["sections"])


def test_areas_not_checked_are_not_called_clean():
    r = finalized(pages=[{"url": "https://x.com/", "problems": [], "could_not_check": [],
                          "could_not_load": True}])
    by_area = {s["area"]: s["status"] for s in r["sections"]}
    assert by_area["links"] == by_area["security"] == "not_checked"
    assert by_area["setup"] == "clean"  # site-wide checks still ran
    skipped = finalized(site_could_not_check=[
        "Security and site-setup checks were switched off on this server for this run, so none of them ran."])
    assert {s["area"]: s["status"] for s in skipped["sections"]}["security"] == "not_checked"


def test_a_newer_checks_topic_becomes_its_own_area():
    r = finalized(unique=[f("Some Cookie Thing", "medium", topic="cookies")])
    assert any(s["area"] == "cookies" and s["status"] == "issues" for s in r["sections"])
    assert r["score"]["value"] == 95


# --- partial ------------------------------------------------------------------

def test_a_page_that_could_not_open_makes_the_report_partial():
    r = finalized(pages=[
        {"url": "https://x.com/", "problems": [], "could_not_check": []},
        {"url": "https://x.com/slow", "problems": [], "could_not_check": [], "could_not_load": True},
    ])
    assert r["partial"] is True and r["partial_reason"] == "pages_failed"
    assert r["not_completed"] == ["https://x.com/slow couldn't be opened, so nothing on it was checked."]
    assert r["summary"].startswith("Partial report — 1 of 2 pages could be opened and checked")
    assert r["score"]["value"] == 100 and r["score"]["partial"] is True


# --- re-check delta -------------------------------------------------------------

def test_recheck_shows_the_change_since_last_time():
    before = finalized(unique=[f("Broken Form", "high")])
    after = finalized(previous=report.previous_summary(before))
    change = after["score"]["change"]
    assert change["delta"] == 15 and change["previous_value"] == 85
    assert change["message"].startswith("Up 15 points since your last check on Oct 11, 2026.")
    assert change["comparable"] is True


def test_recheck_warns_when_our_checks_changed():
    before = finalized()
    prev = report.previous_summary(before)
    prev["check_versions"] = dict(prev["check_versions"], forms="2020-01-01")
    change = finalized(previous=prev)["score"]["change"]
    assert change["delta"] == 0 and "Forms" in change["message"] and "may come from GetBuggy" in change["message"]


def test_recheck_of_another_site_is_ignored():
    prev = report.previous_summary(finalized())
    prev["url"] = "https://other.com/"
    assert "change" not in finalized(previous=prev)["score"]


def test_same_site_treats_www_as_the_same():
    assert report.same_site("https://www.x.com/a", "http://x.com/")
    assert not report.same_site("https://x.com/", "https://y.com/")
    assert not report.same_site("ok", "ok")


# --- export --------------------------------------------------------------------

def test_export_reads_well_and_says_who_fixes_what():
    r = finalized(unique=[f("Broken Form", "high", pages=["https://x.com/contact"])],
                  site=[f("No Sitemap Found")])
    text = report.render_export(r, permalink="https://getbuggy.ai/r/abc")
    assert text.startswith("# Website check for https://x.com/")
    assert "Full report: https://getbuggy.ai/r/abc" in text
    assert "**Score: 84/100 — A few things to fix**" in text
    assert "### 1. [High] Broken Form" in text
    assert "Why it matters:" in text and "How to fix it:" in text and "Who fixes it: your web person" in text
    assert "Found on: https://x.com/contact" in text
    assert "Found on: your whole site" in text
    assert "Links and pages — OK: No broken links or missing pages found on the pages we checked." in text
    assert "Reports are deleted 30 days after they're made." in text


def test_export_does_not_repeat_guidance_already_in_the_message():
    msg = ("Some links have no text. Affects 2 elements on this page. Why it matters: screen readers "
           "say just \"link\". How to fix: Add text. Who fixes it: your web person. (For your web "
           "person: axe-core rule link-name; first elements: .nav a.)")
    r = finalized(unique=[f("Empty Links (No Link Text)", "medium", topic="accessibility", message=msg)])
    text = report.render_export(r)
    assert "What's wrong: Some links have no text. Affects 2 elements on this page.\n" in text
    assert text.count("Why it matters:") == 1
    assert "Details for your web person: axe-core rule link-name; first elements: .nav a" in text


@pytest.mark.parametrize("flag", ["", "true"])
def test_export_never_shows_security_details(monkeypatch, flag):
    monkeypatch.setenv("GETBUGGY_SHOW_SECURITY_DETAILS", flag)
    r = finalized(unique=[f("Secret Key Exposed In Page Source", "high", group="security",
                            evidence="sk_l••••••••", pages=["https://x.com/"])])
    text = report.render_export(r)
    assert "Secret Key" not in text and "sk_l" not in text
    assert "We found 1 possible security exposure on this site." in text


def test_export_of_a_partial_report_lists_what_was_not_done():
    r = finalized(pages=[
        {"url": "https://x.com/", "problems": [], "could_not_check": ["A link needed a login."]},
        {"url": "https://x.com/slow", "problems": [], "could_not_check": [], "could_not_load": True},
    ])
    text = report.render_export(r)
    assert "**This is a partial report.**" in text
    assert "- https://x.com/slow couldn't be opened" in text
    assert "## What we couldn't check" in text and "A link needed a login." in text
