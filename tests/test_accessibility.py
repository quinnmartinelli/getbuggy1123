"""Unit tests for the pure-logic parts of checks_accessibility.py (Step 6)
— rule translation/grouping, media rules, overlay detection, the
accessibility-statement check, the crawl's scan-time budget, and the
report summary. No browser: the in-browser parts (axe, Tab-through focus)
are covered by regression_check.py's test_page_a11y.html and
test_site_a11y/ fixtures.
"""
import core
import checks_accessibility as ca


def _violation(rule, count=1, impact="serious", help_text=None, examples=None):
    return {
        "id": rule,
        "impact": impact,
        "help": help_text or rule,
        "helpUrl": "",
        "count": count,
        "examples": examples or [{"selector": f".{rule}", "label": f'"{rule}" (text)'}],
    }


# --- axe_violations_to_problems ---

def test_rules_with_the_same_meaning_merge_into_one_finding():
    problems = ca.axe_violations_to_problems(
        [_violation("label", 2), _violation("select-name", 1), _violation("color-contrast", 5)]
    )
    by_category = {p["category"]: p for p in problems}
    assert set(by_category) == {"Form Fields Without Labels", "Hard-to-Read Text (Low Contrast)"}
    labels = by_category["Form Fields Without Labels"]
    assert labels["element_count"] == 3
    assert labels["evidence"] == "label, select-name"
    assert labels["severity"] == ca.MEDIUM
    assert labels["confidence"] == ca.VERIFIED
    assert labels["topic"] == ca.TOPIC


def test_every_translated_finding_says_what_why_how_and_who():
    a_rule_for = {k: r for r, k in ca.AXE_RULE_TO_CATEGORY.items()}
    a_rule_for["aria"] = "aria-roles"  # reached by the "aria-" prefix, not the table
    for key, spec in ca.A11Y_CATEGORIES.items():
        rule = a_rule_for[key]
        message = ca.axe_violations_to_problems([_violation(rule)])[0]["message"]
        assert spec["what"] in message
        assert "Why it matters:" in message
        assert "How to fix:" in message
        assert "Who fixes it:" in message


def test_unmapped_aria_rule_goes_to_the_aria_category():
    problems = ca.axe_violations_to_problems([_violation("aria-some-future-rule")])
    assert problems[0]["category"] == "Screen-Reader Code (ARIA) Used Incorrectly"


def test_untranslated_rule_is_reported_not_dropped():
    problems = ca.axe_violations_to_problems(
        [_violation("brand-new-rule", help_text="Widgets must be frobbed")]
    )
    assert problems[0]["category"] == "Accessibility: Widgets must be frobbed"
    assert problems[0]["severity"] == ca.LOW


def test_every_mapped_rule_points_at_a_real_category():
    assert set(ca.AXE_RULE_TO_CATEGORY.values()) <= set(ca.A11Y_CATEGORIES)


def test_rules_covered_elsewhere_or_removed_on_purpose_are_disabled():
    rules = ca.AXE_OPTIONS["rules"]
    for rule in ("image-alt", "document-title", "target-size"):
        assert rules[rule] == {"enabled": False}
    for rule in ("heading-order", "duplicate-id"):
        assert rules[rule] == {"enabled": True}
    assert ca.AXE_OPTIONS["iframes"] is False


# --- media_problems ---

def _media(**kw):
    base = {"tag": "video", "src": "", "autoplay": False, "muted": False,
            "controls": True, "duration": None, "captions": False}
    base.update(kw)
    return base


def test_audible_autoplay_is_medium_verified():
    problems = ca.media_problems([_media(tag="audio", autoplay=True, controls=False, captions=True)])
    assert [p["category"] for p in problems] == ["Media Plays Automatically With Sound"]
    assert problems[0]["severity"] == ca.MEDIUM
    assert problems[0]["confidence"] == ca.VERIFIED


def test_short_autoplay_clip_is_exempt():
    assert ca.media_problems([_media(tag="audio", autoplay=True, duration=2.0, captions=True)]) == []


def test_silent_background_loop_is_not_flagged_at_all():
    assert ca.media_problems([_media(autoplay=True, muted=True, controls=False)]) == []


def test_watchable_video_without_captions_is_medium_needs_look():
    problems = ca.media_problems([_media(src="tour.mp4")])
    assert [p["category"] for p in problems] == ["Video Without Captions"]
    assert problems[0]["confidence"] == ca.NEEDS_LOOK
    assert '"tour.mp4"' in problems[0]["message"]


def test_captioned_video_is_fine():
    assert ca.media_problems([_media(captions=True)]) == []


# --- overlays ---

def test_detects_overlay_vendors_by_host():
    urls = [
        "https://cdn.userway.org/widget.js",
        "https://acsbapp.com/apps/app/dist/js/app.js",
        "https://example.com/userway.org/fake.js",  # path, not host: ignored
    ]
    assert ca.detect_overlay_vendors(urls) == ["accessiBe", "UserWay"]


def test_overlay_finding_says_it_does_not_confer_compliance():
    p = ca.overlay_problem(["UserWay"])
    assert p["confidence"] == ca.NEEDS_LOOK
    assert "does not make your site accessible or compliant" in p["message"]


# --- accessibility statement ---

def test_statement_found_from_footer_link_text():
    links = [{"text": "Accessibility", "href": "/pages/a11y-info"}]
    assert ca.has_accessibility_statement(links)


def test_statement_found_from_sitemap_path():
    assert ca.has_accessibility_statement([], ["https://x.com/accessibility-statement"])


def test_statement_missing():
    links = [{"text": "Contact", "href": "/contact"}, {"text": "Shop", "href": "/shop"}]
    assert not ca.has_accessibility_statement(links, ["https://x.com/about"])


def test_missing_statement_is_low():
    assert ca.missing_statement_finding()["severity"] == ca.LOW


# --- scan-time budget ---

def test_budget_scans_everything_until_a_scan_is_slow(monkeypatch):
    monkeypatch.setenv("A11Y_SLOW_SCAN_SECONDS", "10")
    budget = ca.A11yScanBudget()
    assert budget.should_scan("https://x.com/about", False)
    budget.record("https://x.com/", 2.0, timed_out=False)
    assert budget.should_scan("https://x.com/about", False)
    budget.record("https://x.com/", 12.0, timed_out=False)
    assert not budget.should_scan("https://x.com/about", False)
    # homepage and contact/booking pages are always scanned
    assert budget.should_scan("https://x.com/", True)
    assert budget.should_scan("https://x.com/contact-us", False)
    assert budget.should_scan("https://x.com/book-a-table", False)
    assert budget.skipped_pages == ["https://x.com/about"]
    assert "took 12s" in str(budget.reduced_because)
    assert "https://x.com/" in str(ca.site_skipped_scan_note(budget))


def test_budget_reduces_on_timeout():
    budget = ca.A11yScanBudget()
    budget.record("https://x.com/", 0.5, timed_out=True)
    assert not budget.should_scan("https://x.com/blog", False)


def test_no_site_note_when_nothing_was_skipped():
    assert ca.site_skipped_scan_note(ca.A11yScanBudget()) is None


# --- dedupe + summary ---

def test_dedupe_sums_element_counts_across_pages():
    finding = ca.axe_violations_to_problems([_violation("color-contrast", 4)])[0]
    second = dict(finding, element_count=6)
    unique = core.dedupe_site_problems([
        {"url": "https://x.com/", "problems": [finding]},
        {"url": "https://x.com/about", "problems": [second]},
    ])
    assert len(unique) == 1
    assert unique[0]["element_count"] == 10
    assert unique[0]["topic"] == ca.TOPIC
    assert unique[0]["pages"] == ["https://x.com/", "https://x.com/about"]


def test_summary_always_has_the_disclaimer_and_ranks_by_severity_then_elements():
    assert ca.accessibility_summary([])["note"] == ca.DISCLAIMER
    assert "not mean your site is accessible or legally compliant" in ca.DISCLAIMER
    unique = [
        {"category": "A", "severity": ca.LOW, "topic": ca.TOPIC, "element_count": 50, "pages": ["p1"]},
        {"category": "B", "severity": ca.MEDIUM, "topic": ca.TOPIC, "element_count": 2, "pages": ["p1", "p2"]},
        {"category": "C", "severity": ca.MEDIUM, "topic": ca.TOPIC, "element_count": 9, "pages": ["p1"]},
        {"category": "Broken Link", "severity": ca.HIGH, "pages": ["p1"]},
    ]
    summary = ca.accessibility_summary(unique, [ca.missing_statement_finding()])
    assert [t["category"] for t in summary["top"]] == ["C", "B", "A", "No Accessibility Statement"]
    assert summary["top"][1] == {"category": "B", "severity": ca.MEDIUM, "pages": 2, "elements": 2}
    assert summary["total"] == 4
