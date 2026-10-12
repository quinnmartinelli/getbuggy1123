"""Unit tests for regression_check.py's own comparison logic
(categorize/diff_report/timing tolerance) — this is what decides
PASS/FAIL for every fixture, so a bug here could hide a real regression
silently. No browser involved.
"""
import regression_check as rc


def test_categorize_counts_by_category():
    problems = [
        {"category": "Broken Link"},
        {"category": "Broken Link"},
        {"category": "Missing Alt Text"},
    ]
    counts = rc.categorize(problems)
    assert counts["Broken Link"] == 2
    assert counts["Missing Alt Text"] == 1


def test_diff_report_passes_on_exact_match():
    fail_lines, note_lines = rc.diff_report({"Broken Link": 1}, {"Broken Link": 1})
    assert fail_lines == []


def test_diff_report_fails_on_missing_category():
    fail_lines, _ = rc.diff_report({"Broken Link": 1}, {})
    assert len(fail_lines) == 1
    assert "MISSING" in fail_lines[0]


def test_diff_report_fails_on_unexpected_category():
    fail_lines, _ = rc.diff_report({}, {"Broken Link": 1})
    assert len(fail_lines) == 1
    assert "UNEXPECTED" in fail_lines[0]


def test_diff_report_fails_on_count_mismatch():
    fail_lines, _ = rc.diff_report({"Broken Link": 1}, {"Broken Link": 2})
    assert len(fail_lines) == 1
    assert "COUNT MISMATCH" in fail_lines[0]


def test_diff_report_tolerates_flaky_category_within_bound():
    fail_lines, note_lines = rc.diff_report(
        {"Broken Link": 0}, {"Broken Link": 1}, flaky={"Broken Link": 1}
    )
    assert fail_lines == []
    assert len(note_lines) == 1


def test_diff_report_still_fails_flaky_category_beyond_tolerance():
    fail_lines, _ = rc.diff_report(
        {"Broken Link": 0}, {"Broken Link": 5}, flaky={"Broken Link": 1}
    )
    assert len(fail_lines) == 1


def test_diff_report_never_fails_timing_category_within_band():
    category = next(iter(rc.TIMING_TOLERANT_CATEGORIES))
    tolerance = rc.TIMING_TOLERANT_CATEGORIES[category]
    fail_lines, note_lines = rc.diff_report({}, {category: tolerance})
    assert fail_lines == []
    assert note_lines == []


def test_diff_report_never_fails_timing_category_outside_band_either():
    """The whole point of TIMING_TOLERANT_CATEGORIES: a deviation past
    the tolerance band is still just a note, never a failure."""
    category = next(iter(rc.TIMING_TOLERANT_CATEGORIES))
    tolerance = rc.TIMING_TOLERANT_CATEGORIES[category]
    fail_lines, note_lines = rc.diff_report({}, {category: tolerance + 10})
    assert fail_lines == []
    assert len(note_lines) == 1


def test_diff_report_structural_categories_are_still_exact():
    """A category not in TIMING_TOLERANT_CATEGORIES must still fail on
    any deviation, however small — timing tolerance doesn't leak into
    structural findings."""
    assert "Broken Link" not in rc.TIMING_TOLERANT_CATEGORIES
    fail_lines, _ = rc.diff_report({"Broken Link": 1}, {"Broken Link": 2})
    assert len(fail_lines) == 1


def test_skip_live_excludes_targets_marked_live():
    live_targets = [t for t in rc.TARGETS if t.get("live")]
    assert len(live_targets) >= 1, "expected at least one live-site target (medvi.org)"
    non_live = [t for t in rc.TARGETS if not t.get("live")]
    assert len(non_live) >= 1, "expected at least one non-live (local fixture) target"
