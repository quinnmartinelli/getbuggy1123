"""Unit tests for pure-logic helper functions in core.py and
embedded_form_providers.py — no browser, no network, fast enough to run
on every push/PR in CI (see .github/workflows/ci.yml). The browser-based
checks themselves are covered by regression_check.py's fixture-based
harness, run separately (see CLAUDE.md).
"""
import core
from embedded_form_providers import detect_embedded_form_provider


# --- get_base_domain ---

def test_get_base_domain_simple():
    assert core.get_base_domain("cakesbody.com") == "cakesbody.com"


def test_get_base_domain_subdomain():
    assert core.get_base_domain("cdn.shopify.com") == "shopify.com"


def test_get_base_domain_empty():
    assert core.get_base_domain("") == ""
    assert core.get_base_domain(None) == ""


# --- form-fill constraint helpers ---

def test_clamp_str_length_pads_short_values():
    assert core._clamp_str_length("ab", 5, None) == "abxxx"


def test_clamp_str_length_truncates_long_values():
    assert core._clamp_str_length("abcdef", None, 3) == "abc"


def test_clamp_str_length_noop_when_within_bounds():
    assert core._clamp_str_length("abc", 1, 10) == "abc"


def test_number_within_range_clamps_low():
    assert core._number_within_range("5", "10") == "5"


def test_number_within_range_clamps_below_min():
    assert core._number_within_range("10", "20") == "10"


def test_number_within_range_defaults_to_one_when_unbounded():
    assert core._number_within_range(None, None) == "1"


def test_fill_value_for_phone_pattern_picks_matching_candidate():
    class FakeField:
        def get_attribute(self, name):
            return {
                "name": "phone",
                "pattern": r"\d{3}-\d{3}-\d{4}",
            }.get(name)

    value = core._fill_value_for(FakeField(), "input", "tel")
    assert value == "555-555-5555"


def test_fill_value_for_returns_none_when_pattern_unsatisfiable():
    class FakeField:
        def get_attribute(self, name):
            return {
                "name": "coupon",
                "pattern": r"^[A-Z]{2}-[0-9]{4}-[a-z]{3}$",
            }.get(name)

    assert core._fill_value_for(FakeField(), "input", "text") is None


def test_fill_value_for_email_type():
    class FakeField:
        def get_attribute(self, name):
            return None

    assert core._fill_value_for(FakeField(), "input", "email") == "test@example.com"


# --- summarize_site_check's Pro upsell note ---

def test_summarize_site_check_adds_pro_note_when_capped():
    result = {
        "pages_checked": 5,
        "pages_found_total": 11,
        "pages": [{"problems": []}] * 5,
    }
    summary = core.summarize_site_check(result)
    assert "Checked 5 of 11" in summary
    assert "Pro" in summary


def test_summarize_site_check_omits_pro_note_when_not_capped():
    result = {
        "pages_checked": 3,
        "pages_found_total": 3,
        "pages": [{"problems": []}] * 3,
    }
    summary = core.summarize_site_check(result)
    assert "Checked 3 of 3" in summary
    assert "Pro" not in summary


# --- embedded_form_providers.detect_embedded_form_provider ---

def test_detect_embedded_form_provider_matches_known_domain():
    assert detect_embedded_form_provider("https://calendly.com/acme/30min") == "Calendly"


def test_detect_embedded_form_provider_matches_subdomain():
    assert detect_embedded_form_provider("https://forms.hsforms.com/abc") == "HubSpot"


def test_detect_embedded_form_provider_requires_path_for_google_forms():
    assert (
        detect_embedded_form_provider("https://docs.google.com/document/d/abc")
        is None
    )
    assert (
        detect_embedded_form_provider(
            "https://docs.google.com/forms/d/e/abc/viewform"
        )
        == "Google Forms"
    )


def test_detect_embedded_form_provider_returns_none_for_unknown_domain():
    assert detect_embedded_form_provider("https://example.com/widget") is None


def test_detect_embedded_form_provider_handles_empty_src():
    assert detect_embedded_form_provider("") is None
    assert detect_embedded_form_provider(None) is None
