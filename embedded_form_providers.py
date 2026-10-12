"""Config for detecting iframe-embedded third-party form/booking widgets
(Calendly, Typeform, HubSpot, Jotform, Google Forms, Tally, Cognito Forms)
that `core.py`'s `check_forms` can't fill or submit into, since they're
cross-origin iframes, not real <form> elements on the page itself.

Single source of truth for "which domains count as a known embedded-form
provider" — add a new provider here, not by touching core.py's detection
logic.
"""

import os
from urllib.parse import urlparse

EMBEDDED_FORM_PROVIDERS = {
    "Calendly": {"hostnames": ("calendly.com",)},
    "Typeform": {"hostnames": ("typeform.com",)},
    "HubSpot": {
        "hostnames": ("hubspot.com", "hsforms.com", "hsforms.net", "hs-forms.com")
    },
    "Jotform": {"hostnames": ("jotform.com",)},
    # docs.google.com also serves Docs/Sheets/Slides — the path check
    # keeps this from matching an unrelated embedded Google Doc.
    "Google Forms": {"hostnames": ("docs.google.com",), "path_contains": "/forms/"},
    "Tally": {"hostnames": ("tally.so",)},
    "Cognito Forms": {"hostnames": ("cognitoforms.com",)},
}

# Off by default everywhere, same pattern as core.py's
# ALLOW_PRIVATE_CRAWL_TARGETS_ENV_VAR: an explicit opt-in only the
# regression suite sets, so detect_embedded_form_provider can recognize a
# local fixture server's hostname as a stand-in "provider" for testing,
# without needing a real Calendly/Typeform/etc. embed reachable over the
# live internet. Never set in normal/production operation.
TEST_PROVIDER_HOST_ENV_VAR = "GETBUGGY_TEST_EMBEDDED_PROVIDER_HOST"


def _active_providers():
    providers = dict(EMBEDDED_FORM_PROVIDERS)
    test_host = os.environ.get(TEST_PROVIDER_HOST_ENV_VAR, "").strip()
    if test_host:
        providers["Test Provider"] = {"hostnames": (test_host,)}
    return providers


def detect_embedded_form_provider(iframe_src):
    """Return the provider name if iframe_src's hostname (and path, for a
    provider like Google Forms that shares its domain with unrelated
    content) matches a known embedded-form provider, else None."""
    if not iframe_src:
        return None
    parsed = urlparse(iframe_src)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return None
    for name, spec in _active_providers().items():
        if any(
            hostname == h or hostname.endswith("." + h) for h in spec["hostnames"]
        ):
            path_needle = spec.get("path_contains")
            if path_needle and path_needle not in parsed.path:
                continue
            return name
    return None
