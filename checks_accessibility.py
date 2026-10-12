"""Accessibility checks (GetBuggy Step 6).

Runs axe-core (vendored, see vendor/axe-core/) inside the real browser
against the already-loaded page, WCAG 2.2 AA ruleset, and translates each
rule it fails into one plain-English finding per page. Alongside axe, a
few things axe can't (or doesn't) judge on its own:

  * keyboard focus visibility — Tabs through the page for real and checks
    whether anything visibly changes on each element it lands on
  * media that autoplays with sound, and videos without captions
  * accessibility overlay widgets (accessiBe, UserWay, EqualWeb, AudioEye)
  * (site-level, called from core.run_site_check) no accessibility
    statement linked from the homepage

Self-contained like checks_seo.py / checks_performance.py: no import of
core.py (core imports this), so it keeps its own severity constants.
Every check here is passive — it reads the page and presses Tab; it never
clicks, submits or fetches anything.
"""

import os
import re
import threading
import time
from urllib.parse import urlparse

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
VERIFIED = "verified"
NEEDS_LOOK = "needs_look"

# Every finding this module produces carries this, so the report can pull
# the accessibility findings together (top-violations table, disclaimer)
# without hardcoding a list of category names. Carried through
# core.dedupe_site_problems.
TOPIC = "accessibility"

# Shown with every report that ran the accessibility checks — the Step 6
# requirement that the report itself says automated checks are partial.
DISCLAIMER = (
    "Automated checks like these catch only part of the accessibility problems a real "
    "visitor can run into — many can only be found by a person, for example by using the "
    "site with just a keyboard or with a screen reader. A clean result here does not mean "
    "your site is accessible or legally compliant."
)

AXE_SOURCE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "vendor", "axe-core", "axe.min.js"
)
_axe_source = None
_axe_source_lock = threading.Lock()


def _load_axe_source():
    global _axe_source
    with _axe_source_lock:
        if _axe_source is None:
            with open(AXE_SOURCE_PATH, encoding="utf-8") as f:
                _axe_source = f.read()
    return _axe_source


# WCAG 2.0/2.1/2.2, levels A and AA — the "WCAG 2.2 AA" ruleset.
WCAG_22_AA_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]

# Rules turned on beyond the WCAG tags: the Step 6 spec names heading
# order and duplicate IDs explicitly, and axe files both under
# best-practice (duplicate IDs stopped being a WCAG failure in 2.2) so a
# tag-only run would never report them.
EXTRA_RULES = ("heading-order", "duplicate-id", "duplicate-id-active")

# Rules switched off, each for a reason:
#   image-alt        — core.py's "Missing Alt Text" already reports this,
#                      bundled per page; reporting it twice would double-count.
#   document-title   — checks_seo.py's "Missing Page Title" covers it.
#   video-caption,   — replaced by this module's own media check, which can
#   no-autoplay-audio  tell a silent background loop from a real video.
#   target-size      — small tap targets were removed as a finding on
#                      purpose (Step 5.4 product decision, PLAN.md); axe
#                      ships it disabled, and it's pinned off here so an
#                      axe upgrade can't quietly bring it back.
DISABLED_RULES = ("image-alt", "document-title", "video-caption", "no-autoplay-audio", "target-size")

AXE_OPTIONS = {
    "runOnly": {"type": "tag", "values": WCAG_22_AA_TAGS},
    "rules": {
        **{rule: {"enabled": True} for rule in EXTRA_RULES},
        **{rule: {"enabled": False} for rule in DISABLED_RULES},
    },
    # Only violations matter to the report; asking for passes/incomplete
    # in full makes axe slower and the result far bigger.
    "resultTypes": ["violations"],
    # Cross-origin frames would need axe injected into each one, and
    # without that axe waits on every frame before giving up — off.
    "iframes": False,
    "selectors": True,
    "ancestry": False,
    "xpath": False,
    "elementRef": False,
}

# Plain-English translations, one per finding category. Several axe rules
# that mean the same thing to a business owner share one category (and are
# merged into one finding per page). Severity is fixed per category, like
# every other check in this codebase. Mapping principle: things that stop
# someone using the site (can't read it, can't fill a form, can't press a
# button, can't zoom) are MEDIUM; structure and code-quality problems a
# screen reader mostly copes with are LOW. Nothing here is HIGH — HIGH in
# GetBuggy means "broken for everyone".
A11Y_CATEGORIES = {
    "contrast": {
        "category": "Hard-to-Read Text (Low Contrast)",
        "severity": MEDIUM,
        "what": "Some text doesn't stand out enough from the color behind it.",
        "why": "Visitors with weaker eyesight, or anyone reading a phone in sunlight, may not be able to read it.",
        "fix": "Darken the text or lighten the background (or the other way round) until it's clearly readable — your web person can check the exact colors with a free contrast checker.",
        "who": "your web person or designer",
    },
    "form-labels": {
        "category": "Form Fields Without Labels",
        "severity": MEDIUM,
        "what": "Some form fields don't have a label that a screen reader can read out.",
        "why": "A blind visitor using a screen reader hears just \"edit text\" and has no idea what to type, so they can't contact you or order.",
        "fix": "Give every field a proper label (placeholder text inside the box doesn't count).",
        "who": "your web person",
    },
    "button-names": {
        "category": "Buttons Without a Name",
        "severity": MEDIUM,
        "what": "Some buttons have no text or name a screen reader can read — usually icon-only buttons.",
        "why": "A screen-reader user just hears \"button\" and can't tell what it does (add to cart? close? menu?).",
        "fix": "Add visible text or a hidden label (an aria-label) describing what each button does.",
        "who": "your web person",
    },
    "link-names": {
        "category": "Empty Links (No Link Text)",
        "severity": MEDIUM,
        "what": "Some links have no text — often an icon or image link with nothing describing where it goes.",
        "why": "A screen-reader user hears just \"link\" and can't tell where it leads, so they may skip your social, menu or contact links entirely.",
        "fix": "Add text, or a hidden label (an aria-label, or alt text on the image inside), to each link.",
        "who": "your web person",
    },
    "page-language": {
        "category": "Page Language Not Set",
        "severity": MEDIUM,
        "what": "The page doesn't say (correctly) which language it's written in.",
        "why": "Screen readers use this to pick the right voice and pronunciation — without it, your text can be read out with the wrong accent or completely garbled.",
        "fix": "Add lang=\"en\" (or your language) to the page's <html> tag — usually a one-line change in your site's theme or settings.",
        "who": "your web person",
    },
    "zoom": {
        "category": "Page Blocks Zooming",
        "severity": MEDIUM,
        "what": "The page tells phones not to let visitors zoom in.",
        "why": "People who need bigger text can't pinch to zoom, so they may not be able to read your site on a phone at all.",
        "fix": "Remove \"user-scalable=no\" / \"maximum-scale\" from the page's viewport setting.",
        "who": "your web person",
    },
    "auto-refresh": {
        "category": "Page Refreshes or Redirects on a Timer",
        "severity": MEDIUM,
        "what": "The page reloads itself or jumps to another page after a delay.",
        "why": "Visitors who read slowly or use a screen reader lose their place, or get moved on before they've finished.",
        "fix": "Remove the timed refresh/redirect, or use a normal redirect that happens instantly.",
        "who": "your web person",
    },
    "keyboard-reach": {
        "category": "Content Not Reachable by Keyboard",
        "severity": MEDIUM,
        "what": "Some content — a box with its own scroll bar, or an embedded frame — can't be reached using only the keyboard.",
        "why": "Visitors who can't use a mouse can't read or use what's inside it.",
        "fix": "Make the scrolling area focusable (tabindex=\"0\"), and don't stop embedded frames from receiving keyboard focus.",
        "who": "your web person",
    },
    "name-mismatch": {
        "category": "Button or Link Name Doesn't Match Its Text",
        "severity": LOW,
        "what": "Some buttons or links have a hidden name that doesn't include the words shown on them.",
        "why": "Visitors who control their computer by voice say what they see (\"click Book now\") — if the hidden name is different, nothing happens.",
        "fix": "Make each hidden label (aria-label) start with the visible text, or remove it.",
        "who": "your web person",
    },
    "graphics-text": {
        "category": "Images or Icons Without a Description",
        "severity": LOW,
        "what": "Some image-like elements (icons, SVG graphics, image buttons, image-map areas) have no text description.",
        "why": "Screen-reader users miss whatever information those graphics carry.",
        "fix": "Add a short text description to each one (or mark it as decorative if it's purely decoration).",
        "who": "your web person",
    },
    "heading-order": {
        "category": "Headings Skip Levels",
        "severity": LOW,
        "what": "The page's headings jump levels (for example, from a main heading straight to a sub-sub-heading).",
        "why": "Screen-reader users move around a page by its headings, like a table of contents — skipped levels make it look like something is missing.",
        "fix": "Use heading levels in order (H1, then H2, then H3) — change the heading level, then restyle it if it needs to look smaller or bigger.",
        "who": "your web person",
    },
    "duplicate-ids": {
        "category": "Duplicate IDs in the Page Code",
        "severity": LOW,
        "what": "Several elements in the page's code share the same ID, which is supposed to be unique.",
        "why": "Screen readers and form labels rely on IDs to connect things — duplicates can make a label read out for the wrong field.",
        "fix": "Give each element its own unique ID (often a theme or copy-pasted section is the cause).",
        "who": "your web person",
    },
    "lists-tables": {
        "category": "Lists or Tables Built Incorrectly",
        "severity": LOW,
        "what": "Some lists or tables are coded in a way screen readers can't follow.",
        "why": "A screen-reader user may not hear how many items a list has, or which column a number belongs to.",
        "fix": "Fix the list/table markup so items sit inside their list and table headers are marked as headers.",
        "who": "your web person",
    },
    "aria": {
        "category": "Screen-Reader Code (ARIA) Used Incorrectly",
        "severity": LOW,
        "what": "Some of the page's hidden screen-reader instructions (ARIA attributes) are invalid or contradict each other.",
        "why": "Screen readers may announce elements wrongly, or skip things a visitor needs.",
        "fix": "Correct or remove the invalid ARIA attributes — often they come from a theme, plugin or widget, so updating it may fix this.",
        "who": "your web person",
    },
    "nested-interactive": {
        "category": "Clickable Elements Nested Inside Each Other",
        "severity": LOW,
        "what": "Some buttons or links are placed inside other buttons or links.",
        "why": "Screen readers and keyboards often can't reach the inner one.",
        "fix": "Separate them so each clickable element stands on its own.",
        "who": "your web person",
    },
    "links-in-text": {
        "category": "Links Only Distinguished by Color",
        "severity": LOW,
        "what": "Some links inside paragraphs look like normal text except for their color.",
        "why": "Visitors who are color-blind may not see that they're links.",
        "fix": "Underline links in body text (or make them stand out some other way than color alone).",
        "who": "your web person or designer",
    },
    "frames": {
        "category": "Embedded Frames Without a Title",
        "severity": LOW,
        "what": "Some embedded frames (maps, videos, booking widgets) have no title describing them.",
        "why": "Screen-reader users hear just \"frame\" and don't know what's inside.",
        "fix": "Add a short title attribute to each embed (for example title=\"Map to our shop\").",
        "who": "your web person",
    },
    "bypass": {
        "category": "No Way to Skip to the Main Content",
        "severity": LOW,
        "what": "There's no quick way to jump past the menu to the main content.",
        "why": "Keyboard and screen-reader users have to step through every menu link on every page before reaching the content.",
        "fix": "Add a \"Skip to content\" link, or mark up the page with a main landmark and headings.",
        "who": "your web person",
    },
    "form-autocomplete": {
        "category": "Form Autofill Settings Are Wrong",
        "severity": LOW,
        "what": "Some form fields have an autofill (autocomplete) setting browsers don't recognize.",
        "why": "Visitors who rely on their browser to fill in their name, email or address — often people with memory or motor difficulties — can't.",
        "fix": "Use the standard autocomplete values (name, email, tel, street-address…).",
        "who": "your web person",
    },
    "text-spacing": {
        "category": "Text Spacing Locked",
        "severity": LOW,
        "what": "Some text has its letter or line spacing locked so visitors' own settings can't change it.",
        "why": "People with dyslexia or low vision who widen spacing to read more easily can't.",
        "fix": "Remove the !important spacing styles from that text.",
        "who": "your web person",
    },
    "orientation": {
        "category": "Page Locked to One Screen Orientation",
        "severity": LOW,
        "what": "The page only displays properly in portrait or landscape, not both.",
        "why": "Visitors with a phone or tablet mounted to a wheelchair, for example, can't rotate it.",
        "fix": "Remove the CSS that locks the page to one orientation.",
        "who": "your web person",
    },
    "moving-text": {
        "category": "Blinking or Scrolling Text",
        "severity": LOW,
        "what": "The page uses old-style blinking or scrolling (marquee) text.",
        "why": "Moving text is hard to read and can be distracting, or even harmful, for some visitors.",
        "fix": "Replace it with normal, still text.",
        "who": "your web person",
    },
    "fake-headings": {
        "category": "Text Styled to Look Like a Heading",
        "severity": LOW,
        "what": "Some bold or large text is used as a heading but isn't marked up as one.",
        "why": "Screen-reader users jumping between headings never land on it.",
        "fix": "Make that text a real heading (H2, H3…).",
        "who": "your web person",
    },
}

AXE_RULE_TO_CATEGORY = {
    "color-contrast": "contrast",
    "label": "form-labels",
    "select-name": "form-labels",
    "form-field-multiple-labels": "form-labels",
    "aria-input-field-name": "form-labels",
    "aria-toggle-field-name": "form-labels",
    "button-name": "button-names",
    "input-button-name": "button-names",
    "aria-command-name": "button-names",
    "summary-name": "button-names",
    "link-name": "link-names",
    "html-has-lang": "page-language",
    "html-lang-valid": "page-language",
    "html-xml-lang-mismatch": "page-language",
    "valid-lang": "page-language",
    "meta-viewport": "zoom",
    "meta-refresh": "auto-refresh",
    "scrollable-region-focusable": "keyboard-reach",
    "frame-focusable-content": "keyboard-reach",
    "label-content-name-mismatch": "name-mismatch",
    "area-alt": "graphics-text",
    "input-image-alt": "graphics-text",
    "role-img-alt": "graphics-text",
    "svg-img-alt": "graphics-text",
    "object-alt": "graphics-text",
    "server-side-image-map": "graphics-text",
    "heading-order": "heading-order",
    "duplicate-id": "duplicate-ids",
    "duplicate-id-active": "duplicate-ids",
    "duplicate-id-aria": "duplicate-ids",
    "list": "lists-tables",
    "listitem": "lists-tables",
    "definition-list": "lists-tables",
    "dlitem": "lists-tables",
    "td-has-header": "lists-tables",
    "td-headers-attr": "lists-tables",
    "th-has-data-cells": "lists-tables",
    "table-fake-caption": "lists-tables",
    "nested-interactive": "nested-interactive",
    "link-in-text-block": "links-in-text",
    "frame-title": "frames",
    "frame-title-unique": "frames",
    "bypass": "bypass",
    "autocomplete-valid": "form-autocomplete",
    "avoid-inline-spacing": "text-spacing",
    "css-orientation-lock": "orientation",
    "blink": "moving-text",
    "marquee": "moving-text",
    "p-as-heading": "fake-headings",
}
# Every other ARIA rule axe has ("aria-*") is the same thing to a business
# owner: the page's screen-reader markup is wrong.
_ARIA_RULE_PREFIX = "aria-"

# A rule with no translation above (a new rule in a future axe version)
# still gets reported — never silently dropped — under axe's own one-line
# description, at LOW.
_UNTRANSLATED = {
    "severity": LOW,
    "why": "This can make part of the page hard or impossible to use for visitors with disabilities.",
    "fix": "Your web person can look up the rule named below for the exact fix.",
    "who": "your web person",
}

MAX_EXAMPLES = 3

# Time budget (see A11yScanBudget). Both env vars, tunable on Render
# without a deploy, like CRAWL_CONCURRENCY.
#   A11Y_SCAN_TIMEOUT_SECONDS: a single axe scan is abandoned after this.
#   A11Y_SLOW_SCAN_SECONDS: a scan slower than this switches the rest of
#     the crawl to "homepage and contact/booking pages only".
DEFAULT_SCAN_TIMEOUT_SECONDS = 20
DEFAULT_SLOW_SCAN_SECONDS = 10


def _env_seconds(name, default):
    try:
        return float(os.environ.get(name) or default)
    except ValueError:
        return float(default)


def scan_timeout_seconds():
    return _env_seconds("A11Y_SCAN_TIMEOUT_SECONDS", DEFAULT_SCAN_TIMEOUT_SECONDS)


def slow_scan_seconds():
    return _env_seconds("A11Y_SLOW_SCAN_SECONDS", DEFAULT_SLOW_SCAN_SECONDS)


# The pages the accessibility scan always runs on, even when it's too slow
# to run on every page: the homepage, plus any page whose address says
# it's for contacting or booking the business.
_PRIORITY_PATH_RE = re.compile(r"(contact|book|appointment|reserv|schedul)", re.I)


def is_priority_page(url, is_homepage):
    return bool(is_homepage) or bool(_PRIORITY_PATH_RE.search(urlparse(url).path or ""))


class A11yScanBudget:
    """Crawl-wide: decides whether a page gets the (comparatively
    expensive) axe scan. Starts by scanning every page. The first scan
    that's slower than A11Y_SLOW_SCAN_SECONDS — or times out — means it
    won't fit every page's time budget on this site, so from then on only
    priority pages (homepage, contact/booking) are scanned; every page
    skipped says so in its own "couldn't check" notes. Shared across the
    crawl's worker threads, hence the lock."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reduced_because = None
        self.skipped_pages = []

    def should_scan(self, url, is_homepage):
        with self._lock:
            if self.reduced_because is None or is_priority_page(url, is_homepage):
                return True
            self.skipped_pages.append(url)
            return False

    def record(self, url, seconds, timed_out):
        with self._lock:
            if self.reduced_because is not None:
                return
            if timed_out:
                self.reduced_because = f"the scan didn't finish within {scan_timeout_seconds():.0f}s on {url}"
            elif seconds > slow_scan_seconds():
                self.reduced_because = f"the scan took {seconds:.0f}s on {url}"


def skipped_scan_note(reason):
    return (
        "We skipped the automated accessibility scan on this page to stay within the time "
        f"limit — it was slow on this site ({reason}), so it only ran on your homepage and "
        "contact/booking pages."
    )


def site_skipped_scan_note(budget):
    if not budget or not budget.skipped_pages:
        return None
    n = len(budget.skipped_pages)
    return (
        f"The automated accessibility scan only ran on your homepage and contact/booking "
        f"pages — it was too slow on this site to run on every page ({budget.reduced_because}), "
        f"so {n} page{'' if n == 1 else 's'} weren't scanned for accessibility problems."
    )


# --- axe -------------------------------------------------------------------

# Injected with `define`/`module`/`exports` shadowed, so axe's UMD wrapper
# never registers itself with the site's own module loader (RequireJS and
# friends) — axe sets window.axe either way.
def _inject_expression():
    return (
        "(function (define, module, exports) {\n"
        + _load_axe_source()
        + "\n}).call(window, undefined, undefined, undefined);\n"
        "typeof window.axe === 'object' && typeof window.axe.run === 'function'"
    )


# How an element is named in the report: the words a visitor would
# recognize ("Order now" (button)), never a bare tag name. Shared by the
# axe and focus checks. Field values are never read (privacy).
_DESCRIBE_JS = """
  const KIND = { a: 'link', button: 'button', input: 'form field', select: 'dropdown', textarea: 'text box',
    img: 'image', svg: 'icon', video: 'video', audio: 'audio player', iframe: 'embedded frame', summary: 'button',
    h1: 'heading', h2: 'heading', h3: 'heading', h4: 'heading', h5: 'heading', h6: 'heading' };
  const describe = (el) => {
    const tag = el.tagName.toLowerCase();
    if (tag === 'html' || tag === 'body') return 'the page itself';
    const kind = KIND[tag] || 'text';
    const text = (el.innerText || el.getAttribute('aria-label') || el.getAttribute('alt') ||
      el.getAttribute('placeholder') || el.getAttribute('title') || el.getAttribute('name') || '')
      .replace(/\\s+/g, ' ').trim().slice(0, 40);
    if (text) return `"${text}" (${kind})`;
    return kind === 'text' ? `a <${tag}> element` : `a ${kind} with no text`;
  };
"""

# A human-readable label for each example element — the text a visitor
# would recognize ("Order now"), not just a CSS selector, which goes along
# for the web person.
_RUN_AXE_JS = """
async ({ options, timeoutMs, maxExamples }) => {
""" + _DESCRIBE_JS + """
  const started = performance.now();
  const timeout = new Promise((resolve) => setTimeout(() => resolve({ timedOut: true }), timeoutMs));
  const run = window.axe.run(document, options).then((res) => ({ res }));
  const out = await Promise.race([run, timeout]);
  const ms = performance.now() - started;
  if (out.timedOut) return { timedOut: true, ms };
  const labelFor = (target) => {
    try {
      if (!target || target.length !== 1 || typeof target[0] !== 'string') return '';
      const el = document.querySelector(target[0]);
      if (!el) return '';
      return describe(el);
    } catch (e) {
      return '';
    }
  };
  const violations = out.res.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    helpUrl: v.helpUrl,
    count: v.nodes.length,
    examples: v.nodes.slice(0, maxExamples).map((n) => ({
      selector: (n.target || []).map((t) => Array.isArray(t) ? t.join(' >>> ') : t).join(' '),
      label: labelFor(n.target),
    })),
  }));
  return { timedOut: false, ms, violations };
}
"""


def _category_key_for_rule(rule_id):
    key = AXE_RULE_TO_CATEGORY.get(rule_id)
    if key is None and rule_id.startswith(_ARIA_RULE_PREFIX):
        key = "aria"
    return key


def _examples_text(examples):
    labels = [e["label"] for e in examples if e.get("label")]
    return ", ".join(dict.fromkeys(labels))


def _selectors_text(examples):
    return ", ".join(dict.fromkeys(e["selector"] for e in examples if e.get("selector")))


def axe_violations_to_problems(violations):
    """Groups axe's per-rule violations into one finding per plain-English
    category (several rules can share one), with the element count and a
    few recognizable examples. Pure function — unit-tested without a
    browser."""
    grouped = {}
    order = []
    for v in violations:
        key = _category_key_for_rule(v["id"]) or f"axe:{v['id']}"
        if key not in grouped:
            grouped[key] = {"rules": [], "count": 0, "examples": [], "help": v.get("help") or v["id"]}
            order.append(key)
        g = grouped[key]
        g["rules"].append(v["id"])
        g["count"] += int(v.get("count") or 0)
        g["examples"].extend(v.get("examples") or [])

    problems = []
    for key in order:
        g = grouped[key]
        examples = g["examples"][:MAX_EXAMPLES]
        rules = ", ".join(sorted(set(g["rules"])))
        n = g["count"]
        spec = A11Y_CATEGORIES.get(key)
        if spec:
            category, severity = spec["category"], spec["severity"]
            what, why, fix, who = spec["what"], spec["why"], spec["fix"], spec["who"]
        else:
            category = f"Accessibility: {g['help']}"
            severity = _UNTRANSLATED["severity"]
            what = f"{g['help']}."
            why, fix, who = _UNTRANSLATED["why"], _UNTRANSLATED["fix"], _UNTRANSLATED["who"]
        example_text = _examples_text(examples)
        selectors = _selectors_text(examples)
        message = (
            f"{what} Affects {n} element{'' if n == 1 else 's'} on this page"
            + (f" — e.g. {example_text}" if example_text else "")
            + f". Why it matters: {why} How to fix: {fix} Who fixes it: {who}."
            + f" (For your web person: axe-core rule {rules}"
            + (f"; first elements: {selectors}" if selectors else "")
            + ".)"
        )
        problems.append({
            "category": category,
            "message": message,
            "severity": severity,
            # axe reports a violation only when its rule fully evaluated
            # and failed — uncertain results ("incomplete") are never
            # requested, so what's left is a direct observation.
            "confidence": VERIFIED,
            "evidence": rules,
            "topic": TOPIC,
            "element_count": n,
        })
    return problems


def run_axe(page):
    """Injects axe and runs it. Returns (violations, seconds, timed_out)."""
    if not page.evaluate(_inject_expression()):
        raise RuntimeError("axe-core did not load on this page")
    out = page.evaluate(
        _RUN_AXE_JS,
        {
            "options": AXE_OPTIONS,
            "timeoutMs": int(scan_timeout_seconds() * 1000),
            "maxExamples": MAX_EXAMPLES,
        },
    )
    return out.get("violations") or [], (out.get("ms") or 0) / 1000.0, bool(out.get("timedOut"))


# --- keyboard focus visibility --------------------------------------------

FOCUS_CHECK_MAX_TABS = 20

# Every style that could make focus visible: outline, ring (box-shadow),
# border, background/text color, underline, size/position (a skip link
# sliding into view), on the element, its ::before/::after, and its parent
# (a :focus-within ring on a wrapper). Snapshotted for every focusable
# element BEFORE anything is focused, then compared with what each element
# looks like once Tab actually lands on it. Running CSS transitions are
# finished before reading, or a 0.2s fade-in focus ring would look like no
# change at all.
_FOCUS_SNAPSHOT_JS = """
() => {
  // Outline and text-decoration are normalized to "none" when they can't
  // be seen: Chromium's own stylesheet nudges outline-offset on a focused
  // link even when the site has set "outline: none", which would otherwise
  // count as a visible change.
  const outline = (cs) => (cs.getPropertyValue('outline-style') === 'none' ||
      parseFloat(cs.getPropertyValue('outline-width')) === 0) ? 'none' :
    ['outline-style', 'outline-width', 'outline-color', 'outline-offset'].map((p) => cs.getPropertyValue(p)).join(' ');
  const underline = (cs) => cs.getPropertyValue('text-decoration-line') === 'none' ? 'none' :
    ['text-decoration-line', 'text-decoration-color', 'text-decoration-thickness'].map((p) => cs.getPropertyValue(p)).join(' ');
  const PROPS = ['box-shadow', 'border-top-color', 'border-bottom-color', 'border-left-color', 'border-right-color',
    'border-top-width', 'border-bottom-width', 'background-color', 'background-image', 'color', 'transform',
    'opacity', 'filter', 'font-weight', 'left', 'top', 'clip', 'clip-path', 'width', 'height', 'visibility'];
  const PSEUDO = ['content', 'background-color', 'border-bottom-color', 'border-bottom-width', 'box-shadow',
    'opacity', 'transform', 'width', 'height', 'visibility'];
  const read = (el) => {
    if (!el || el.nodeType !== 1) return '';
    const cs = getComputedStyle(el);
    const b = getComputedStyle(el, '::before');
    const a = getComputedStyle(el, '::after');
    return outline(cs) + '|' + underline(cs) + '|' + PROPS.map((p) => cs.getPropertyValue(p)).join('|') + '#' +
      outline(b) + '|' + PSEUDO.map((p) => b.getPropertyValue(p)).join('|') + '#' +
      outline(a) + '|' + PSEUDO.map((p) => a.getPropertyValue(p)).join('|');
  };
  const readWithParent = (el) => {
    const parent = el.parentElement;
    if (parent) {
      const ps = getComputedStyle(parent);
      return read(el) + '^' + outline(ps) + '|' + ['box-shadow', 'background-color', 'border-bottom-color']
        .map((p) => ps.getPropertyValue(p)).join('|');
    }
    return read(el);
  };
  const finishTransitions = (el) => {
    for (const node of [el, el.parentElement]) {
      if (!node || !node.getAnimations) continue;
      getComputedStyle(node).outlineStyle;  // forces the style update that starts the transition
      for (const anim of node.getAnimations({ subtree: true })) {
        try { anim.finish(); } catch (e) {}
      }
    }
  };
""" + _DESCRIBE_JS + """
  if (document.activeElement && document.activeElement !== document.body) document.activeElement.blur();
  const snap = new Map();
  const sel = 'a[href], button, input:not([type=hidden]), select, textarea, summary, [tabindex], [contenteditable=""], [contenteditable="true"]';
  // Tab order follows document order (barring positive tabindex), so the
  // first few hundred focusable elements comfortably cover the first
  // FOCUS_CHECK_MAX_TABS stops without reading every link on a huge page.
  for (const el of [...document.querySelectorAll(sel)].slice(0, 400)) snap.set(el, readWithParent(el));
  window.__getbuggyFocusCheck = {
    seen: new Set(),
    probe() {
      const el = document.activeElement;
      if (!el || el === document.body || el === document.documentElement) return { done: true };
      if (el.tagName === 'IFRAME') return { skip: true };
      if (this.seen.has(el)) return { done: true };
      this.seen.add(el);
      if (!snap.has(el)) return { skip: true };
      finishTransitions(el);
      return { visible: readWithParent(el) !== snap.get(el), label: describe(el) };
    },
  };
  return snap.size;
}
"""


def check_focus_visibility(page, problems):
    """Presses Tab for real (up to FOCUS_CHECK_MAX_TABS times) and records
    every element focus lands on whose appearance doesn't change at all.
    `needs_look`: the focus indicator could live somewhere this can't see
    (a sibling, a separate overlay element), so a person should confirm."""
    if not page.evaluate(_FOCUS_SNAPSHOT_JS):
        return
    reached, invisible = 0, []
    for _ in range(FOCUS_CHECK_MAX_TABS):
        page.keyboard.press("Tab")
        result = page.evaluate("() => window.__getbuggyFocusCheck.probe()")
        if result.get("done"):
            break
        if result.get("skip"):
            continue
        reached += 1
        if not result.get("visible"):
            invisible.append(result.get("label") or "an element")
    if not invisible:
        return
    n = len(invisible)
    examples = ", ".join(list(dict.fromkeys(invisible))[:MAX_EXAMPLES])
    problems.append({
        "category": "No Visible Keyboard Focus",
        "message": (
            f"When we moved through the page with the Tab key, {n} of the first {reached} "
            f"links, buttons or fields showed no visible sign of being selected — e.g. {examples}. "
            "Why it matters: people who use a keyboard instead of a mouse can't see where they "
            "are on the page, so they can't tell what pressing Enter will do. How to fix: don't "
            "remove the browser's focus outline (\"outline: none\") without adding a clear "
            "replacement style. Who fixes it: your web person. Worth a quick check yourself: "
            "click into your page and press Tab a few times."
        ),
        "severity": MEDIUM,
        "confidence": NEEDS_LOOK,
        "topic": TOPIC,
        "element_count": n,
    })


# --- media: autoplay with sound, videos without captions -------------------

# WCAG 1.4.2 exempts sound that stops on its own within 3 seconds.
AUTOPLAY_EXEMPT_SECONDS = 3

_MEDIA_JS = """
() => {
  const media = [...document.querySelectorAll('video, audio')].map((m) => {
    const src = m.currentSrc || m.getAttribute('src') || (m.querySelector('source') || {}).src || '';
    return {
      tag: m.tagName.toLowerCase(),
      src: src.split('?')[0].split('/').pop() || '',
      autoplay: m.autoplay || !m.paused,
      muted: m.muted || m.defaultMuted,
      controls: m.controls,
      duration: Number.isFinite(m.duration) ? m.duration : null,
      captions: [...m.querySelectorAll('track')].some((t) => t.kind === 'captions' || t.kind === 'subtitles'),
    };
  });
  const players = [...document.querySelectorAll('iframe[src]')]
    .map((f) => f.src)
    .filter((s) => /(^https?:\\/\\/)?([a-z0-9-]+\\.)*(youtube\\.com|youtube-nocookie\\.com|vimeo\\.com|wistia\\.(com|net)|loom\\.com)\\//i.test(s));
  return { media, players: players.length };
}
"""


def _media_name(m):
    if m.get("src"):
        return f"\"{m['src']}\" ({m['tag']})"
    return "an audio player on the page" if m["tag"] == "audio" else "a video on the page"


def _capitalize(text):
    return text[:1].upper() + text[1:]


def media_problems(media):
    """Pure function over _MEDIA_JS's media list — unit-tested."""
    problems = []
    autoplaying = [
        m for m in media
        if m["autoplay"] and not m["muted"]
        and not (m.get("duration") is not None and m["duration"] <= AUTOPLAY_EXEMPT_SECONDS)
    ]
    if autoplaying:
        names = _capitalize(", ".join(_media_name(m) for m in autoplaying[:MAX_EXAMPLES]))
        problems.append({
            "category": "Media Plays Automatically With Sound",
            "message": (
                f"{names} is set to start playing on its own with the sound on. Why it matters: "
                "sudden sound drowns out screen readers (blind visitors can't hear their way to "
                "the pause button) and startles everyone else. How to fix: turn off autoplay, or "
                "start it muted with a visible play/pause button. Who fixes it: your web person."
            ),
            "severity": MEDIUM,
            "confidence": VERIFIED,
            "evidence": "|".join(sorted(m["src"] for m in autoplaying)),
            "topic": TOPIC,
            "element_count": len(autoplaying),
        })

    # A muted, autoplaying, control-less video is a silent background loop
    # — decoration, nothing to caption. Every other <video> is meant to be
    # watched.
    uncaptioned = [
        m for m in media
        if m["tag"] == "video" and not m["captions"]
        and not (m["muted"] and m["autoplay"] and not m["controls"])
    ]
    if uncaptioned:
        names = _capitalize(", ".join(_media_name(m) for m in uncaptioned[:MAX_EXAMPLES]))
        problems.append({
            "category": "Video Without Captions",
            "message": (
                f"{names} has no captions track. Why it matters: visitors who are deaf or hard of "
                "hearing — and anyone watching with the sound off — miss whatever is said. How to "
                "fix: add a captions file (most video tools can generate one), or make sure the "
                "captions are already part of the video picture. Who fixes it: you or your web "
                "person. Marked \"needs a look\" because captions burned into the video itself "
                "can't be detected."
            ),
            "severity": MEDIUM,
            "confidence": NEEDS_LOOK,
            "evidence": "|".join(sorted(m["src"] for m in uncaptioned)),
            "topic": TOPIC,
            "element_count": len(uncaptioned),
        })
    return problems


# --- overlay widgets -------------------------------------------------------

OVERLAY_VENDORS = {
    "accessiBe": ("acsbapp.com", "acsbap.com", "accessibe.com"),
    "UserWay": ("userway.org",),
    "EqualWeb": ("equalweb.com",),
    "AudioEye": ("audioeye.com",),
}

_OVERLAY_SOURCES_JS = """
() => [
  ...[...document.querySelectorAll('script[src], iframe[src], link[href]')].map((e) => e.src || e.href || ''),
  ...performance.getEntriesByType('resource').map((r) => r.name),
]
"""


def detect_overlay_vendors(urls):
    """Pure function: which known overlay vendors any of `urls` came from."""
    found = []
    for vendor, domains in OVERLAY_VENDORS.items():
        for u in urls:
            host = (urlparse(u).hostname or "").lower()
            if any(host == d or host.endswith("." + d) for d in domains):
                found.append(vendor)
                break
    return found


def overlay_problem(vendors):
    names = " and ".join(vendors)
    return {
        "category": "Accessibility Overlay Widget",
        "message": (
            f"This site loads an accessibility overlay widget ({names}). Worth knowing: these "
            "widgets add a toolbar on top of your site but don't fix the problems in the site "
            "itself — having one does not make your site accessible or compliant, and businesses "
            "using them have still faced accessibility lawsuits. Some disabled visitors find "
            "they get in the way of their own tools. How to fix: treat the other accessibility "
            "findings in this report as the real to-do list, then decide whether you still want "
            "the widget. Who fixes it: you and your web person (your lawyer, if it was sold to you "
            "as legal protection)."
        ),
        "severity": LOW,
        "confidence": NEEDS_LOOK,
        "evidence": "|".join(vendors),
        "topic": TOPIC,
    }


# --- per-page entry point --------------------------------------------------

def check_accessibility(page, problems, could_not_check, budget=None, page_url=None, is_homepage=False):
    """DOM-only check (runs on the already-loaded page; no extra page
    load). Run it before anything that changes the page (form filling),
    so axe sees the page as a visitor first does.

    `budget` (an A11yScanBudget, crawl only) decides whether the axe scan
    runs on this page; without one (a single-page check) it always runs.
    The cheap checks — focus, media, overlays — run regardless. Any part
    that can't complete goes to `could_not_check`, never silently."""
    page_url = page_url or page.url

    if budget is None or budget.should_scan(page_url, is_homepage):
        started = time.time()
        try:
            violations, axe_seconds, timed_out = run_axe(page)
            if timed_out:
                could_not_check.append(
                    f"The automated accessibility scan didn't finish within "
                    f"{scan_timeout_seconds():.0f}s on this page, so it was stopped — "
                    "this page's accessibility results are incomplete."
                )
            else:
                problems.extend(axe_violations_to_problems(violations))
            if budget is not None:
                budget.record(page_url, axe_seconds or (time.time() - started), timed_out)
        except Exception as e:
            could_not_check.append(
                f"Couldn't run the automated accessibility scan on this page "
                f"({e.__class__.__name__})."
            )
    else:
        could_not_check.append(skipped_scan_note(budget.reduced_because))

    try:
        check_focus_visibility(page, problems)
    except Exception as e:
        could_not_check.append(
            f"Couldn't complete the keyboard-focus check on this page ({e.__class__.__name__})."
        )

    try:
        media = page.evaluate(_MEDIA_JS)
        problems.extend(media_problems(media["media"]))
        if media["players"]:
            n = media["players"]
            could_not_check.append(
                f"This page embeds {n} video player{'' if n == 1 else 's'} from another service "
                "(YouTube, Vimeo, …) — we can't see inside those players to check for captions."
            )
    except Exception as e:
        could_not_check.append(
            f"Couldn't check this page's video and audio for accessibility ({e.__class__.__name__})."
        )

    try:
        vendors = detect_overlay_vendors(page.evaluate(_OVERLAY_SOURCES_JS))
        if vendors:
            problems.append(overlay_problem(vendors))
    except Exception:
        pass  # overlay detection is informational; nothing to tell the owner if it can't run


# --- site-level: accessibility statement -----------------------------------

_STATEMENT_RE = re.compile(r"accessib|a11y", re.I)


def has_accessibility_statement(homepage_links, sitemap_urls=()):
    """Pure function: any homepage link (text, label or address) or sitemap
    page that looks like an accessibility statement."""
    for link in homepage_links or []:
        haystack = " ".join(
            str(link.get(k) or "") for k in ("text", "aria", "href", "resolved")
        )
        if _STATEMENT_RE.search(haystack):
            return True
    return any(_STATEMENT_RE.search(urlparse(u).path or "") for u in sitemap_urls or [])


def missing_statement_finding():
    return {
        "category": "No Accessibility Statement",
        "message": (
            "We couldn't find an accessibility statement — no link to one on your homepage and "
            "no such page in your sitemap. Why it matters: it's a short page that tells visitors "
            "with disabilities how accessible your site is and how to reach you if something "
            "doesn't work for them; it also shows good faith if anyone ever raises a complaint. "
            "How to fix: publish a short page (what you've done, any known problems, an email or "
            "phone number for help) and link it in your footer. Who fixes it: you write it, your "
            "web person links it. Marked \"needs a look\" in case it exists somewhere we didn't check."
        ),
        "severity": LOW,
        "confidence": NEEDS_LOOK,
        "topic": TOPIC,
    }


# --- report summary --------------------------------------------------------

TOP_VIOLATIONS = 5
_SEVERITY_RANK = {HIGH: 0, MEDIUM: 1, LOW: 2}


def accessibility_summary(unique_problems, site_findings=()):
    """The report's accessibility section: the disclaimer (always), plus
    the top accessibility problems by severity then how many elements they
    affect, each with its page and element counts. Built from the
    already-deduplicated problems (see core.dedupe_site_problems), so it
    works for a partial report too."""
    items = [p for p in list(unique_problems or []) + list(site_findings or []) if p.get("topic") == TOPIC]
    items.sort(key=lambda p: (_SEVERITY_RANK.get(p["severity"], 3), -(p.get("element_count") or 0)))
    return {
        "note": DISCLAIMER,
        "total": len(items),
        "top": [
            {
                "category": p["category"],
                "severity": p["severity"],
                "pages": len(p.get("pages") or []),
                "elements": p.get("element_count"),
            }
            for p in items[:TOP_VIOLATIONS]
        ],
    }
