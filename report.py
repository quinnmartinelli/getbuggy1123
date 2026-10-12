"""The finished report (GetBuggy Step 8): score, finding schema, report
areas with their "nothing found" lines, partial-report labelling, the
change since a previous check, and the "send to your web person" export.

Pure logic — no browser, no network. `finalize_report` is called once on
every finished crawl result (complete or partial) by server.py, and by the
CLI; everything else here is a helper of it or of the export.

The score formula and severity rubric are documented in PLAN.md
("Report score"); the constants below are the single source of truth and
PLAN.md quotes them.
"""
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from checks_accessibility import DISCLAIMER as ACCESSIBILITY_DISCLAIMER
from checks_security import SECRET_PATTERNS, is_security_finding, mask_secret, redact_security_details
from crawl_utils import normalize_host
import finding_guide

SCHEMA_VERSION = 1

# --- Score ------------------------------------------------------------------
SCORE_FORMULA_VERSION = 1
SEVERITY_POINTS = {"high": 15, "medium": 5, "low": 1}
# No single area can take more than this off the score, so one bad area
# (say, thirty accessibility problems) can't zero the whole report.
AREA_CAP_POINTS = 25
SCORE_BANDS = (
    (90, "In good shape"),
    (75, "A few things to fix"),
    (50, "Needs attention"),
    (0, "Needs work soon"),
)

# Findings that move with network conditions and our own server's load
# rather than with the site (mirrors regression_check.TIMING_TOLERANT_
# CATEGORIES). Two runs of the same site "score the same within the timing
# tolerance" when their scores agree once these are left out — see
# scores_match().
TIMING_SENSITIVE_CATEGORIES = frozenset({
    "Page Load Time", "Largest Contentful Paint", "Layout Shifts While Loading",
    "Slow Server Response", "Heavy Page", "Many Requests", "Oversized Images",
    "Core Web Vitals Check Failed", "Mobile Check Failed",
})

# --- Report areas -------------------------------------------------------------
# (key, title, line shown when nothing was found, depends on pages being
# opened). The clean line only appears when the area's checks actually ran.
SECTIONS = (
    ("links", "Links and pages", "No broken links or missing pages found.", True),
    ("forms", "Forms", "No broken forms found.", True),
    ("errors", "Errors and broken files", "No script errors or broken files found.", True),
    ("speed", "Speed", "No speed problems found.", True),
    ("mobile", "Mobile", "No mobile layout problems found.", True),
    ("seo", "Search engines", "No search-engine basics missing.", True),
    ("accessibility", "Accessibility", "The automated accessibility checks found nothing.", True),
    ("security", "Security", "No exposed files or hacked-site signals found.", True),
    ("setup", "Site setup", "No problems with robots.txt, your sitemap or redirects.", False),
)
_SECTION_TITLES = {key: title for key, title, _, _ in SECTIONS}

# When each area's checks last changed in a way that can change findings.
# Bump the date for an area whenever its logic changes that way: a re-check
# compares these, so an owner is told when part of a score change came from
# GetBuggy rather than from their site.
CHECK_VERSIONS = {
    "links": "2026-09-26",
    "forms": "2026-09-26",
    "errors": "2026-09-25",
    "speed": "2026-09-26",
    "mobile": "2026-09-26",
    "seo": "2026-09-26",
    "accessibility": "2026-10-11",
    "security": "2026-10-11",
    "setup": "2026-10-11",
    "other": "2026-10-11",
}

_SECURITY_SKIPPED_NOTE = "Security and site-setup checks were switched off"
MAX_EVIDENCE_CHARS = 300


def area_for(finding):
    """Which report area a finding is scored and summarised under."""
    if is_security_finding(finding):
        return "security"
    if finding.get("topic") == "accessibility":
        return "accessibility"
    area = finding_guide.guide_for(finding["category"], finding.get("severity")).get("area")
    if area:
        return area
    # A newer check's own topic becomes its own area rather than vanishing.
    return finding.get("topic") or "other"


def finding_id(finding):
    """Stable across runs for the same issue: the same identity the
    cross-page dedup uses (category + evidence)."""
    raw = f"{finding['category']}\x1f{finding.get('evidence') if finding.get('evidence') is not None else ''}"
    return "f-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def mask_evidence(evidence):
    """Evidence as a short string with anything key-shaped masked."""
    if evidence is None:
        return None
    text = evidence if isinstance(evidence, str) else json.dumps(evidence, sort_keys=True)
    for _kind, pattern in SECRET_PATTERNS:
        text = pattern.sub(_mask_match, text)
    if len(text) > MAX_EVIDENCE_CHARS:
        text = text[: MAX_EVIDENCE_CHARS - 1] + "…"
    return text


def _mask_match(m):
    raw = (m.group(1) if m.groups() else None) or m.group(0)
    return m.group(0).replace(raw, mask_secret(raw))


def normalize_finding(finding, pages, platform=None):
    """Adds the standard schema fields to a finding dict, in place:
    id, title, why_it_matters, how_to_fix, who_fixes, platform_note (when
    there is one), pages, evidence (masked), check_version — plus `area`.
    The original `message` (what's wrong on this site) is kept."""
    guide = finding_guide.guide_for(finding["category"], finding.get("severity"))
    area = area_for(finding)
    finding["id"] = finding_id(finding)
    finding.setdefault("title", finding["category"])
    finding.setdefault("why_it_matters", guide["why"])
    finding.setdefault("how_to_fix", guide["how"])
    if not finding.get("who_fixes"):
        finding["who_fixes"] = guide["who"]
    note = finding_guide.platform_note(finding["who_fixes"], platform)
    if note and not finding.get("platform_note"):
        finding["platform_note"] = note
    if not finding.get("pages"):
        if finding.get("items"):
            seen = []
            for item in finding["items"]:
                for u in item.get("pages") or ([item["page"]] if item.get("page") else []):
                    if u not in seen:
                        seen.append(u)
            finding["pages"] = seen
        else:
            finding["pages"] = list(pages)
    finding["evidence"] = mask_evidence(finding.get("evidence"))
    finding["check_version"] = f"{area}/{CHECK_VERSIONS.get(area, CHECK_VERSIONS['other'])}"
    finding["area"] = area
    return finding


def _scorable(result):
    return list(result.get("unique_problems") or []) + list(result.get("site_findings") or [])


def _opened_pages(result):
    return [p for p in result.get("pages") or [] if not p.get("could_not_load")]


def _band(value):
    for floor, label in SCORE_BANDS:
        if value >= floor:
            return label
    return SCORE_BANDS[-1][1]


def compute_score(result):
    """0-100. Starts at 100; each distinct verified finding takes off
    SEVERITY_POINTS by severity; each area takes off at most
    AREA_CAP_POINTS; never below 0. `needs_look` and informational
    findings don't count. Needs at least one page that actually opened."""
    opened = _opened_pages(result)
    if not opened:
        return {
            "value": None,
            "out_of": 100,
            "formula_version": SCORE_FORMULA_VERSION,
            "partial": bool(result.get("partial")),
            "reason": "We couldn't open any pages on this site, so there's nothing to score.",
        }

    raw = defaultdict(int)
    raw_steady = defaultdict(int)  # same, without timing-sensitive findings
    counted = defaultdict(int)
    excluded_needs_look = 0
    for f in _scorable(result):
        if f.get("informational"):
            continue
        if f.get("confidence") != "verified":
            excluded_needs_look += 1
            continue
        points = SEVERITY_POINTS.get(f.get("severity"), 0)
        area = area_for(f)
        raw[area] += points
        counted[area] += 1
        if f["category"] not in TIMING_SENSITIVE_CATEGORIES:
            raw_steady[area] += points

    capped = {a: min(p, AREA_CAP_POINTS) for a, p in raw.items()}
    value = max(0, 100 - sum(capped.values()))
    steady = max(0, 100 - sum(min(p, AREA_CAP_POINTS) for p in raw_steady.values()))

    order = [key for key, *_ in SECTIONS]
    areas = sorted(raw, key=lambda a: (order.index(a) if a in order else len(order), a))
    n_pages = len(opened)
    basis = f"Based on {n_pages} page{'' if n_pages == 1 else 's'} checked"
    if result.get("partial"):
        basis += " — this report is partial, so the score only covers what we managed to check"
    return {
        "value": value,
        "out_of": 100,
        "band": _band(value),
        "formula_version": SCORE_FORMULA_VERSION,
        "rules": dict(SEVERITY_POINTS, area_cap=AREA_CAP_POINTS),
        "partial": bool(result.get("partial")),
        "basis": basis + ".",
        "deductions": [
            {
                "area": a,
                "title": _SECTION_TITLES.get(a, a.replace("_", " ").capitalize()),
                "points": capped[a],
                "uncapped_points": raw[a],
                "capped": raw[a] > AREA_CAP_POINTS,
                "findings_counted": counted[a],
            }
            for a in areas
        ],
        "needs_look_not_counted": excluded_needs_look,
        "value_without_timing": steady,
        "timing_sensitive_points": steady - value,
    }


def scores_match(a, b):
    """Two scores for the same site agree within the timing tolerance: once
    the timing-sensitive findings are left out, they're identical."""
    if a is None or b is None or a.get("value") is None or b.get("value") is None:
        return (a or {}).get("value") is None and (b or {}).get("value") is None
    return a["value_without_timing"] == b["value_without_timing"]


def build_sections(result):
    """One entry per report area: status "issues" / "clean" /
    "not_checked", a count, and the line to show. Counts only — never a
    finding's text — so it's safe in a public report even for security."""
    findings = _scorable(result)
    opened = bool(_opened_pages(result))
    discovery_done = bool(result.get("pages_planned")) or not result.get("partial")
    security_skipped = any(
        _SECURITY_SKIPPED_NOTE in note for note in result.get("site_could_not_check") or []
    )
    by_area = defaultdict(list)
    for f in findings:
        if not f.get("informational"):
            by_area[area_for(f)].append(f)

    keys = [key for key, *_ in SECTIONS]
    extra = sorted(a for a in by_area if a not in keys)
    sections = []
    for key in keys + extra:
        spec = next((s for s in SECTIONS if s[0] == key), None)
        title, clean_line, page_based = (spec[1], spec[2], spec[3]) if spec else (
            key.replace("_", " ").capitalize(), None, True)
        issues = by_area.get(key, [])
        if issues:
            n = len(issues)
            needs_look = sum(1 for f in issues if f.get("confidence") != "verified")
            if key == "security":
                line = f"{n} possible security exposure{'' if n == 1 else 's'} found."
            else:
                line = f"{n} problem{'' if n == 1 else 's'} found."
            if needs_look:
                line += f" {needs_look} of them need{'s' if needs_look == 1 else ''} a look to confirm."
            status = "issues"
        elif not discovery_done or (page_based and not opened) or (
            key in ("security", "setup") and security_skipped
        ):
            status, n, needs_look = "not_checked", 0, 0
            line = "We couldn't check this, so we can't say either way."
        elif clean_line is None:
            continue
        else:
            status, n, needs_look = "clean", 0, 0
            line = clean_line[:-1] + " on the pages we checked." if page_based else clean_line
        sections.append({
            "area": key,
            "title": title,
            "status": status,
            "count": n,
            "needs_look": needs_look,
            "line": line,
        })
    return sections


def not_completed(result):
    """Plain-English list of what a partial report didn't get to."""
    out = []
    reason = result.get("partial_reason")
    if result.get("partial") and not result.get("pages_planned"):
        out.append("No pages were checked: the time limit ran out while we were still finding your "
                   "site's pages.")
        return out
    late = result.get("pages_not_checked_in_time") or []
    if late and reason == "time_cap":
        out.append(f"{len(late)} page{'' if len(late) == 1 else 's'} weren't checked before the time "
                   "limit ran out (listed at the bottom of the report).")
    elif late:
        out.append(f"The check stopped unexpectedly, so {len(late)} planned "
                   f"page{'' if len(late) == 1 else 's'} weren't checked (listed at the bottom).")
    for page in result.get("pages") or []:
        if page.get("could_not_load"):
            out.append(f"{page['url']} couldn't be opened, so nothing on it was checked.")
    return out


def score_change(previous, current_score, current_versions):
    """How the score moved since the report this re-check started from.
    `previous` = {"score", "checked_at", "check_versions"} of that report."""
    prev_score = previous.get("score") or {}
    prev_value, cur_value = prev_score.get("value"), current_score.get("value")
    change = {"previous_value": prev_value, "previous_checked_at": previous.get("checked_at")}
    if prev_value is None or cur_value is None:
        change.update(delta=None, comparable=False,
                      message="One of the two reports couldn't be scored, so there's nothing to compare.")
        return change
    notes = []
    comparable = prev_score.get("formula_version") == current_score.get("formula_version")
    if not comparable:
        notes.append("We changed how the score is worked out since then, so the two numbers aren't "
                     "directly comparable.")
    prev_versions = previous.get("check_versions") or {}
    changed = [
        _SECTION_TITLES.get(a) or a for a in sorted(current_versions)
        if a in prev_versions and prev_versions[a] != current_versions[a]
    ]
    if changed:
        notes.append(f"Some of our checks were updated since then ({', '.join(changed)}), so part of "
                     "the difference may come from GetBuggy, not your site.")
    if prev_score.get("partial") or current_score.get("partial"):
        notes.append("One of the two reports is partial, so they may not cover the same pages.")
    delta = cur_value - prev_value
    when = _friendly_date(previous.get("checked_at"))
    since = f" since your last check{f' on {when}' if when else ''}"
    if delta > 0:
        message = f"Up {delta} point{'' if delta == 1 else 's'}{since}."
    elif delta < 0:
        message = f"Down {-delta} point{'' if delta == -1 else 's'}{since}."
    else:
        message = f"No change{since}."
    change.update(delta=delta, comparable=comparable, message=" ".join([message] + notes))
    return change


def _friendly_date(iso):
    if not iso:
        return ""
    try:
        d = datetime.fromisoformat(iso)
    except ValueError:
        return ""
    return f"{d.strftime('%b')} {d.day}, {d.year}"


def same_site(url_a, url_b):
    try:
        return normalize_host(urlparse(url_a).hostname) == normalize_host(urlparse(url_b).hostname) != ""
    except (TypeError, ValueError):
        return False


def previous_summary(result):
    """The bits of a finished report a later re-check needs for its delta."""
    return {
        "score": result.get("score"),
        "checked_at": result.get("checked_at"),
        "check_versions": result.get("check_versions"),
        "url": result.get("url"),
    }


def finalize_report(result, url, report_id, checked_at=None, previous=None):
    """Turns a crawl result (complete or partial) into the stored report,
    in place, and returns it."""
    from core import summarize_site_check  # core imports Playwright; keep this module light

    result["schema_version"] = SCHEMA_VERSION
    result["url"] = url
    result["report_id"] = report_id
    result["checked_at"] = checked_at or datetime.now(timezone.utc).isoformat(timespec="seconds")

    # A page that couldn't be opened (it timed out or refused to load) makes
    # the report partial too: those pages were attempted, not checked.
    if not result.get("partial") and any(p.get("could_not_load") for p in result.get("pages") or []):
        result["partial"] = True
        result["partial_reason"] = "pages_failed"

    platform = result.get("platform")
    for f in result.get("unique_problems") or []:
        normalize_finding(f, f.get("pages") or [], platform)
    for f in result.get("site_findings") or []:
        normalize_finding(f, [], platform)
    for page in result.get("pages") or []:
        for f in page.get("problems") or []:
            normalize_finding(f, [page["url"]], platform)

    result["not_completed"] = not_completed(result) if result.get("partial") else []
    result["sections"] = build_sections(result)
    result["check_versions"] = dict(CHECK_VERSIONS)
    result["score"] = compute_score(result)
    if previous and same_site(previous.get("url") or "", url):
        result["score"]["change"] = score_change(previous, result["score"], result["check_versions"])
    result["summary"] = summarize_site_check(result)
    return result


# --- "Send to your web person" ------------------------------------------------

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
_MAX_PAGES_LISTED = 5
# Some checks (accessibility, security) already write why/how/who into the
# message itself; the export prints those as their own lines instead.
_GUIDANCE_IN_MESSAGE = re.compile(r"\s+(?:Why it matters:|How to fix:|Who fixes it:)")
_WEB_PERSON_DETAILS = re.compile(r"\(For your web person: (.+)\)\s*$")


def _split_message(message):
    """(what's wrong, technical details for the web person or None)."""
    details = _WEB_PERSON_DETAILS.search(message)
    what = _GUIDANCE_IN_MESSAGE.split(message, maxsplit=1)[0].strip()
    return what, (details.group(1).rstrip(".") if details else None)


def render_export(result, permalink=None):
    """Plain-text/markdown version of a report for pasting into an email.
    Always ownership-gated: security details never appear here, whatever
    the server flag says (CLAUDE.md: never on a permalink or export)."""
    r = redact_security_details({"result": result})["result"]
    lines = []
    lines.append(f"# Website check for {r.get('url') or 'your site'}")
    meta = []
    when = _friendly_date(r.get("checked_at"))
    if when:
        meta.append(f"Checked {when} (UTC) by GetBuggy")
    if permalink:
        meta.append(f"Full report: {permalink}")
    if meta:
        lines.append(" · ".join(meta))
    lines.append("")

    score = r.get("score") or {}
    if score.get("value") is not None:
        lines.append(f"**Score: {score['value']}/100 — {score.get('band', '')}**")
        lines.append(score.get("basis", ""))
        if (score.get("change") or {}).get("message"):
            lines.append(score["change"]["message"])
    elif score.get("reason"):
        lines.append(f"**No score:** {score['reason']}")
    lines.append("")
    if r.get("summary"):
        lines.append(r["summary"])
        lines.append("")

    if r.get("partial"):
        lines.append("**This is a partial report.** Not everything was checked:")
        for item in r.get("not_completed") or []:
            lines.append(f"- {item}")
        lines.append("")

    sections = r.get("sections") or []
    if sections:
        lines.append("## At a glance")
        marks = {"clean": "OK", "issues": "To fix", "not_checked": "Not checked"}
        for s in sections:
            lines.append(f"- {s['title']} — {marks.get(s['status'], s['status'])}: {s['line']}")
        lines.append("")

    findings = list(r.get("site_findings") or []) + list(r.get("unique_problems") or [])
    findings = [f for f in findings if not f.get("informational")]
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.get("severity"), 3),
                                 f.get("confidence") != "verified"))
    if findings:
        lines.append("## What to fix")
        lines.append("")
        for i, f in enumerate(findings, 1):
            sev = (f.get("severity") or "").capitalize()
            look = " (needs a look)" if f.get("confidence") != "verified" else ""
            lines.append(f"### {i}. [{sev}] {f.get('title') or f['category']}{look}")
            what, details = _split_message(f.get("message", ""))
            lines.append(f"What's wrong: {what}")
            if f.get("why_it_matters"):
                lines.append(f"Why it matters: {f['why_it_matters']}")
            if f.get("how_to_fix"):
                lines.append(f"How to fix it: {f['how_to_fix']}")
            if f.get("who_fixes"):
                lines.append(f"Who fixes it: {f['who_fixes']}")
            if f.get("platform_note"):
                lines.append(f"Note: {f['platform_note']}")
            if details:
                lines.append(f"Details for your web person: {details}")
            pages = f.get("pages") or []
            if pages:
                shown = ", ".join(pages[:_MAX_PAGES_LISTED])
                more = len(pages) - _MAX_PAGES_LISTED
                lines.append(f"Found on: {shown}{f' and {more} more' if more > 0 else ''}")
            else:
                lines.append("Found on: your whole site")
            if look:
                lines.append("We're not completely sure about this one — please double-check it "
                             "before spending money on a fix.")
            lines.append("")

    sec = r.get("security_summary") or {}
    if sec.get("message"):
        lines.append("## Security")
        lines.append(sec["message"])
        lines.append("")

    notes = list(r.get("site_could_not_check") or [])
    for page in r.get("pages") or []:
        for n in page.get("could_not_check") or []:
            notes.append(f"{n} ({page['url']})" if page.get("url") and page["url"] not in n else n)
    if notes:
        lines.append("## What we couldn't check")
        for n in notes:
            lines.append(f"- {n}")
        lines.append("")

    lines.append("---")
    lines.append(f"Accessibility: {ACCESSIBILITY_DISCLAIMER}")
    lines.append("Things marked \"needs a look\" don't count toward the score. GetBuggy only looks at a "
                 "site the way a visitor would — it never submits forms or tries to break in.")
    lines.append("Reports are deleted 30 days after they're made.")
    return "\n".join(lines).rstrip() + "\n"
