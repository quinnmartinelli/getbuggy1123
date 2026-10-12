import sys

from checks_accessibility import DISCLAIMER as ACCESSIBILITY_DISCLAIMER
from checks_cookies import JURISDICTIONS
from checks_security import (
    PUBLIC_SECURITY_MESSAGE,
    is_security_finding,
    show_security_details,
)
from core import (
    run_check,
    run_site_check,
    summarize_site_check,
    sort_problems,
    DEFAULT_CRAWL_PAGE_CAP,
    HIGH,
    MEDIUM,
    LOW,
    NEEDS_LOOK,
)
from report import finalize_report, render_export


def _gate_security(problems):
    """Same ownership gate as the web report: security findings print as a
    count only, unless GETBUGGY_SHOW_SECURITY_DETAILS=true."""
    if show_security_details():
        return problems, 0
    hidden = sum(is_security_finding(p) for p in problems)
    return [p for p in problems if not is_security_finding(p)], hidden


def print_report(problems, could_not_check=None):
    problems, hidden = _gate_security(problems)
    if hidden:
        print(PUBLIC_SECURITY_MESSAGE.format(n=hidden, s="" if hidden == 1 else "s"))
        print()
    if not problems and not could_not_check:
        print("No problems found.")
        return

    if problems:
        problems = sort_problems(problems)
        print(f"Found {len(problems)} problem(s):\n")
        current_severity = None
        for p in problems:
            if p["severity"] != current_severity:
                current_severity = p["severity"]
                print(f"--- {current_severity.upper()} ---")
            marker = " [NEEDS A LOOK]" if p.get("confidence") == NEEDS_LOOK else ""
            print(f"[{p['category']}]{marker} {p['message']}")

    if could_not_check:
        print(f"\nWhat we couldn't check ({len(could_not_check)}):")
        for note in could_not_check:
            print(f"  - {note}")


def print_site_report(result):
    print(result.get("summary") or summarize_site_check(result))
    score = result.get("score") or {}
    if score.get("value") is not None:
        print(f"Score: {score['value']}/100 — {score.get('band', '')}. {score.get('basis', '')}")
    elif score.get("reason"):
        print(f"No score: {score['reason']}")
    for item in result.get("not_completed") or []:
        print(f"  (not completed) {item}")
    if result.get("sections"):
        print()
        marks = {"clean": "OK ", "issues": "FIX", "not_checked": " - "}
        for s in result["sections"]:
            print(f"  [{marks.get(s['status'], '   ')}] {s['title']}: {s['line']}")
    print()
    if result.get("site_findings") or result.get("site_could_not_check"):
        print("=== Across your whole site ===")
        print_report(result.get("site_findings", []), result.get("site_could_not_check"))
        print()
    for page in result["pages"]:
        print(f"=== {page['url']} ===")
        print_report(page["problems"], page.get("could_not_check"))
        print()
    cookies = result.get("cookies")
    if cookies:
        print(f"=== Cookies and tracking (written for {cookies['written_for']}) ===")
        print(cookies["headline"])
        for c in cookies["companies"]:
            names = ", ".join(c["cookies"]) or "no cookies, contacted only"
            print(f"  - {c['name']} [{c['category']}]: {names}")
        print(cookies["note"])
        print()


if __name__ == "__main__":
    args = sys.argv[1:]
    crawl = "--crawl" in args
    if crawl:
        args.remove("--crawl")
    markdown = "--markdown" in args  # Step 8: the report for your web person
    if markdown:
        args.remove("--markdown")
    jurisdiction = None
    if "--jurisdiction" in args:
        i = args.index("--jurisdiction")
        jurisdiction = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]

    if len(args) != 1 or (jurisdiction is not None and jurisdiction not in JURISDICTIONS):
        print("Usage: python checker.py [--crawl] [--jurisdiction us|eu_uk|both] <url-or-local-file>")
        print(
            f"  --crawl  check the whole site (sitemap.xml, capped at "
            f"{DEFAULT_CRAWL_PAGE_CAP} pages by default), not just one page"
        )
        print("  --jurisdiction  whose cookie rules to describe (crawl only; default: us)")
        print("  --markdown  with --crawl: print the plain-text report for your web person instead")
        sys.exit(1)

    target = args[0]
    if crawl:
        result = run_site_check(target, jurisdiction=jurisdiction or "us")
        for page in result["pages"]:
            page["problems"] = sort_problems(page["problems"])
        finalize_report(result, url=target, report_id=None)
        if markdown:
            print(render_export(result), end="")
            sys.exit(0)
        print_site_report(result)
    else:
        problems, could_not_check = run_check(target)
        print_report(problems, could_not_check)
    print(f"\nAccessibility: {ACCESSIBILITY_DISCLAIMER}")
