"""Step 8: the queued, partial and scored states actually render in the
page, and a shared /r/<id> link opens its report. Loads the real
static/index.html + report.js in headless Chromium with the API answered
by canned responses (page.route), so no server, crawl or network is
involved. Skipped if Chromium isn't installed."""
import json
import os

import pytest

playwright = pytest.importorskip("playwright.sync_api")

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
BASE = "http://getbuggy.test"

PARTIAL_RESULT = {
    "url": "https://bakery.example/",
    "checked_at": "2026-10-11T12:00:00+00:00",
    "report_id": "abcdefghijklmnop1234",
    "summary": "Partial report — 1 of 2 pages could be opened and checked — 1 problem(s) on 1 page(s)",
    "partial": True,
    "partial_reason": "pages_failed",
    "pages_planned": 2,
    "pages_checked": 2,
    "pages_found_total": 2,
    "not_completed": ["https://bakery.example/menu couldn't be opened, so nothing on it was checked."],
    "pages": [
        {"url": "https://bakery.example/", "problems": [], "could_not_check": []},
        {"url": "https://bakery.example/menu", "problems": [], "could_not_check": [], "could_not_load": True},
    ],
    "unique_problems": [{
        "category": "Broken Form", "title": "Broken Form", "severity": "high", "confidence": "verified",
        "message": "Form contact did nothing when sent.", "pages": ["https://bakery.example/"],
    }],
    "site_findings": [],
    "score": {
        "value": 85, "out_of": 100, "band": "A few things to fix", "partial": True,
        "basis": "Based on 1 page checked — this report is partial, so the score only covers what we managed to check.",
        "deductions": [{"area": "forms", "title": "Forms", "points": 15, "capped": False, "findings_counted": 1}],
        "needs_look_not_counted": 0,
        "change": {"delta": 10, "message": "Up 10 points since your last check on Oct 1, 2026."},
    },
    "sections": [
        {"area": "links", "title": "Links and pages", "status": "clean", "count": 0, "needs_look": 0,
         "line": "No broken links or missing pages found on the pages we checked."},
        {"area": "forms", "title": "Forms", "status": "issues", "count": 1, "needs_look": 0,
         "line": "1 problem found."},
        {"area": "security", "title": "Security", "status": "clean", "count": 0, "needs_look": 0,
         "line": "No exposed files or hacked-site signals found on the pages we checked."},
    ],
}


@pytest.fixture
def page():
    with playwright.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:  # Chromium not installed here
            pytest.skip(f"Chromium unavailable: {e}")
        pg = browser.new_page()
        yield pg
        browser.close()


def serve(pg, api):
    """Static files from disk; /api/* from `api(path, method)`; anything
    else (fonts etc.) is refused, so nothing leaves this machine."""
    def handle(route, request):
        url = request.url
        if not url.startswith(BASE):
            return route.abort()
        path = url[len(BASE):].split("?")[0]
        if path.startswith("/api/"):
            status, body = api(path, request.method)
            return route.fulfill(status=status, content_type="application/json", body=json.dumps(body))
        name = "index.html" if path == "/" or path.startswith("/r/") else path.lstrip("/")
        file = os.path.join(STATIC, name)
        if not os.path.isfile(file):
            return route.fulfill(status=404, body="")
        ctype = {"js": "application/javascript", "css": "text/css"}.get(name.rsplit(".", 1)[-1], "text/html")
        with open(file, "rb") as fh:
            return route.fulfill(status=200, content_type=ctype, body=fh.read())
    pg.route("**/*", handle)


def test_queued_then_partial_report_renders(page):
    polls = {"n": 0}

    def api(path, method):
        if path == "/api/check":
            return 200, {"job_id": "job1", "status": "queued", "queue_position": 2}
        if path == "/api/check-status/job1":
            polls["n"] += 1
            if polls["n"] == 1:
                return 200, {"status": "queued", "queue_position": 2, "estimated_wait_seconds": 240,
                             "queue_message": "Lots of people are checking their sites right now. You're 2nd in line — your check should start in about 4 minutes. Keep this page open; it will start by itself."}
            return 200, {"status": "done", "result": PARTIAL_RESULT}
        return 404, {"detail": "nope"}

    serve(page, api)
    page.goto(BASE + "/")
    page.fill("#url-input", "bakery.example")
    page.check("#authorize-checkbox")
    page.click("#submit-btn")

    page.wait_for_function("document.getElementById('status').textContent.includes('2nd in line')", timeout=10000)
    assert "about 4 minutes" in page.text_content("#status")

    page.wait_for_selector(".gb-score", timeout=10000)
    results = page.text_content("#results")
    assert "This is a partial report: some pages couldn't be opened" in results
    assert "https://bakery.example/menu couldn't be opened" in results
    assert page.text_content(".gb-score-value") == "85"
    assert "A few things to fix" in results and "Up 10 points" in results
    assert "No broken links or missing pages found on the pages we checked." in results
    assert "No exposed files or hacked-site signals found" in results
    assert page.is_visible("text=Copy for your web person")
    # The next check from this page carries the report id, for the delta.
    assert page.evaluate("window.gbPreviousReportId") == "abcdefghijklmnop1234"


def test_shared_permalink_opens_its_report(page):
    def api(path, method):
        if path == "/api/report/abcdefghijklmnop1234":
            return 200, {"status": "done", "result": PARTIAL_RESULT}
        return 404, {"detail": "We couldn't find that report. Reports are deleted 30 days after they're made."}

    serve(page, api)
    page.goto(BASE + "/r/abcdefghijklmnop1234")
    page.wait_for_selector(".gb-score", timeout=10000)
    assert "Report for https://bakery.example/" in page.text_content("#results")


def test_expired_permalink_says_so_plainly(page):
    serve(page, lambda path, method: (404, {"detail": "We couldn't find that report. Reports are deleted 30 days after they're made."}))
    page.goto(BASE + "/r/zzzzzzzzzzzzzzzzzzzz")
    page.wait_for_function("document.getElementById('error').textContent.length > 0", timeout=10000)
    assert "deleted 30 days" in page.text_content("#error")
