"""Launches a headless Chromium instance and immediately closes it, then
exits 0 — or exits non-zero with a message on stderr if it couldn't.

Used by GET /health (see server.py) to verify the browser can actually
launch, not just that the server process is alive. Run as its own
subprocess, the same way every other Chromium launch in this project is
(see CLAUDE.md's standing rule on this) — a hung or crashed browser
launch can then never affect the main server process itself, the same
safety property the crawl subprocess already has.
"""
import sys

from playwright.sync_api import sync_playwright


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        browser.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}", file=sys.stderr)
        sys.exit(1)
