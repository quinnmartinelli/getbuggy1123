"""Refreshes the known-vulnerable / known-outdated lists bundled in
security_data/ (GetBuggy Step 5). Run by hand, then commit the result:

    python update_security_data.py

The checker itself NEVER fetches these at runtime — it only reads the
bundled files (see checks_security.py). That keeps every report
reproducible from the commit that produced it, and means a check never
depends on a third-party API being up.

Sources (all public, no key needed):
  * Front-end libraries: Retire.js's vulnerability repository
    (github.com/RetireJS/retire.js, Apache-2.0). Trimmed to the fields
    checks_security.py uses (version extractors + vulnerable ranges).
  * WordPress core: WordPress.org's own stable-check API, which labels
    every released version "latest", "outdated" or "insecure" (insecure =
    WordPress.org has shipped a security fix the version doesn't have).
  * WordPress plugins: latest released version of the most popular
    plugins on WordPress.org. This answers "outdated", not "known CVE" —
    no free, key-less plugin vulnerability feed exists any more (the
    Wordfence v2 feed this was going to use now answers HTTP 410), so the
    report says plainly that plugin vulnerabilities weren't checked.
"""

import datetime
import json
import os
import sys

import requests

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_data")
HEADERS = {"User-Agent": "GetBuggyBot/1.0 (+https://github.com/quinnmartinelli/website-checker)"}

RETIRE_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json"
WP_CORE_URL = "https://api.wordpress.org/core/stable-check/1.0/"
WP_PLUGINS_URL = "https://api.wordpress.org/plugins/info/1.2/"
WP_PLUGIN_PAGES = 4  # x 250 = the 1,000 most popular plugins

# Retire.js extractor kinds checks_security.py understands. The others
# ("hashes", "ast", "filecontentreplace") need tooling we don't bundle.
RETIRE_EXTRACTORS = ("uri", "filename", "filecontent", "func")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _write(name, payload):
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, name)
    with open(path, "w") as f:
        json.dump(payload, f, indent=0, sort_keys=True)
        f.write("\n")
    print(f"wrote {path} ({os.path.getsize(path) // 1024} KB)")


def update_retire():
    raw = requests.get(RETIRE_URL, headers=HEADERS, timeout=60).json()
    libraries = {}
    for name, lib in raw.items():
        if name == "retire-example" or not isinstance(lib, dict):
            continue
        extractors = {
            k: v for k, v in (lib.get("extractors") or {}).items()
            if k in RETIRE_EXTRACTORS and v
        }
        vulns = []
        for v in lib.get("vulnerabilities") or []:
            ids = v.get("identifiers") or {}
            vulns.append({
                k: val for k, val in {
                    "below": v.get("below"),
                    "atOrAbove": v.get("atOrAbove"),
                    "severity": v.get("severity"),
                    "cve": ids.get("CVE") or [],
                    "summary": ids.get("summary"),
                }.items() if val
            })
        if extractors and vulns:
            libraries[name] = {"extractors": extractors, "vulnerabilities": vulns}
    _write("retirejs.json", {
        "_source": RETIRE_URL,
        "_license": "Apache-2.0 (Retire.js)",
        "_fetched": _now(),
        "libraries": libraries,
    })


def update_wordpress_core():
    versions = requests.get(WP_CORE_URL, headers=HEADERS, timeout=60).json()
    _write("wordpress_core.json", {
        "_source": WP_CORE_URL,
        "_fetched": _now(),
        "versions": versions,
    })


def update_wordpress_plugins():
    latest = {}
    for page in range(1, WP_PLUGIN_PAGES + 1):
        resp = requests.get(
            WP_PLUGINS_URL,
            params={
                "action": "query_plugins",
                "request[browse]": "popular",
                "request[per_page]": 250,
                "request[page]": page,
                "request[fields][description]": 0,
                "request[fields][sections]": 0,
                "request[fields][screenshots]": 0,
                "request[fields][tags]": 0,
                "request[fields][ratings]": 0,
                "request[fields][banners]": 0,
                "request[fields][icons]": 0,
            },
            headers=HEADERS,
            timeout=60,
        )
        for plugin in resp.json().get("plugins", []):
            if plugin.get("slug") and plugin.get("version"):
                latest[plugin["slug"]] = {
                    "name": plugin.get("name") or plugin["slug"],
                    "latest": plugin["version"],
                }
    _write("wordpress_plugins.json", {
        "_source": WP_PLUGINS_URL + " (browse=popular)",
        "_fetched": _now(),
        "_note": "Latest released versions only - not a vulnerability list.",
        "plugins": latest,
    })


if __name__ == "__main__":
    try:
        update_retire()
        update_wordpress_core()
        update_wordpress_plugins()
    except (requests.RequestException, ValueError) as e:
        print(f"Update failed, bundled data left as it was: {e}")
        sys.exit(1)
