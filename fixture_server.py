"""Tiny local HTTP server for the fixture sites the regression harness
crawls (test_site*/). A plain static server can't produce what several
Step 4 fixtures need, so this adds — driven by an optional `_fixture.json`
in the site's directory:

  * `{{BASE}}` in .xml/.txt/.html files is replaced with the server's real
    address, so a sitemap can list absolute URLs without hardcoding a port
  * `foo.xml.gz` is served gzipped on the fly from `foo.xml` (a gzipped
    sitemap, without committing a binary file)
  * "redirects": {"/old": "/new"}       -> 301
  * "headers":   {"/": {"X-Robots-Tag": "noindex"}}  (a list value sends
                                            the header once per item —
                                            several Set-Cookie lines)
  * {{THIRD_PARTY}} in templated files   -> the same server as
                                            http://localhost:<port>, a
                                            different host from the site's
                                            own 127.0.0.1 (a stand-in tracker)
  * {{TODAY}} in templated files         -> today's date ("March 05, 2026"),
                                            so a "recently updated" privacy
                                            policy never goes stale
  * "soft404":   "notfound.html"        -> every missing path answers 200
                                            with that page (a "soft 404")
  * "slow_prefix"/"slow_seconds"        -> matching paths hang that long
                                            (a page that never finishes)
  * "responses": {"/robots.txt": {"status": 500, "body": "...",
                  "body_hex": "...", "content_type": "..."}}
                                         -> a fixed answer for that path
                                            (sensitive-file probes: a .git
                                            folder or .DS_Store can't be
                                            committed as a real file)
  * "not_found_body": "..."              -> the body sent with every 404
  * redirects/responses keys may include a query string ("/?author=1")
  * {{FAKE:<kind>}} in templated files   -> a fake but realistic-looking
                                            secret (see FAKE_SECRETS) — built
                                            here so no key-shaped string is
                                            ever committed (GitHub push
                                            protection would block the push)

Test tooling only — never imported by the deployed app.
"""
import datetime
import gzip
import http.server
import json
import mimetypes
import os
import threading
import time
from urllib.parse import unquote, urlparse

TEMPLATED_EXTENSIONS = (".xml", ".txt", ".html", ".js")

# Assembled from pieces on purpose — see the module docstring.
FAKE_SECRETS = {
    "stripe": "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc0",
    "aws": "AKIA" + "QX7GETBUGGYFAKE1",
    "sendgrid": "SG." + "GetBuggyFixtureKey0000" + "." + "GetBuggyFixtureSecret0000000000000000000000",
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # per-request access logs would just interleave with the harness output

    def do_HEAD(self):
        self._serve(head_only=True)

    def do_GET(self):
        self._serve(head_only=False)

    def _send(self, status, body=b"", content_type="text/html; charset=utf-8", extra=None, head_only=False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            for value in v if isinstance(v, list) else [v]:
                self.send_header(k, value)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _read(self, fs_path, base):
        with open(fs_path, "rb") as f:
            data = f.read()
        if fs_path.endswith(TEMPLATED_EXTENSIONS):
            data = data.replace(b"{{BASE}}", base.encode())
            data = data.replace(b"{{THIRD_PARTY}}", base.replace("127.0.0.1", "localhost").encode())
            data = data.replace(b"{{TODAY}}", datetime.date.today().strftime("%B %d, %Y").encode())
            for kind, value in FAKE_SECRETS.items():
                data = data.replace(f"{{{{FAKE:{kind}}}}}".encode(), value.encode())
        return data

    def _serve(self, head_only):
        cfg = self.server.fixture_config
        root = self.server.fixture_dir
        base = f"http://127.0.0.1:{self.server.server_port}"
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        full = f"{path}?{parsed.query}" if parsed.query else path

        for key in (full, path):
            if key in cfg.get("redirects", {}):
                return self._send(301, extra={"Location": cfg["redirects"][key]}, head_only=head_only)
            if key in cfg.get("responses", {}):
                r = cfg["responses"][key]
                body = bytes.fromhex(r["body_hex"]) if "body_hex" in r else r.get("body", "").encode()
                return self._send(
                    r.get("status", 200), body,
                    r.get("content_type", "text/plain; charset=utf-8"), head_only=head_only,
                )

        prefix = cfg.get("slow_prefix")
        if prefix and path.startswith(prefix):
            time.sleep(cfg.get("slow_seconds", 120))

        rel = path.lstrip("/") or "index.html"
        if rel.endswith("/"):
            rel += "index.html"
        fs_path = os.path.normpath(os.path.join(root, rel))
        extra = dict(cfg.get("headers", {}).get(path, {}))

        if not fs_path.startswith(os.path.abspath(root)):
            return self._send(404, b"not found", head_only=head_only)

        if os.path.isfile(fs_path):
            ctype = mimetypes.guess_type(fs_path)[0] or "application/octet-stream"
            if fs_path.endswith(".html"):
                ctype = "text/html; charset=utf-8"
            return self._send(200, self._read(fs_path, base), ctype, extra, head_only)

        if fs_path.endswith(".gz") and os.path.isfile(fs_path[:-3]):
            body = gzip.compress(self._read(fs_path[:-3], base))
            return self._send(200, body, "application/gzip", extra, head_only)

        if cfg.get("soft404"):
            page = os.path.join(root, cfg["soft404"])
            return self._send(200, self._read(page, base), extra=extra, head_only=head_only)

        return self._send(404, cfg.get("not_found_body", "not found").encode(), extra=extra, head_only=head_only)


class _Server(http.server.ThreadingHTTPServer):
    # The default listen backlog (5) drops connections when a crawl's
    # browser and checks_security's probes hit the fixture at once.
    request_queue_size = 128


def serve(directory, port):
    """Serves `directory` on 127.0.0.1:port in a background thread. Call
    .shutdown() on the returned server when done."""
    server = _Server(("127.0.0.1", port), _Handler)
    server.daemon_threads = True  # a deliberately hung request must not block shutdown
    server.fixture_dir = os.path.abspath(directory)
    cfg_path = os.path.join(directory, "_fixture.json")
    server.fixture_config = json.load(open(cfg_path)) if os.path.isfile(cfg_path) else {}
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
