"""Demo-video helper: runs the real GetBuggy app unchanged, except that the
API-layer SSRF guard also accepts the one local demo site
(http://127.0.0.1:8765, see serve_demo.py). Every other private address is
still rejected. Local demo tooling only — never deployed.

    GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS=true ./venv/bin/python demo_video/demo_server.py
"""
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server  # noqa: E402

DEMO_NETLOC = "127.0.0.1:8765"
_real_validate = server.validate_public_url


def _validate_allowing_demo_site(url):
    if urlparse(url).netloc == DEMO_NETLOC:
        return
    return _real_validate(url)


server.validate_public_url = _validate_allowing_demo_site

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(server.app, host="127.0.0.1", port=8010)
