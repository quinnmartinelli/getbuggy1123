"""Demo-video helper: serves the Sunrise Bakery demo site (demo_video/site)
on 127.0.0.1:8765 using the test fixture server, so {{BASE}} in the sitemap
is filled in. Runs until killed. Local demo tooling only."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fixture_server  # noqa: E402

PORT = 8765
server = fixture_server.serve(os.path.join(os.path.dirname(__file__), "site"), PORT)
print(f"Demo bakery site on http://127.0.0.1:{PORT}/", flush=True)
while True:
    time.sleep(3600)
