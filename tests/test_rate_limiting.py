"""Unit tests for server.py's rate limiting (GetBuggy Step 3, operational
safety): the per-IP hourly limit and the daily global run cap. No real
server process or browser involved — these call the rate-limiting
functions directly, and the two TestClient cases at the bottom exercise
/api/check's rejection paths only (missing authorization, unsafe URL),
which are rejected before any subprocess/browser ever gets spawned.
"""
import time

import server


def _reset_rate_limit_state():
    server._global_run_times.clear()
    server._ip_run_times.clear()


def setup_function(_):
    _reset_rate_limit_state()


def teardown_function(_):
    _reset_rate_limit_state()


def test_per_ip_limit_allows_up_to_the_configured_count():
    original = server.RATE_LIMIT_PER_IP_PER_HOUR
    server.RATE_LIMIT_PER_IP_PER_HOUR = 3
    try:
        for _ in range(3):
            assert server.check_rate_limits("1.2.3.4") is None
            server.record_run("1.2.3.4")
    finally:
        server.RATE_LIMIT_PER_IP_PER_HOUR = original


def test_per_ip_limit_blocks_once_exceeded_with_a_friendly_message():
    original = server.RATE_LIMIT_PER_IP_PER_HOUR
    server.RATE_LIMIT_PER_IP_PER_HOUR = 3
    try:
        for _ in range(3):
            server.record_run("1.2.3.4")
        message = server.check_rate_limits("1.2.3.4")
        assert message is not None
        assert "3" in message
        # A friendly, plain-English message, not a bare "429" — see
        # CLAUDE.md's "plain English" standing rule.
        assert "try again" in message.lower()
    finally:
        server.RATE_LIMIT_PER_IP_PER_HOUR = original


def test_per_ip_limit_is_independent_per_ip():
    original = server.RATE_LIMIT_PER_IP_PER_HOUR
    server.RATE_LIMIT_PER_IP_PER_HOUR = 1
    try:
        server.record_run("1.1.1.1")
        assert server.check_rate_limits("1.1.1.1") is not None
        # A different IP has its own, unused budget.
        assert server.check_rate_limits("2.2.2.2") is None
    finally:
        server.RATE_LIMIT_PER_IP_PER_HOUR = original


def test_per_ip_limit_window_expires_old_entries():
    original = server.RATE_LIMIT_PER_IP_PER_HOUR
    server.RATE_LIMIT_PER_IP_PER_HOUR = 1
    try:
        stale = time.time() - server.RATE_LIMIT_WINDOW_SECONDS - 10
        server._ip_run_times["9.9.9.9"].append(stale)
        # That one run happened over an hour ago — outside the rolling
        # window — so this IP should read as having 0 runs, not 1.
        assert server.check_rate_limits("9.9.9.9") is None
    finally:
        server.RATE_LIMIT_PER_IP_PER_HOUR = original


def test_global_daily_cap_blocks_every_ip_once_hit():
    original = server.DAILY_GLOBAL_RUN_CAP
    server.DAILY_GLOBAL_RUN_CAP = 2
    try:
        server.record_run("a")
        server.record_run("b")
        # The cap is hit regardless of which IPs contributed to it — even
        # a brand-new IP that has never run before is blocked.
        message = server.check_rate_limits("never-seen-before")
        assert message is not None
    finally:
        server.DAILY_GLOBAL_RUN_CAP = original


def test_global_daily_cap_window_expires_old_entries():
    original = server.DAILY_GLOBAL_RUN_CAP
    server.DAILY_GLOBAL_RUN_CAP = 1
    try:
        stale = time.time() - server.DAILY_WINDOW_SECONDS - 10
        server._global_run_times.append(stale)
        assert server.check_rate_limits("anyone") is None
    finally:
        server.DAILY_GLOBAL_RUN_CAP = original


def test_global_cap_is_reported_over_per_ip_limit_when_both_would_trigger():
    """The global cap protects everyone; the per-IP limit protects
    against one caller. When both would block a request, the global
    cap's message is the one returned."""
    orig_daily = server.DAILY_GLOBAL_RUN_CAP
    orig_ip = server.RATE_LIMIT_PER_IP_PER_HOUR
    server.DAILY_GLOBAL_RUN_CAP = 1
    server.RATE_LIMIT_PER_IP_PER_HOUR = 1
    try:
        server.record_run("x")
        message = server.check_rate_limits("x")
        assert "today" in message.lower()
    finally:
        server.DAILY_GLOBAL_RUN_CAP = orig_daily
        server.RATE_LIMIT_PER_IP_PER_HOUR = orig_ip


def test_check_rate_limits_does_not_itself_record_a_run():
    """Calling check_rate_limits() (e.g. just to see if a request would
    be allowed) must not consume budget on its own — only record_run()
    should. Otherwise a caller who checks once, then gets rejected for
    an unrelated reason (bad URL, missing authorization), would have
    silently spent part of their rate-limit budget for nothing."""
    original = server.RATE_LIMIT_PER_IP_PER_HOUR
    server.RATE_LIMIT_PER_IP_PER_HOUR = 1
    try:
        for _ in range(5):
            assert server.check_rate_limits("repeat-checker") is None
    finally:
        server.RATE_LIMIT_PER_IP_PER_HOUR = original


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, headers=None, client_host=None):
        self.headers = headers or {}
        self.client = _FakeClient(client_host) if client_host else None


def test_get_client_ip_prefers_x_forwarded_for():
    """Render (like most PaaS platforms) proxies requests, so
    request.client.host would otherwise be the proxy's own address for
    every visitor, not the real one."""
    req = _FakeRequest(
        headers={"x-forwarded-for": "203.0.113.5, 10.0.0.1"},
        client_host="10.0.0.1",
    )
    assert server.get_client_ip(req) == "203.0.113.5"


def test_get_client_ip_falls_back_to_request_client():
    req = _FakeRequest(headers={}, client_host="192.168.1.1")
    assert server.get_client_ip(req) == "192.168.1.1"


def test_get_client_ip_handles_missing_client():
    req = _FakeRequest(headers={}, client_host=None)
    assert server.get_client_ip(req) == "unknown"


# --- /api/check rejection paths, via a real (but browser-free) request ---
# These never reach the concurrency semaphore or spawn a subprocess, so
# they're fast and safe to run in CI on every push.

from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(server.app)


def test_check_endpoint_requires_authorization():
    resp = client.post("/api/check", json={"url": "https://example.com"})
    assert resp.status_code == 400
    detail = resp.json()["detail"].lower()
    assert "own" in detail or "permission" in detail


def test_check_endpoint_rejects_explicit_authorized_false():
    resp = client.post(
        "/api/check", json={"url": "https://example.com", "authorized": False}
    )
    assert resp.status_code == 400


def test_check_endpoint_rejects_unsafe_url_even_when_authorized():
    """Safety validation isn't bypassable just by checking the
    authorization box — a private/internal address is still rejected."""
    resp = client.post(
        "/api/check", json={"url": "http://localhost", "authorized": True}
    )
    assert resp.status_code == 400
