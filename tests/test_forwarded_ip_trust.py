"""
Tests for the fix to the --forwarded-allow-ips=* Dockerfile vulnerability,
plus the follow-up fix for IP resolution on Render.

With --forwarded-allow-ips=*, uvicorn rewrites request.client.host to
whatever X-Forwarded-For an attacker sends for ANY connecting peer, which
silently defeats web/auth.py's get_client_ip() peer check (get_client_ip
re-inspects request.client.host, but by the time it runs uvicorn may have
already substituted an attacker-controlled value).

Three things are covered here:
  1. The Dockerfile no longer hands uvicorn a wildcard trust-everyone flag,
     and instead scopes it to the same TRUSTED_PROXY_IPS allowlist the app
     itself uses.
  2. get_client_ip's own application-level logic: it must only honor
     X-Forwarded-For/X-Real-IP when the immediate peer is a trusted proxy,
     and must ignore (not crash on) forwarded headers from anyone else.
  3. On Render (TRUSTED_PROXY_IPS unset in production -- confirmed absent
     from the Render dashboard's env var list), request.client.host is
     Render's own internal proxy peer, identical for every visitor, which
     collapsed the 5-attempts/15-minutes login rate limit onto a single
     shared bucket for the whole world. Render fronts every service with
     Cloudflare (confirmed live: onrender.com responses carry
     `server: cloudflare`, `cf-ray`, `x-render-origin-server: uvicorn`),
     and Cloudflare sets CF-Connecting-IP from the real TCP connection to
     its edge -- a client cannot forge it (Cloudflare docs). get_client_ip
     now uses CF-Connecting-IP when RENDER=true, restoring one rate-limit
     bucket per real visitor.

Same convention as tests/test_rate_limiter.py: plain pytest, no async needed
here since get_client_ip is synchronous.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web import auth


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, peer_ip, headers=None):
        self.client = _FakeClient(peer_ip) if peer_ip is not None else None
        self.headers = headers or {}


def test_dockerfile_does_not_wildcard_trust_forwarded_headers():
    dockerfile = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Dockerfile")
    with open(dockerfile) as f:
        content = f.read()
    cmd_lines = [line for line in content.splitlines() if line.startswith("CMD")]
    assert cmd_lines, "expected a CMD instruction in the Dockerfile"
    assert "--forwarded-allow-ips=*" not in cmd_lines[0]
    assert "--forwarded-allow-ips=${TRUSTED_PROXY_IPS:-127.0.0.1}" in cmd_lines[0]


def test_forwarded_header_honored_only_from_trusted_peer(monkeypatch):
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", {"10.0.0.5"})
    request = _FakeRequest("10.0.0.5", headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.5"})
    assert auth.get_client_ip(request) == "203.0.113.7"


def test_forwarded_header_ignored_from_untrusted_peer(monkeypatch):
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", {"10.0.0.5"})
    # Attacker connects directly and sends a spoofed X-Forwarded-For --
    # since their peer IP isn't the trusted proxy, the header must be ignored
    # and the real connecting IP used instead.
    request = _FakeRequest("198.51.100.9", headers={"X-Forwarded-For": "1.2.3.4"})
    assert auth.get_client_ip(request) == "198.51.100.9"


def test_empty_trusted_proxy_ips_never_honors_any_forwarded_header(monkeypatch):
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", set())
    request = _FakeRequest("127.0.0.1", headers={"X-Forwarded-For": "1.2.3.4"})
    assert auth.get_client_ip(request) == "127.0.0.1"


def test_falls_back_to_real_ip_header_when_no_forwarded_for(monkeypatch):
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", {"10.0.0.5"})
    request = _FakeRequest("10.0.0.5", headers={"X-Real-IP": "203.0.113.99"})
    assert auth.get_client_ip(request) == "203.0.113.99"


def test_missing_client_returns_unknown():
    request = _FakeRequest(None)
    assert auth.get_client_ip(request) == "unknown"


# ─── Render + Cloudflare: CF-Connecting-IP resolution ──────────────────────────

def test_render_trusts_cf_connecting_ip_over_shared_proxy_peer(monkeypatch):
    """On Render, request.client.host is Render's internal proxy -- the same
    for every visitor -- so it must never be used when CF-Connecting-IP is
    present, or every visitor collapses onto one rate-limit bucket."""
    monkeypatch.setattr(auth, "_ON_RENDER", True)
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", set())
    request = _FakeRequest(
        "10.201.4.17",  # Render's shared internal proxy peer
        headers={"CF-Connecting-IP": "203.0.113.7"},
    )
    assert auth.get_client_ip(request) == "203.0.113.7"


def test_render_ignores_spoofable_forwarded_for_leftmost_entry(monkeypatch):
    """Cloudflare APPENDS its verified IP to any client-supplied
    X-Forwarded-For rather than replacing it, so the leftmost entry can be
    attacker-injected. get_client_ip must key off CF-Connecting-IP, not
    X-Forwarded-For position, once on Render."""
    monkeypatch.setattr(auth, "_ON_RENDER", True)
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", set())
    request = _FakeRequest(
        "10.201.4.17",
        headers={
            "X-Forwarded-For": "198.51.100.250, 203.0.113.7",  # attacker-prepended fake, then real
            "CF-Connecting-IP": "203.0.113.7",
        },
    )
    assert auth.get_client_ip(request) == "203.0.113.7"


def test_render_falls_back_to_direct_ip_when_cf_header_missing(monkeypatch):
    monkeypatch.setattr(auth, "_ON_RENDER", True)
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", set())
    request = _FakeRequest("10.201.4.17", headers={})
    assert auth.get_client_ip(request) == "10.201.4.17"


def test_render_ignores_malformed_cf_connecting_ip(monkeypatch):
    monkeypatch.setattr(auth, "_ON_RENDER", True)
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", set())
    request = _FakeRequest("10.201.4.17", headers={"CF-Connecting-IP": "not-an-ip"})
    assert auth.get_client_ip(request) == "10.201.4.17"


def test_off_render_ignores_cf_connecting_ip(monkeypatch):
    """Off Render (e.g. local dev, or another host with no Cloudflare edge in
    front), CF-Connecting-IP is just another client-suppliable header and
    must not be trusted."""
    monkeypatch.setattr(auth, "_ON_RENDER", False)
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", set())
    request = _FakeRequest("198.51.100.9", headers={"CF-Connecting-IP": "1.2.3.4"})
    assert auth.get_client_ip(request) == "198.51.100.9"


def test_trusted_proxy_forwarded_for_rejects_malformed_ip(monkeypatch):
    monkeypatch.setattr(auth, "_ON_RENDER", False)
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", {"10.0.0.5"})
    request = _FakeRequest("10.0.0.5", headers={"X-Forwarded-For": "'; DROP TABLE users;--"})
    assert auth.get_client_ip(request) == "10.0.0.5"


# ─── Two real-world visitors behind Render must get independent rate limits ────

def test_two_visitors_behind_render_get_independent_rate_limit_buckets(monkeypatch):
    """Simulates two genuine users in different countries, both proxied
    through the same Render/Cloudflare edge (same request.client.host), each
    identified by their own CF-Connecting-IP. Exhausting one visitor's login
    attempts must not touch the other's -- this is the exact scenario that
    was broken when get_client_ip() fell back to Render's shared proxy peer."""
    monkeypatch.setattr(auth, "_ON_RENDER", True)
    monkeypatch.setattr(auth, "_TRUSTED_PROXY_IPS", set())
    auth._login_attempts.clear()

    render_proxy_peer = "10.201.4.17"
    visitor_iraq = _FakeRequest(render_proxy_peer, headers={"CF-Connecting-IP": "37.236.0.55"})
    visitor_germany = _FakeRequest(render_proxy_peer, headers={"CF-Connecting-IP": "85.214.132.117"})

    ip_iraq = auth.get_client_ip(visitor_iraq)
    ip_germany = auth.get_client_ip(visitor_germany)
    assert ip_iraq != ip_germany

    for _ in range(auth.RATE_LIMIT_MAX):
        assert auth.check_rate_limit(ip_iraq)[0] is True
        auth.record_failed_attempt(ip_iraq)

    allowed, remaining = auth.check_rate_limit(ip_iraq)
    assert allowed is False
    assert remaining > 0

    # The German visitor, sharing the same Render proxy peer, must be
    # completely unaffected.
    allowed_germany, _ = auth.check_rate_limit(ip_germany)
    assert allowed_germany is True

    auth._login_attempts.pop(ip_iraq, None)
    auth._login_attempts.pop(ip_germany, None)
