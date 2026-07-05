"""
Tests for the fix to the --forwarded-allow-ips=* Dockerfile vulnerability.

With --forwarded-allow-ips=*, uvicorn rewrites request.client.host to
whatever X-Forwarded-For an attacker sends for ANY connecting peer, which
silently defeats web/auth.py's get_client_ip() peer check (get_client_ip
re-inspects request.client.host, but by the time it runs uvicorn may have
already substituted an attacker-controlled value).

Two things are covered here:
  1. The Dockerfile no longer hands uvicorn a wildcard trust-everyone flag,
     and instead scopes it to the same TRUSTED_PROXY_IPS allowlist the app
     itself uses.
  2. get_client_ip's own application-level logic: it must only honor
     X-Forwarded-For/X-Real-IP when the immediate peer is a trusted proxy,
     and must ignore (not crash on) forwarded headers from anyone else.

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
