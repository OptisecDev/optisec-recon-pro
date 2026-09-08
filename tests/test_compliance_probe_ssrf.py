"""
Tests for the SSRF guard on modules/compliance/checker.py's
auto_probe_target() (POST /compliance/api/probe, and indirectly
POST /compliance/api/assess via _probe_https_signal()).

auto_probe_target() made a real outbound HTTP request to whatever
target_url the caller supplied, with no validation that it wasn't
internal/private -- any authenticated `compliance`-entitled user could
point it at 127.0.0.1, 169.254.169.254 (cloud metadata), or an RFC1918
address and get back status code/headers/cookies for it. Same class of
bug already fixed in modules/osint/network_intelligence.py
(_is_ssrf_blocked_ip, commit 4e3ce17) -- this is that same guard, adapted
for a full URL rather than a bare IP, plus per-redirect-hop revalidation
since this function (unlike network_intelligence.py's direct socket
probes) follows HTTP redirects, which a legitimate-looking public
target_url could use to redirect into an internal address.

Follows tests/test_network_intelligence.py's convention: monkeypatched
httpx.AsyncClient, no real network calls for the blocked-path assertions.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.compliance.checker as checker


def _run(coro):
    return asyncio.run(coro)


class _FakeHeaders(dict):
    def items(self):
        return dict.items(self)


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, is_redirect=False, next_url=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.is_redirect = is_redirect
        self.cookies = type("C", (), {"jar": []})()
        self.next_request = type("R", (), {"url": next_url})() if next_url else None


class _FakeAsyncClient:
    def __init__(self, responses=None, **kw):
        self._responses = list(responses or [])
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, follow_redirects=False, **kw):
        self.calls.append(url)
        return self._responses.pop(0) if self._responses else _FakeResponse()


class TestIsSsrfBlockedUrl:
    def test_loopback_is_blocked(self):
        assert checker._is_ssrf_blocked_url("http://127.0.0.1/") is True

    def test_link_local_metadata_is_blocked(self):
        assert checker._is_ssrf_blocked_url("http://169.254.169.254/latest/meta-data/") is True

    def test_rfc1918_private_is_blocked(self):
        assert checker._is_ssrf_blocked_url("http://10.0.0.5:8080/admin") is True
        assert checker._is_ssrf_blocked_url("http://192.168.1.1/") is True

    def test_localhost_hostname_is_blocked(self):
        assert checker._is_ssrf_blocked_url("http://localhost/") is True

    def test_bare_host_without_scheme_is_blocked_when_private(self):
        assert checker._is_ssrf_blocked_url("127.0.0.1") is True

    def test_public_url_is_allowed(self):
        assert checker._is_ssrf_blocked_url("https://example.com/") is False

    def test_unresolvable_host_fails_closed(self):
        assert checker._is_ssrf_blocked_url("http://this-should-not-resolve-xyz123.invalid/") is True


class TestAutoProbeTargetRefusesInternalTargets:
    def test_loopback_target_is_refused_without_any_network_call(self, monkeypatch):
        fake = _FakeAsyncClient()
        monkeypatch.setattr(checker.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(checker.auto_probe_target("http://127.0.0.1/admin"))

        assert "probe_error" in result and "private/internal" in result["probe_error"]
        assert fake.calls == []  # refused before any GET happened

    def test_metadata_target_is_refused(self, monkeypatch):
        fake = _FakeAsyncClient()
        monkeypatch.setattr(checker.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(checker.auto_probe_target("http://169.254.169.254/"))

        assert "probe_error" in result and "private/internal" in result["probe_error"]

    def test_public_target_still_works(self, monkeypatch):
        fake = _FakeAsyncClient(responses=[_FakeResponse(200, {"strict-transport-security": "max-age=1"})])
        monkeypatch.setattr(checker.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(checker.auto_probe_target("https://example.com/"))

        assert result.get("hsts") is True
        assert "probe_error" not in result


class TestRedirectRevalidation:
    def test_redirect_to_internal_address_is_refused(self, monkeypatch):
        """A public-looking target_url that 302s to an internal address
        must not be followed -- httpx's own follow_redirects=True would
        have walked straight into it."""
        redirect_resp = _FakeResponse(302, {"location": "http://169.254.169.254/"}, is_redirect=True,
                                       next_url="http://169.254.169.254/")
        fake = _FakeAsyncClient(responses=[redirect_resp])
        monkeypatch.setattr(checker.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(checker.auto_probe_target("https://example.com/redirect-me"))

        assert "probe_error" in result and "private/internal" in result["probe_error"]
        assert fake.calls == ["https://example.com/redirect-me"]  # never followed to the internal hop

    def test_redirect_to_another_public_url_is_followed(self, monkeypatch):
        redirect_resp = _FakeResponse(302, {"location": "https://example.org/final"}, is_redirect=True,
                                       next_url="https://example.org/final")
        final_resp = _FakeResponse(200, {"content-security-policy": "default-src 'self'"})
        fake = _FakeAsyncClient(responses=[redirect_resp, final_resp])
        monkeypatch.setattr(checker.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(checker.auto_probe_target("https://example.com/redirect-me"))

        assert result.get("csp") is True
        assert fake.calls == ["https://example.com/redirect-me", "https://example.org/final"]

    def test_excessive_redirects_are_refused(self, monkeypatch):
        loop_resp = _FakeResponse(302, {"location": "https://example.com/loop"}, is_redirect=True,
                                   next_url="https://example.com/loop")
        fake = _FakeAsyncClient(responses=[loop_resp] * 10)
        monkeypatch.setattr(checker.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(checker.auto_probe_target("https://example.com/loop"))

        assert "probe_error" in result and "too many redirects" in result["probe_error"]
