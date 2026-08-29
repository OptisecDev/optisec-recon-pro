"""
Tests for Username / Social Footprint search.

Regression coverage for a confirmed production false-positive: searching a
clearly nonexistent username (xzqw9847zzzznonexistent99999) returned
"FOUND" on 13 of 50 platforms (Instagram, TikTok, Twitch, Reddit,
Pinterest, Steam, Replit, Spotify, HackTheBox, CyberChef, ...) because the
old code trusted HTTP 200 as proof of existence on every platform, even
client-rendered SPAs whose server always returns 200 regardless of whether
the profile exists.

Mirrors tests/test_darkweb_intelligence.py's conventions: a minimal fake
aiohttp.ClientSession, no real network calls.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
import pytest

import modules.osint.username_footprint as uf


FAKE_NONEXISTENT_USERNAME = "xzqw9847zzzznonexistent99999"


def _run(coro):
    return asyncio.run(coro)


class _FakeResponse:
    def __init__(self, status=200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeSession:
    """Every GET returns the same status, simulating a platform (or every
    platform) answering 200 regardless of what username is requested."""

    def __init__(self, status=200):
        self._status = status

    def get(self, url, **kwargs):
        return _FakeResponse(self._status)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _patch_all_200(monkeypatch):
    monkeypatch.setattr(uf.aiohttp, "ClientSession", lambda *a, **kw: _FakeSession(200))


class TestPlatformList:
    def test_no_duplicate_platform_names(self):
        names = [name for name, _, _ in uf.PLATFORMS]
        assert len(names) == len(set(names))

    def test_every_platform_has_username_placeholder_or_is_unverified(self):
        """A platform URL that doesn't even scope by username (like the old,
        removed CyberChef entry, a static tool page unrelated to per-user
        profiles) can never provide a real existence signal — every entry
        must template on {u}."""
        for name, url_tpl, _mode in uf.PLATFORMS:
            assert "{u}" in url_tpl, f"{name} URL has no username placeholder"

    def test_cyberchef_removed(self):
        assert "CyberChef" not in [name for name, _, _ in uf.PLATFORMS]

    def test_every_unverified_platform_has_a_reason(self):
        unverified_names = {name for name, _, mode in uf.PLATFORMS if mode == "unverified"}
        assert unverified_names, "expected at least one unverified platform"
        for name in unverified_names:
            assert name in uf._UNVERIFIED_REASONS

    def test_known_spa_platforms_are_unverified(self):
        """These were named explicitly in the confirmed production false
        positive report — status-code-based detection is unreliable for
        all of them because they always return HTTP 200."""
        by_name = {name: mode for name, _, mode in uf.PLATFORMS}
        for platform in ("Instagram", "TikTok", "Twitch", "Reddit", "Pinterest",
                          "Steam", "Replit", "Spotify", "HackTheBox"):
            assert by_name[platform] == "unverified", platform


class TestCheckPlatform:
    def test_unverified_mode_never_hits_the_network(self, monkeypatch):
        def _boom(*a, **kw):
            raise AssertionError("unverified platforms must not make HTTP requests")
        monkeypatch.setattr(uf.aiohttp, "ClientSession", _boom)

        session = None  # never touched
        result = _run(uf._check_platform(session, "Instagram",
                                          "https://www.instagram.com/{u}/",
                                          "unverified", FAKE_NONEXISTENT_USERNAME))
        assert result["exists"] is None
        assert result["verified"] is False
        assert "reason" in result

    def test_status_mode_200_means_exists(self):
        session = _FakeSession(200)
        result = _run(uf._check_platform(session, "GitHub", "https://github.com/{u}",
                                          "status", FAKE_NONEXISTENT_USERNAME))
        assert result["exists"] is True
        assert result["verified"] is True

    def test_status_mode_404_means_not_found(self):
        session = _FakeSession(404)
        result = _run(uf._check_platform(session, "GitHub", "https://github.com/{u}",
                                          "status", FAKE_NONEXISTENT_USERNAME))
        assert result["exists"] is False
        assert result["verified"] is True


class TestSearchUsername:
    def test_nonexistent_username_all_platforms_return_200(self, monkeypatch):
        """Regression: simulates the exact confirmed production bug — every
        platform's server answers 200 for a clearly nonexistent username.
        No known SPA platform should end up in `found` with full
        confidence; each must be excluded and reported as unverified
        instead."""
        _patch_all_200(monkeypatch)
        result = _run(uf.search_username(FAKE_NONEXISTENT_USERNAME))

        found_names = {p["platform"] for p in result["found"]}
        unverified_names = {p["platform"] for p in result["unverified"]}

        for platform in ("Instagram", "TikTok", "Reddit"):
            assert platform not in found_names
            assert platform in unverified_names

    def test_unverified_platforms_excluded_from_risk_score(self, monkeypatch):
        _patch_all_200(monkeypatch)
        result = _run(uf.search_username(FAKE_NONEXISTENT_USERNAME))
        expected_score = min(len(result["found"]) * 8, 95)
        assert result["risk_score"] == expected_score
        # Every status-mode platform reported 200 in this mock, so they are
        # legitimately "found" — but the unverified ones must not have
        # inflated the count.
        verifiable_count = sum(1 for _, _, m in uf.PLATFORMS if m == "status")
        assert len(result["found"]) == verifiable_count

    def test_unverified_note_present_when_any_unverified(self, monkeypatch):
        _patch_all_200(monkeypatch)
        result = _run(uf.search_username(FAKE_NONEXISTENT_USERNAME))
        assert result["unverified_count"] > 0
        assert result["unverified_note"]

    def test_all_not_found(self, monkeypatch):
        monkeypatch.setattr(uf.aiohttp, "ClientSession", lambda *a, **kw: _FakeSession(404))
        result = _run(uf.search_username(FAKE_NONEXISTENT_USERNAME))
        assert result["found"] == []
        assert result["risk_score"] == 0
        assert result["risk_label"] == "LOW"
        # unverified platforms are still reported as unverified, never as not-found
        assert result["unverified_count"] > 0

    def test_result_shape(self, monkeypatch):
        _patch_all_200(monkeypatch)
        result = _run(uf.search_username(FAKE_NONEXISTENT_USERNAME))
        for key in ("username", "found", "not_found_count", "unverified", "unverified_count",
                    "platforms_checked", "platforms_verifiable", "risk_score", "risk_label",
                    "variations"):
            assert key in result
        assert result["platforms_checked"] == len(uf.PLATFORMS)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
