"""
Tests for the AlienVault OTX live threat feed integration
(modules/threat_intel/otx_feed.py).

All HTTP calls are mocked via monkeypatch on `otx_feed.requests.Session` —
these tests never hit the real OTX API. Mirrors tests/test_darkweb_intelligence.py's
fake-response convention, adapted for the synchronous `requests` library
used here instead of aiohttp.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.threat_intel.otx_feed as otx_feed


class _FakeResponse:
    def __init__(self, json_data):
        self._json_data = json_data

    def raise_for_status(self):
        pass

    def json(self):
        return self._json_data


class _FakeSession:
    """Serves one page of pulses (from `pages`) per .get() call, then an
    empty page with no "next" key to stop pagination. `headers` is a plain
    dict so otx_feed._session()'s `s.headers.update(...)` call works as-is."""

    def __init__(self, pages):
        self._pages = list(pages)
        self.headers = {}

    def get(self, url, params=None, timeout=None):
        if self._pages:
            return _FakeResponse(self._pages.pop(0))
        return _FakeResponse({"results": [], "next": None})


def _patch_session(monkeypatch, pages):
    fake = _FakeSession(pages)
    monkeypatch.setattr(otx_feed.requests, "Session", lambda: fake)
    return fake


def _pulse(**overrides):
    base = {
        "name": "Test Pulse",
        "tlp": "white",
        "malware_families": [],
        "created": "2024-01-01T00:00:00",
        "modified": "2024-01-02T00:00:00",
        "author_name": "tester",
        "indicators": [{"type": "domain", "indicator": "evil.example", "created": "2024-01-01T00:00:00"}],
        "targeted_countries": [],
        "tags": [],
    }
    base.update(overrides)
    return base


class TestFetchOtxPulsesAdversaryFiltering:
    def test_verified_actor_name_is_kept(self, monkeypatch):
        otx_feed._CACHE.clear()
        _patch_session(monkeypatch, [{"results": [_pulse(adversary="APT28")], "next": None}])
        iocs = otx_feed.fetch_otx_pulses("fake-key", limit=10)
        assert len(iocs) == 1
        assert iocs[0]["adversary"] == "APT28"
        assert iocs[0]["unverified_adversary"] == ""

    def test_generic_phrase_is_not_a_confirmed_adversary(self, monkeypatch):
        """Regression for the documented incident: OTX's free-text
        `adversary` field returning a generic topic phrase (e.g.
        "Artificial Intelligence") must not be trusted as a confirmed
        threat actor — it should land in unverified_adversary instead, and
        must never appear in `adversary`."""
        otx_feed._CACHE.clear()
        _patch_session(monkeypatch, [{"results": [_pulse(adversary="Artificial Intelligence")], "next": None}])
        iocs = otx_feed.fetch_otx_pulses("fake-key", limit=10)
        assert len(iocs) == 1
        assert iocs[0]["adversary"] == ""
        assert iocs[0]["unverified_adversary"] == "Artificial Intelligence"

    def test_missing_adversary_leaves_both_fields_empty(self, monkeypatch):
        otx_feed._CACHE.clear()
        _patch_session(monkeypatch, [{"results": [_pulse()], "next": None}])
        iocs = otx_feed.fetch_otx_pulses("fake-key", limit=10)
        assert iocs[0]["adversary"] == ""
        assert iocs[0]["unverified_adversary"] == ""


class TestScoreIndicatorAdversaryBonus:
    def test_verified_actor_name_adds_bonus(self):
        indicator = {"type": "domain"}
        pulse = {"adversary": "APT28"}
        score = otx_feed._score_indicator(indicator, pulse)
        assert score == 70 + 8  # domain base (70) + verified-actor bonus

    def test_generic_phrase_does_not_add_bonus(self):
        """Same incident, at the scoring layer: a generic phrase in
        `adversary` must not inflate threat_score."""
        indicator = {"type": "domain"}
        pulse = {"adversary": "Artificial Intelligence"}
        score = otx_feed._score_indicator(indicator, pulse)
        assert score == 70  # domain base only, no bonus

    def test_no_adversary_no_bonus(self):
        indicator = {"type": "domain"}
        pulse = {}
        score = otx_feed._score_indicator(indicator, pulse)
        assert score == 70
