"""
Tests for modules/firewall/ngfw_v2.py::_geo_lookup — replaced a hardcoded
18-entry IP-range table (anything outside those 18 ranges fell through to
"Unknown") with a real lookup via modules.osint.geo_intel (the same
ip-api.com/ipinfo.io module Threat Map uses), backed by a TTL disk cache
and a sliding-window call limiter so DPI traffic bursts can't blow past
ip-api.com's free-tier rate limit.

No real network calls here — geolocate_ip() is monkeypatched throughout,
same convention as tests/test_geo_intel.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.firewall.ngfw_v2 as ngfw


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(ngfw, "GEO_CACHE_FILE", tmp_path / "ngfw_geo_cache.json")
    # Fresh rate-limit window per test — the real deque is module-level
    # and would otherwise leak call counts across tests.
    monkeypatch.setattr(ngfw, "_geo_call_times", __import__("collections").deque())


class _Calls:
    """Records every geolocate_ip() call and returns a canned response."""
    def __init__(self, response=None, raises=None):
        self.ips = []
        self.response = response
        self.raises = raises

    async def __call__(self, ip):
        self.ips.append(ip)
        if self.raises:
            raise self.raises
        return self.response


# ── Private/loopback/link-local — classified locally, never hits the network ──

class TestPrivateIpsNeverCallProvider:
    def test_rfc1918_192_168_is_lan_without_calling_provider(self, monkeypatch):
        calls = _Calls()
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)
        geo = _run(ngfw._geo_lookup("192.168.1.100"))
        assert geo == {"country": "Internal Network", "country_code": "LAN", "is_high_risk": False, "risk_reason": ""}
        assert calls.ips == []

    def test_rfc1918_10_is_lan_without_calling_provider(self, monkeypatch):
        calls = _Calls()
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)
        geo = _run(ngfw._geo_lookup("10.0.0.50"))
        assert geo["country_code"] == "LAN"
        assert calls.ips == []

    def test_loopback_is_lan_without_calling_provider(self, monkeypatch):
        calls = _Calls()
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)
        geo = _run(ngfw._geo_lookup("127.0.0.1"))
        assert geo["country_code"] == "LAN"
        assert calls.ips == []


# ── Public IP — real provider result, never a guessed one ──────────────────

class TestPublicIpUsesRealProvider:
    def test_successful_lookup_returns_real_country(self, monkeypatch):
        calls = _Calls(response={"country": "Germany", "country_code": "DE"})
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)
        geo = _run(ngfw._geo_lookup("85.1.2.3"))
        assert geo["country"] == "Germany"
        assert geo["country_code"] == "DE"
        assert geo["is_high_risk"] is False
        assert calls.ips == ["85.1.2.3"]

    def test_high_risk_country_code_is_flagged(self, monkeypatch):
        calls = _Calls(response={"country": "Russia", "country_code": "RU"})
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)
        geo = _run(ngfw._geo_lookup("5.1.2.3"))
        assert geo["country_code"] == "RU"
        assert geo["is_high_risk"] is True
        assert geo["risk_reason"]

    def test_provider_error_response_falls_back_to_honest_unknown(self, monkeypatch):
        calls = _Calls(response={"error": "All geolocation providers failed"})
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)
        geo = _run(ngfw._geo_lookup("93.0.113.9"))
        assert geo == {"country": "Unknown", "country_code": "??", "is_high_risk": False, "risk_reason": ""}

    def test_provider_exception_falls_back_to_honest_unknown_not_a_guess(self, monkeypatch):
        calls = _Calls(raises=RuntimeError("network down"))
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)
        geo = _run(ngfw._geo_lookup("93.0.113.10"))
        assert geo["country"] == "Unknown"
        assert geo["country_code"] == "??"


# ── Cache — a resolved IP isn't re-queried within the TTL ───────────────────

class TestGeoCache:
    def test_second_lookup_within_ttl_does_not_call_provider_again(self, monkeypatch):
        calls = _Calls(response={"country": "Japan", "country_code": "JP"})
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)

        first = _run(ngfw._geo_lookup("93.0.113.20"))
        second = _run(ngfw._geo_lookup("93.0.113.20"))

        assert first == second
        assert calls.ips == ["93.0.113.20"]  # only called once

    def test_expired_cache_entry_is_requeried(self, monkeypatch):
        calls = _Calls(response={"country": "Brazil", "country_code": "BR"})
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)
        monkeypatch.setattr(ngfw, "GEO_CACHE_TTL", 0)  # instantly stale

        _run(ngfw._geo_lookup("93.0.113.30"))
        _run(ngfw._geo_lookup("93.0.113.30"))

        assert calls.ips == ["93.0.113.30", "93.0.113.30"]

    def test_failed_lookup_is_not_cached(self, monkeypatch):
        """An "Unknown" from a provider failure must not be cached as a
        permanent answer — a later retry should hit the provider again."""
        calls = _Calls(raises=RuntimeError("down"))
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)

        _run(ngfw._geo_lookup("93.0.113.40"))
        _run(ngfw._geo_lookup("93.0.113.40"))

        assert calls.ips == ["93.0.113.40", "93.0.113.40"]


# ── Rate limiter — a burst can't blow through the provider's free-tier cap ──

class TestRateLimiter:
    def test_calls_beyond_the_window_cap_return_unknown_without_calling_provider(self, monkeypatch):
        calls = _Calls(response={"country": "France", "country_code": "FR"})
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)
        monkeypatch.setattr(ngfw, "_GEO_RATE_MAX", 3)

        results = [_run(ngfw._geo_lookup(f"93.51.100.{i}")) for i in range(5)]

        assert len(calls.ips) == 3  # only the first 3 distinct IPs hit the provider
        assert results[3]["country_code"] == "??"
        assert results[4]["country_code"] == "??"


# ── deep_inspect() end-to-end: the geo field is the real lookup result ──────

class TestDeepInspectUsesRealGeo:
    def test_deep_inspect_geo_field_matches_real_lookup(self, monkeypatch, tmp_path):
        monkeypatch.setattr(ngfw, "DATA_FILE", tmp_path / "ngfw_v2_state.json")
        calls = _Calls(response={"country": "Nigeria", "country_code": "NG"})
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)

        result = _run(ngfw.deep_inspect(
            method="GET", path="/", headers={}, body="", src_ip="41.1.2.3",
        ))

        assert result["geo"]["country"] == "Nigeria"
        assert result["geo"]["country_code"] == "NG"
        assert calls.ips == ["41.1.2.3"]

    def test_deep_inspect_geo_for_private_ip_is_lan_not_fabricated_country(self, monkeypatch, tmp_path):
        monkeypatch.setattr(ngfw, "DATA_FILE", tmp_path / "ngfw_v2_state.json")
        calls = _Calls()
        monkeypatch.setattr(ngfw, "geolocate_ip", calls)

        result = _run(ngfw.deep_inspect(
            method="GET", path="/", headers={}, body="", src_ip="192.168.0.5",
        ))

        assert result["geo"]["country_code"] == "LAN"
        assert calls.ips == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
