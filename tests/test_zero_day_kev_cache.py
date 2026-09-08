"""
Tests for modules/ai_advanced/zero_day.py's CISA KEV feed caching.

_fetch_cisa_kev() (called on every /api/zero-day/predict) and
trending_threats() each independently re-fetched the full CISA KEV feed
over the network on every single call, with no caching -- unlike
modules/threat_intel/otx_feed.py's established _CACHE/_CACHE_TTL pattern,
which this now reuses via a shared _fetch_kev_feed() helper. Verifies the
network is only hit once across multiple calls within the TTL, and that
both callers still see correct data.

Same _FakeAsyncClient convention as tests/test_hibp_integration.py: no real
network calls, httpx.AsyncClient is monkeypatched.
"""

import asyncio

import httpx
import pytest

import modules.ai_advanced.zero_day as zero_day


def _run(coro):
    return asyncio.run(coro)


class _FakeHttpResponse:
    def __init__(self, json_data):
        self._json_data = json_data

    def raise_for_status(self):
        pass

    def json(self):
        return self._json_data


class _FakeAsyncClient:
    def __init__(self, json_data, **kw):
        self._json_data = json_data
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        self.calls += 1
        return _FakeHttpResponse(self._json_data)


_KEV_PAYLOAD = {
    "vulnerabilities": [
        {"cveID": "CVE-2024-0001", "product": "nginx", "vendorProject": "F5",
         "dateAdded": "2026-08-01", "requiredAction": "Patch", "shortDescription": "x"},
        {"cveID": "CVE-2024-0002", "product": "Exchange", "vendorProject": "Microsoft",
         "dateAdded": "2026-09-01", "requiredAction": "Patch", "shortDescription": "y"},
    ]
}


@pytest.fixture(autouse=True)
def _clear_kev_cache():
    zero_day._KEV_CACHE["data"] = None
    zero_day._KEV_CACHE["ts"] = 0.0
    yield
    zero_day._KEV_CACHE["data"] = None
    zero_day._KEV_CACHE["ts"] = 0.0


def test_second_call_within_ttl_does_not_hit_network_again(monkeypatch):
    fake = _FakeAsyncClient(json_data=_KEV_PAYLOAD)
    monkeypatch.setattr(zero_day.httpx, "AsyncClient", lambda *a, **kw: fake)

    r1 = _run(zero_day._fetch_cisa_kev("nginx"))
    r2 = _run(zero_day._fetch_cisa_kev("nginx"))

    assert fake.calls == 1
    assert r1["found"] is True
    assert r2["found"] is True


def test_trending_threats_shares_the_same_cache_as_fetch_cisa_kev(monkeypatch):
    fake = _FakeAsyncClient(json_data=_KEV_PAYLOAD)
    monkeypatch.setattr(zero_day.httpx, "AsyncClient", lambda *a, **kw: fake)

    _run(zero_day._fetch_cisa_kev("nginx"))
    result = _run(zero_day.trending_threats())

    assert fake.calls == 1  # trending_threats() reused the cache _fetch_cisa_kev() populated
    assert result["total_kev"] == 2


def test_cache_expires_after_ttl(monkeypatch):
    fake = _FakeAsyncClient(json_data=_KEV_PAYLOAD)
    monkeypatch.setattr(zero_day.httpx, "AsyncClient", lambda *a, **kw: fake)

    _run(zero_day._fetch_cisa_kev("nginx"))
    # Simulate the cache having gone stale.
    zero_day._KEV_CACHE["ts"] -= zero_day._KEV_CACHE_TTL + 1
    _run(zero_day._fetch_cisa_kev("nginx"))

    assert fake.calls == 2


def test_fetch_failure_is_not_cached(monkeypatch):
    class _BoomClient:
        def __init__(self, **kw):
            self.calls = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, **kw):
            self.calls += 1
            raise httpx.ConnectError("boom")

    boom = _BoomClient()
    monkeypatch.setattr(zero_day.httpx, "AsyncClient", lambda *a, **kw: boom)

    r1 = _run(zero_day._fetch_cisa_kev("nginx"))
    r2 = _run(zero_day._fetch_cisa_kev("nginx"))

    assert r1["found"] is False and "error" in r1
    assert r2["found"] is False and "error" in r2
    assert boom.calls == 2  # a failed fetch must not poison the cache with no data
