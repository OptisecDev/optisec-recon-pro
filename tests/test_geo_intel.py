"""
Tests for Geographic Intelligence (modules/osint/geo_intel.py).

Regression coverage for a confirmed bug: _query_ip_api() read d.get("lng")
but ip-api.com's real field is "lon" — so `lon` was always None and the
generated OpenStreetMap link was broken (&mlon=None&zoom=12).

Mirrors tests/test_hibp_integration.py's conventions: plain pytest, async
functions driven via asyncio.run(), httpx.AsyncClient monkeypatched, no
real network calls.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import pytest

import modules.osint.geo_intel as geo


def _run(coro):
    return asyncio.run(coro)


class _FakeHttpResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=self)

    def json(self):
        return self._json_data


class _FakeAsyncClient:
    def __init__(self, response, **kw):
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        return self._response


# Real ip-api.com response shape for 8.8.8.8 (fields=66846719) — note the
# real field is "lon", not "lng".
_IP_API_RESPONSE = {
    "status": "success",
    "country": "United States",
    "countryCode": "US",
    "regionName": "Virginia",
    "city": "Ashburn",
    "lat": 39.03,
    "lon": -77.5,
    "timezone": "America/New_York",
    "isp": "Google LLC",
    "org": "Google Public DNS",
    "as": "AS15169 Google LLC",
    "proxy": False,
    "hosting": True,
    "mobile": False,
    "reverse": "dns.google",
}


class TestQueryIpApi:
    def test_reads_lon_field_not_lng(self, monkeypatch):
        fake = _FakeAsyncClient(_FakeHttpResponse(200, _IP_API_RESPONSE))
        monkeypatch.setattr(geo.httpx, "AsyncClient", lambda *a, **kw: fake)
        result = _run(geo._query_ip_api("8.8.8.8"))
        assert result["lon"] == -77.5
        assert result["lat"] == 39.03

    def test_lon_is_never_none_when_upstream_provides_it(self, monkeypatch):
        fake = _FakeAsyncClient(_FakeHttpResponse(200, _IP_API_RESPONSE))
        monkeypatch.setattr(geo.httpx, "AsyncClient", lambda *a, **kw: fake)
        result = _run(geo._query_ip_api("8.8.8.8"))
        assert result["lon"] is not None
        assert isinstance(result["lon"], (int, float))

    def test_failed_lookup_returns_error(self, monkeypatch):
        fake = _FakeAsyncClient(_FakeHttpResponse(200, {"status": "fail", "message": "invalid query"}))
        monkeypatch.setattr(geo.httpx, "AsyncClient", lambda *a, **kw: fake)
        result = _run(geo._query_ip_api("not-an-ip"))
        assert result["error"] == "invalid query"


class TestGeolocateIpMapsUrl:
    def test_maps_url_has_real_longitude_not_none(self, monkeypatch):
        monkeypatch.setattr(geo, "_resolve_to_ip", lambda target: "8.8.8.8")
        fake = _FakeAsyncClient(_FakeHttpResponse(200, _IP_API_RESPONSE))
        monkeypatch.setattr(geo.httpx, "AsyncClient", lambda *a, **kw: fake)
        result = _run(geo.geolocate_ip("8.8.8.8"))
        assert "mlon=None" not in result["maps_url"]
        assert "mlon=-77.5" in result["maps_url"]
        assert "mlat=39.03" in result["maps_url"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
