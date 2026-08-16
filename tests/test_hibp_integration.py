"""Tests for the Eternal Core HIBP integration: app/services/external/hibp_service.py
and app/services/recon/recon_engine.scan_email.

Mirrors tests/test_cve_pipeline.py's conventions: plain pytest, async functions
driven via asyncio.run(), monkeypatch for isolation, no real network calls
(httpx.AsyncClient is monkeypatched, never actually invoked).
"""
import asyncio

import httpx
import pytest

import app.services.external.hibp_service as hibp_service
import app.services.recon.recon_engine as recon_engine


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
    """Returns `responses` in order (one per .get() call); repeats the last
    one if more calls happen than responses provided. `exc`, if set, is
    raised on the very first call instead of returning a response."""

    def __init__(self, responses=None, exc=None, **kw):
        self._responses = list(responses or [])
        self._exc = exc
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None, params=None):
        self.calls += 1
        if self._exc:
            raise self._exc
        if self._responses:
            return self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]
        raise AssertionError("no fake response configured")


def _breach_payload():
    return [
        {
            "Name": "LinkedIn",
            "Title": "LinkedIn",
            "BreachDate": "2016-05-05",
            "Description": "LinkedIn breach description.",
        },
        {
            "Name": "Adobe",
            "Title": "Adobe",
            "BreachDate": "2013-10-04",
            "Description": "Adobe breach description.",
        },
    ]


class TestCheckHibp:
    def test_success_returns_breaches(self, monkeypatch):
        fake = _FakeAsyncClient(responses=[_FakeHttpResponse(200, _breach_payload())])
        monkeypatch.setattr(hibp_service.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(hibp_service.check_hibp("test@example.com"))

        assert result["message"] is None
        assert len(result["breaches"]) == 2
        assert result["breaches"][0]["Name"] == "LinkedIn"

    def test_404_returns_empty_with_message(self, monkeypatch):
        fake = _FakeAsyncClient(responses=[_FakeHttpResponse(404)])
        monkeypatch.setattr(hibp_service.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(hibp_service.check_hibp("clean@example.com"))

        assert result["breaches"] == []
        assert result["message"]

    def test_429_retries_once_then_succeeds(self, monkeypatch):
        fake = _FakeAsyncClient(
            responses=[_FakeHttpResponse(429), _FakeHttpResponse(200, _breach_payload())]
        )
        monkeypatch.setattr(hibp_service.httpx, "AsyncClient", lambda *a, **kw: fake)
        _real_sleep = asyncio.sleep
        monkeypatch.setattr(hibp_service.asyncio, "sleep", lambda *_: _real_sleep(0))

        result = _run(hibp_service.check_hibp("test@example.com"))

        assert fake.calls == 2
        assert len(result["breaches"]) == 2

    def test_server_error_raises_http_error(self, monkeypatch):
        fake = _FakeAsyncClient(responses=[_FakeHttpResponse(500)])
        monkeypatch.setattr(hibp_service.httpx, "AsyncClient", lambda *a, **kw: fake)

        with pytest.raises(httpx.HTTPError):
            _run(hibp_service.check_hibp("test@example.com"))


class TestScanEmail:
    def test_hibp_success(self, monkeypatch):
        """scan_email returns real HIBP data with source='HIBP' when the API succeeds."""
        fake = _FakeAsyncClient(responses=[_FakeHttpResponse(200, _breach_payload())])
        monkeypatch.setattr(hibp_service.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(recon_engine.scan_email("test@example.com"))

        assert result["source"] == "HIBP"
        assert result["mock"] is False
        assert result["email"] == "test@example.com"
        assert [b["source"] for b in result["breaches"]] == ["LinkedIn", "Adobe"]
        assert result["breaches"][0]["year"] == "2016"

    def test_hibp_fallback(self, monkeypatch):
        """scan_email falls back to mock data with source='mock_fallback' when HIBP
        is unreachable (network failure)."""
        fake = _FakeAsyncClient(exc=httpx.ConnectError("no network"))
        monkeypatch.setattr(hibp_service.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(recon_engine.scan_email("test@example.com"))

        assert result["source"] == "mock_fallback"
        assert result["mock"] is True
        assert len(result["breaches"]) > 0

    def test_hibp_no_breaches_found(self, monkeypatch):
        fake = _FakeAsyncClient(responses=[_FakeHttpResponse(404)])
        monkeypatch.setattr(hibp_service.httpx, "AsyncClient", lambda *a, **kw: fake)

        result = _run(recon_engine.scan_email("clean@example.com"))

        assert result["source"] == "HIBP"
        assert result["breaches"] == []
        assert result["message"]
