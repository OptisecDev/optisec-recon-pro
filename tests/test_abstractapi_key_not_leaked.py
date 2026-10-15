"""
The AbstractAPI phone-validation key must never appear in the error text
returned by modules.osint.phone_social._check_abstractapi (that dict is sent
back to the browser via /api/osint/phone-social) or in logs.

AbstractAPI only documents query-string auth (api_key=...), so the request URL
carries the key. aiohttp's ClientResponseError -- and its ContentTypeError
subclass raised by resp.json() on a non-JSON error page -- embeds that full
URL in str(e). These tests build such errors around a fake key and check it
does not leak.
"""

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
import pytest
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

import modules.osint.phone_social as phone_social

KEY = "test-abstract-key-not-real"
E164 = "+9647701234567"


def _run(coro):
    return asyncio.run(coro)


def _request_info(url: str) -> aiohttp.RequestInfo:
    return aiohttp.RequestInfo(URL(url), "GET", CIMultiDictProxy(CIMultiDict()), URL(url))


class _FakeResponse:
    def __init__(self, url: str, json_exc: Exception | None = None, payload: dict | None = None):
        self._url = url
        self._json_exc = json_exc
        self._payload = payload or {}

    async def json(self):
        if self._json_exc is not None:
            raise self._json_exc
        return self._payload


class _FakeCtx:
    def __init__(self, enter_exc=None, response=None):
        self._enter_exc = enter_exc
        self._response = response

    async def __aenter__(self):
        if self._enter_exc is not None:
            raise self._enter_exc
        return self._response

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    """Stands in for aiohttp.ClientSession; records the URL/kwargs it was given."""

    def __init__(self, make_ctx):
        self._make_ctx = make_ctx
        self.calls: list[tuple[str, dict]] = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self._make_ctx(url)


@pytest.fixture(autouse=True)
def _fake_key(monkeypatch):
    monkeypatch.setenv("ABSTRACTAPI_PHONE_KEY", KEY)


def _assert_no_leak(result: dict, caplog):
    text = repr(result) + "\n" + caplog.text
    leaked = KEY in text
    assert not leaked
    # The old code truncated to 100 chars, which can cut the key mid-way and
    # still expose a prefix -- so also reject any partial key / query param.
    partially_leaked = KEY[:8] in text or "api_key=" in text
    assert not partially_leaked


class TestAbstractApiKeyNotLeaked:
    def test_fake_error_really_contains_key(self):
        # Sanity: the raw aiohttp error text does embed the key, so the
        # assertions below are actually exercising the redaction.
        url = f"https://phonevalidation.abstractapi.com/v1/?api_key={KEY}&phone=1"
        exc = aiohttp.ClientResponseError(_request_info(url), (), status=401, message="Unauthorized")
        leaked = KEY in str(exc)
        assert leaked

    def test_http_status_error_does_not_leak_key(self, caplog):
        def make_ctx(url):
            return _FakeCtx(enter_exc=aiohttp.ClientResponseError(
                _request_info(url), (), status=401, message="Unauthorized"))

        session = _FakeSession(make_ctx)
        with caplog.at_level(logging.DEBUG):
            result = _run(phone_social._check_abstractapi(session, E164))

        assert result["checked"] is False
        assert result["service"] == "AbstractAPI Phone"
        assert "401" in result["error"]
        _assert_no_leak(result, caplog)

    def test_content_type_error_from_json_does_not_leak_key(self, caplog):
        def make_ctx(url):
            exc = aiohttp.ContentTypeError(
                _request_info(url), (), status=200,
                message="Attempt to decode JSON with unexpected mimetype: text/html")
            return _FakeCtx(response=_FakeResponse(url, json_exc=exc))

        session = _FakeSession(make_ctx)
        with caplog.at_level(logging.DEBUG):
            result = _run(phone_social._check_abstractapi(session, E164))

        assert result["checked"] is False
        _assert_no_leak(result, caplog)

    def test_other_exception_with_url_in_message_does_not_leak_key(self, caplog):
        def make_ctx(url):
            return _FakeCtx(enter_exc=aiohttp.InvalidURL(url))

        session = _FakeSession(make_ctx)
        with caplog.at_level(logging.DEBUG):
            result = _run(phone_social._check_abstractapi(session, E164))

        assert result["checked"] is False
        _assert_no_leak(result, caplog)

    def test_successful_call_unchanged(self):
        payload = {"valid": True, "phone": "9647701234567", "format": {}, "country": {},
                   "type": "mobile", "carrier": "Zain Iraq"}

        def make_ctx(url):
            return _FakeCtx(response=_FakeResponse(url, payload=payload))

        session = _FakeSession(make_ctx)
        result = _run(phone_social._check_abstractapi(session, E164))

        assert result["checked"] is True
        assert result["valid"] is True
        assert result["carrier"] == "Zain Iraq"
        # Provider documents query-string auth only, so the key still travels
        # in the URL (not a header) -- transport is intentionally unchanged.
        url, kwargs = session.calls[0]
        in_url = f"api_key={KEY}" in url
        assert in_url
        assert "headers" not in kwargs
