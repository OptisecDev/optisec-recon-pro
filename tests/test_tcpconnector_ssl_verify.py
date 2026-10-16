"""
The connector built by modules.osint.phone_social.phone_social_lookup must
verify TLS certificates. Its session carries the HIBP key (header) and the
NumVerify / AbstractAPI keys (query string).

The per-request ssl=True in _check_hibp/_check_numverify/_check_abstractapi
is not enough on its own: aiohttp's TCPConnector._get_ssl_context() treats a
request's ssl=True as "use the connector default", so a connector built with
ssl=False silently downgraded every one of those requests to an unverified
context. These tests capture the connector exactly as phone_social_lookup
builds it and check the context aiohttp would really use.

No real network call is made: ClientSession is replaced with a fake whose
get() records calls. Fake session helpers follow
test_numverify_https_and_no_leak.py.
"""

import asyncio
import os
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
import pytest

import modules.osint.phone_social as phone_social

FAKE_KEYS = {
    "HIBP_API_KEY": "test-hibp-key-not-real",
    "NUMVERIFY_API_KEY": "test-numverify-key-not-real",
    "ABSTRACTAPI_PHONE_KEY": "test-abstractapi-key-not-real",
}
NUMBER = "+9647701234567"
REAL_TCP_CONNECTOR = aiohttp.TCPConnector


def _run(coro):
    return asyncio.run(coro)


class _FakeResponse:
    status = 200

    async def json(self):
        return {}


class _FakeCtx:
    async def __aenter__(self):
        return _FakeResponse()

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    """Stands in for aiohttp.ClientSession; records the connector and calls."""

    instances: list = []

    def __init__(self, *args, **kwargs):
        self.connector = kwargs.get("connector")
        self.calls: list[tuple[str, dict]] = []
        _FakeSession.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        if self.connector is not None:
            await self.connector.close()
        return False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _FakeCtx()


class _FakeReq:
    """Minimal ClientRequest stand-in for TCPConnector._get_ssl_context()."""

    def __init__(self, ssl_arg):
        self.ssl = ssl_arg

    def is_ssl(self):
        return True


@pytest.fixture
def captured(monkeypatch):
    for name, value in FAKE_KEYS.items():
        monkeypatch.setenv(name, value)

    connector_kwargs: list[dict] = []
    connectors: list = []

    def spy_connector(*args, **kwargs):
        connector_kwargs.append(kwargs)
        conn = REAL_TCP_CONNECTOR(*args, **kwargs)
        connectors.append(conn)
        return conn

    _FakeSession.instances = []
    monkeypatch.setattr(phone_social.aiohttp, "TCPConnector", spy_connector)
    monkeypatch.setattr(phone_social.aiohttp, "ClientSession", _FakeSession)

    ssl_contexts: list = []

    async def run_and_resolve():
        await phone_social.phone_social_lookup(NUMBER)
        session = _FakeSession.instances[0]
        # Resolve the context aiohttp would use for each recorded request.
        for _url, kwargs in session.calls:
            ssl_contexts.append(connectors[0]._get_ssl_context(_FakeReq(kwargs.get("ssl", True))))

    _run(run_and_resolve())
    return connector_kwargs, _FakeSession.instances, ssl_contexts


class TestPhoneSocialConnectorVerifiesTls:
    def test_connector_does_not_disable_ssl(self, captured):
        connector_kwargs, _sessions, _ctxs = captured
        one_connector = len(connector_kwargs) == 1
        assert one_connector
        disables_ssl = connector_kwargs[0].get("ssl", True) is False
        assert not disables_ssl

    def test_session_uses_that_connector(self, captured):
        _kwargs, sessions, _ctxs = captured
        one_session = len(sessions) == 1
        assert one_session
        has_connector = isinstance(sessions[0].connector, REAL_TCP_CONNECTOR)
        assert has_connector

    def test_key_bearing_requests_are_https(self, captured):
        _kwargs, sessions, _ctxs = captured
        urls = [url for url, _ in sessions[0].calls]
        made_calls = len(urls) >= 3
        assert made_calls
        all_https = all(u.startswith("https://") for u in urls)
        assert all_https

    def test_effective_ssl_context_verifies_certificates(self, captured):
        _kwargs, _sessions, ssl_contexts = captured
        made_calls = len(ssl_contexts) >= 3
        assert made_calls
        all_verify = all(
            isinstance(c, ssl.SSLContext)
            and c.verify_mode == ssl.CERT_REQUIRED
            and c.check_hostname
            for c in ssl_contexts
        )
        assert all_verify


def test_aiohttp_request_ssl_true_does_not_override_connector_ssl_false():
    # Documents why the per-request ssl=True was not sufficient on its own.
    async def resolve():
        conn = aiohttp.TCPConnector(ssl=False)
        try:
            return conn._get_ssl_context(_FakeReq(True))
        finally:
            await conn.close()

    ctx = _run(resolve())
    verifies = ctx.verify_mode == ssl.CERT_REQUIRED
    assert not verifies
