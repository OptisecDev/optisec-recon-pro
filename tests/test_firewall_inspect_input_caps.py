"""
Tests for input-length caps on POST /firewall/api/inspect
(web/routers/firewall.py).

inspect_request() regex-matches path/body/headers against 81 WAF
signatures with no length limit of its own. No ReDoS was found in the
signature set (manually reviewed -- no nested-unbounded-quantifier
shapes; most patterns already use bounded {0,N} quantifiers), but an
unbounded body/path/header value still means unbounded per-request
regex work. Capped for resource hygiene, same shape as
web/routers/ai_security.py's _MAX_ANALYZE_*_CHARS.

Follows tests/test_quantum_encapsulate_router.py's convention: call the
route handler function directly with a fake Request.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.models import User
import web.routers.firewall as firewall_router


def _run(coro):
    return asyncio.run(coro)


def _fake_user() -> User:
    return User(id=1, username="tester", email="tester@example.com",
                password_hash="x", role="analyst", subscription_tier="pro")


class _FakeRequest:
    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


def test_oversized_path_is_capped(monkeypatch):
    captured = {}

    def fake_inspect(**kwargs):
        captured.update(kwargs)
        return {"threats": [], "action": "allow"}

    monkeypatch.setattr("modules.firewall.ai_firewall.inspect_request", fake_inspect)

    huge_path = "/" + "a" * 50_000
    _run(firewall_router.inspect_request_api(
        _FakeRequest({"path": huge_path}), user=_fake_user(),
    ))

    assert len(captured["path"]) == firewall_router._MAX_INSPECT_PATH_LEN


def test_oversized_body_is_capped(monkeypatch):
    captured = {}

    def fake_inspect(**kwargs):
        captured.update(kwargs)
        return {"threats": [], "action": "allow"}

    monkeypatch.setattr("modules.firewall.ai_firewall.inspect_request", fake_inspect)

    huge_body = "x" * 500_000
    _run(firewall_router.inspect_request_api(
        _FakeRequest({"request_body": huge_body}), user=_fake_user(),
    ))

    assert len(captured["body"]) == firewall_router._MAX_INSPECT_BODY_LEN


def test_oversized_header_value_is_capped(monkeypatch):
    captured = {}

    def fake_inspect(**kwargs):
        captured.update(kwargs)
        return {"threats": [], "action": "allow"}

    monkeypatch.setattr("modules.firewall.ai_firewall.inspect_request", fake_inspect)

    huge_header = "y" * 100_000
    _run(firewall_router.inspect_request_api(
        _FakeRequest({"headers": {"X-Custom": huge_header}}), user=_fake_user(),
    ))

    assert len(captured["headers"]["X-Custom"]) == firewall_router._MAX_INSPECT_HEADER_VALUE_LEN


def test_ordinary_inspect_still_works(monkeypatch):
    def fake_inspect(**kwargs):
        return {"threats": [], "action": "allow", "kwargs": kwargs}

    monkeypatch.setattr("modules.firewall.ai_firewall.inspect_request", fake_inspect)

    result = _run(firewall_router.inspect_request_api(
        _FakeRequest({"method": "GET", "path": "/login", "request_body": "", "ip": "1.2.3.4"}),
        user=_fake_user(),
    ))

    assert result["action"] == "allow"
