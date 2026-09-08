"""
Regression test for web/routers/quantum.py's POST /api/encapsulate.

The handler used to read `return await _enc(...) if False else _enc(...)`
-- dead leftover from an incomplete edit. The `if False` branch could
never run (encapsulate() is a plain `def`, not `async def`, so awaiting
its return value would have raised TypeError if that branch were ever
live), and the reachable branch worked correctly, so this had no runtime
effect today -- but it's exactly the kind of stale artifact that silently
breaks on the next refactor. Simplified to a single direct call.
"""

import asyncio
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.models import User
import web.routers.quantum as quantum_router


def _run(coro):
    return asyncio.run(coro)


def _fake_user() -> User:
    return User(id=1, username="tester", email="tester@example.com",
                password_hash="x", role="analyst", subscription_tier="enterprise")


class _FakeRequest:
    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


def test_encapsulate_returns_a_plain_dict_not_a_coroutine():
    pub_b64 = base64.b64encode(b"x" * 1184).decode()
    result = _run(quantum_router.encapsulate(
        _FakeRequest({"public_key": pub_b64, "algorithm": "kyber768"}),
        user=_fake_user(),
    ))
    assert isinstance(result, dict)
    assert "ciphertext" in result
    assert "shared_secret" in result
    assert result["algorithm"] == "kyber768"
