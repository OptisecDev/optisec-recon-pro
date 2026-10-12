"""
Tests for WebSocket handshake authentication (web/auth.py get_ws_user).

Before this fix get_ws_user accepted a `?token=` query param (which lands
in access logs) and fell back to the access_token cookie with no Origin
check. Browsers attach cookies to cross-site WebSocket handshakes, so any
external page could open /ws/scan/<id> as the logged-in victim
(Cross-Site WebSocket Hijacking).

Now: an Authorization: Bearer header is accepted as-is (non-browser
clients); cookie auth requires Origin to match Host; query-string tokens
are ignored. Drives the real /ws/scan/{scan_id} route end-to-end with the
same TestClient + isolated in-memory DB pattern as the other app tests.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
from web.models import User, Scan
from web.auth import hash_password, create_access_token
import web.app as app_module

SCAN_ID = "ws-auth-scan-1"
SAME_ORIGIN = "http://testserver"  # TestClient's default Host is "testserver"
POLICY_VIOLATION = 1008


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def client():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db

    c = TestClient(app_module.app)
    yield c, session_factory

    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


@pytest.fixture
def token(client):
    """A valid session token for a user who owns SCAN_ID."""
    _, session_factory = client

    async def go():
        async with session_factory() as db:
            user = User(
                username="ws_user", email="ws_user@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role="analyst", is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            db.add(Scan(id=SCAN_ID, user_id=user.id, target_url="https://example.com",
                        status="done", progress=100, results={}))
            await db.commit()
            return user.id

    user_id = _run(go())
    return create_access_token(user_id, "analyst")


def _assert_accepted(c, path=f"/ws/scan/{SCAN_ID}", headers=None):
    with c.websocket_connect(path, headers=headers or {}) as ws:
        msg = ws.receive_json()
        assert msg["type"] == "state"
        assert msg["status"] == "done"


def _assert_rejected(c, path=f"/ws/scan/{SCAN_ID}", headers=None):
    with pytest.raises(WebSocketDisconnect) as exc:
        with c.websocket_connect(path, headers=headers or {}) as ws:
            ws.receive_json()
    assert exc.value.code == POLICY_VIOLATION


def test_same_origin_cookie_is_accepted(client, token):
    c, _ = client
    _assert_accepted(c, headers={"origin": SAME_ORIGIN, "cookie": f"access_token={token}"})


def test_cross_origin_cookie_is_rejected(client, token):
    c, _ = client
    _assert_rejected(c, headers={"origin": "https://evil.example", "cookie": f"access_token={token}"})


def test_cookie_without_origin_is_rejected(client, token):
    c, _ = client
    _assert_rejected(c, headers={"cookie": f"access_token={token}"})


def test_valid_bearer_without_origin_is_accepted(client, token):
    c, _ = client
    _assert_accepted(c, headers={"authorization": f"Bearer {token}"})


def test_invalid_bearer_is_rejected(client, token):
    c, _ = client
    _assert_rejected(c, headers={"authorization": "Bearer not-a-valid-jwt"})


def test_query_string_token_is_rejected(client, token):
    c, _ = client
    _assert_rejected(c, path=f"/ws/scan/{SCAN_ID}?token={token}")
