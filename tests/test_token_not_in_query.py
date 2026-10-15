"""
Credentials must travel in headers, never in the URL query string (Issue #2).

nginx's error_log records the full request line, query string included, so
a `?token=<jwt>` or `?api_key=<key>` would be written to disk in clear text.
web/auth.get_current_user reads only the X-API-Key header, the
Authorization: Bearer header and the access_token cookie; these tests pin
that down for HTTP API routes (the WebSocket equivalent lives in
tests/test_ws_auth.py). Same TestClient + isolated in-memory DB pattern as
the other app tests.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
from web.models import User
from web.auth import hash_password, hash_api_key, create_access_token
import web.app as app_module

ROUTE = "/api/scans"
API_KEY = "test-api-key-not-a-real-secret"


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
    """A valid session token for an analyst who also has an API key."""
    _, session_factory = client

    async def go():
        async with session_factory() as db:
            user = User(
                username="query_token_user", email="query_token_user@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role="analyst", is_active=True,
                api_key_hash=hash_api_key(API_KEY),
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id

    user_id = _run(go())
    return create_access_token(user_id, "analyst")


def _missing_auth_status(c):
    return c.get(ROUTE).status_code


def test_route_requires_auth(client, token):
    c, _ = client
    assert _missing_auth_status(c) == 401


def test_bearer_header_is_accepted(client, token):
    c, _ = client
    resp = c.get(ROUTE, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.parametrize("param", ["token", "access_token", "jwt", "auth"])
def test_query_string_token_is_rejected(client, token, param):
    c, _ = client
    resp = c.get(ROUTE, params={param: token})
    assert resp.status_code == _missing_auth_status(c) == 401


def test_query_string_authorization_value_is_rejected(client, token):
    c, _ = client
    resp = c.get(ROUTE, params={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_api_key_header_is_accepted(client, token):
    c, _ = client
    resp = c.get(ROUTE, headers={"X-API-Key": API_KEY})
    assert resp.status_code == 200


@pytest.mark.parametrize("param", ["api_key", "apikey", "key", "X-API-Key"])
def test_query_string_api_key_is_rejected(client, token, param):
    c, _ = client
    resp = c.get(ROUTE, params={param: API_KEY})
    assert resp.status_code == 401


@pytest.mark.parametrize("header", [
    "Bearer not-a-valid-jwt",
    "Bearer ",
    "Bearer",
    "Basic dXNlcjpwYXNz",
    "Token {token}",
    "{token}",
])
def test_malformed_authorization_header_is_rejected(client, token, header):
    c, _ = client
    resp = c.get(ROUTE, headers={"Authorization": header.format(token=token)})
    assert resp.status_code == 401


def test_malformed_header_does_not_fall_back_to_query_string(client, token):
    c, _ = client
    resp = c.get(ROUTE, params={"token": token},
                 headers={"Authorization": "Bearer not-a-valid-jwt"})
    assert resp.status_code == 401
