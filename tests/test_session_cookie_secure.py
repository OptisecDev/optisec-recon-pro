"""
Tests for the access_token session cookie's Secure attribute (web/app.py).

Previously every response.set_cookie("access_token", ...) call set
httponly=True and samesite="lax" but never secure=True, so the session
cookie could be sent over a plain HTTP connection -- if any hop between
the browser and the server isn't HTTPS (a misconfigured proxy, plain-HTTP
staging, a stripped-TLS MITM), the cookie leaks in cleartext.

config.IS_PRODUCTION (GROQ_ENV=production or RENDER set) now gates
secure=True: local dev over plain http://localhost keeps working (a
Secure cookie is silently dropped by browsers on non-HTTPS origins, which
would otherwise break every dev login), while a real deployment gets the
Secure flag. httponly and samesite were already correct and are checked
here too as a regression guard.

Drives the real FastAPI app end-to-end via /register (same TestClient +
isolated in-memory DB pattern as tests/test_register_rate_limit.py), and
inspects the raw Set-Cookie header rather than the parsed cookie jar,
since the jar doesn't expose flag attributes.
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
import web.app as app_module
from web import auth as auth_module


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def client():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    TestSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = _get_db_override
    auth_module._login_attempts.clear()
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    auth_module._login_attempts.clear()
    _run(engine.dispose())


def _register(client, username="gooduser"):
    payload = {"username": username, "email": f"{username}@example.com", "password": "StrongPass1!"}
    return client.post("/register", data=payload, follow_redirects=False)


def _set_cookie_header(resp):
    header = resp.headers.get("set-cookie", "")
    assert "access_token=" in header, f"no access_token cookie in response: {header!r}"
    return header


def test_session_cookie_is_secure_in_production(client, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    resp = _register(client)
    assert resp.status_code == 302
    header = _set_cookie_header(resp)
    assert "secure" in header.lower()


def test_session_cookie_is_not_secure_outside_production(client, monkeypatch):
    # A Secure cookie is silently dropped by browsers on a plain http://
    # origin -- local dev (GROQ_ENV unset/development, no RENDER) must
    # keep getting a non-Secure cookie or every dev login would appear to
    # "not stick".
    monkeypatch.setattr(app_module, "IS_PRODUCTION", False)
    resp = _register(client)
    assert resp.status_code == 302
    header = _set_cookie_header(resp)
    assert "secure" not in header.lower()


@pytest.mark.parametrize("is_production", [True, False])
def test_session_cookie_httponly_and_samesite_always_set(client, monkeypatch, is_production):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", is_production)
    resp = _register(client)
    header = _set_cookie_header(resp).lower()
    assert "httponly" in header
    assert "samesite=lax" in header


def test_resolve_is_production_false_with_no_env_flags(monkeypatch):
    monkeypatch.delenv("GROQ_ENV", raising=False)
    monkeypatch.delenv("RENDER", raising=False)
    import config
    assert config._resolve_is_production() is False


def test_resolve_is_production_true_when_groq_env_is_production(monkeypatch):
    monkeypatch.setenv("GROQ_ENV", "production")
    monkeypatch.delenv("RENDER", raising=False)
    import config
    assert config._resolve_is_production() is True


def test_resolve_is_production_true_when_render_is_set(monkeypatch):
    monkeypatch.delenv("GROQ_ENV", raising=False)
    monkeypatch.setenv("RENDER", "true")
    import config
    assert config._resolve_is_production() is True


def test_resolve_is_production_false_for_explicit_dev_flag(monkeypatch):
    monkeypatch.setenv("GROQ_ENV", "development")
    monkeypatch.delenv("RENDER", raising=False)
    import config
    assert config._resolve_is_production() is False
