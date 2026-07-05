"""
Tests for rate limiting on /register and /api/auth/register (web/app.py),
added because both endpoints previously had no protection against
credential-stuffing-style abuse or account-creation spam, unlike /login
and /api/auth/login which already used check_rate_limit/record_failed_attempt.

Drives the real FastAPI app end-to-end with TestClient (same approach as
tests/test_migration_endpoint.py), with web.database.get_db swapped for an
isolated in-memory SQLite session per test so nothing touches the real DB.
web.auth._login_attempts is a module-level dict keyed by IP, shared with
/login, so it's cleared before/after each test for isolation.
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

RATE_LIMIT_MAX = auth_module.RATE_LIMIT_MAX


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


def _weak_password_payload(n):
    return {"username": f"user{n}", "email": f"user{n}@example.com", "password": "weak"}


def test_register_form_rate_limits_after_max_failed_attempts(client):
    for i in range(RATE_LIMIT_MAX):
        resp = client.post("/register", data=_weak_password_payload(i), follow_redirects=False)
        assert resp.status_code == 400  # weak password rejected, but counted as an attempt

    resp = client.post("/register", data=_weak_password_payload(999), follow_redirects=False)
    assert resp.status_code == 429


def test_api_register_rate_limits_after_max_failed_attempts(client):
    for i in range(RATE_LIMIT_MAX):
        resp = client.post("/api/auth/register", json=_weak_password_payload(i))
        assert resp.status_code == 400

    resp = client.post("/api/auth/register", json=_weak_password_payload(999))
    assert resp.status_code == 429


def test_api_register_rate_limit_is_independent_of_username_or_email(client):
    # The limit is keyed by IP, not by the attempted username/email -- so
    # varying those on every request must not let an attacker bypass it.
    for i in range(RATE_LIMIT_MAX):
        resp = client.post("/api/auth/register", json=_weak_password_payload(f"distinct-{i}"))
        assert resp.status_code == 400

    resp = client.post("/api/auth/register", json=_weak_password_payload("distinct-final"))
    assert resp.status_code == 429


def test_successful_registration_clears_attempts_and_does_not_rate_limit_next_call(client):
    strong_payload = {"username": "gooduser", "email": "good@example.com", "password": "StrongPass1!"}
    resp = client.post("/api/auth/register", json=strong_payload)
    assert resp.status_code == 200
    assert resp.json()["api_key"]

    # A handful of subsequent failed attempts from the same client should
    # still be allowed to start counting from zero, not inherit anything
    # from before the successful registration.
    for i in range(RATE_LIMIT_MAX - 1):
        resp = client.post("/api/auth/register", json=_weak_password_payload(f"after-{i}"))
        assert resp.status_code == 400
