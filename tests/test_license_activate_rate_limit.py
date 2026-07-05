"""
Tests for rate limiting on /api/license/activate and /license/activate
(web/app.py), added because both endpoints previously had no protection
against repeatedly guessing license keys, unlike /login and
/api/auth/login which already used
check_rate_limit/record_failed_attempt/clear_attempts.

Same approach as tests/test_register_rate_limit.py: drive the real FastAPI
app via TestClient with an isolated in-memory DB. These routes additionally
require an authenticated admin (Depends(web_user) + require_admin), so
web_user is overridden directly to return a fixed admin User instead of
exercising the full login/cookie flow -- that flow is already covered by
other tests, this file is only about the rate-limit gate.
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
        async with TestSessionLocal() as session:
            admin = User(
                username="admin", email="admin@example.com", password_hash="x",
                role="admin", is_active=True, api_key_hash="unused",
            )
            session.add(admin)
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _admin_user_override():
        async with TestSessionLocal() as session:
            from sqlalchemy import select
            result = await session.execute(select(User).where(User.username == "admin"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[app_module.web_user] = _admin_user_override
    auth_module._login_attempts.clear()
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    auth_module._login_attempts.clear()
    _run(engine.dispose())


def test_api_license_activate_rate_limits_after_max_failed_attempts(client):
    for _ in range(RATE_LIMIT_MAX):
        resp = client.post("/api/license/activate", json={"key": "not-a-real-key"})
        assert resp.status_code == 422  # invalid key rejected, but counted as an attempt

    resp = client.post("/api/license/activate", json={"key": "not-a-real-key"})
    assert resp.status_code == 429


def test_license_activate_form_rate_limits_after_max_failed_attempts(client):
    for _ in range(RATE_LIMIT_MAX):
        resp = client.post("/license/activate", data={"key": "not-a-real-key"})
        assert resp.status_code == 200  # form re-renders with a flash error, not a raw 4xx

    resp = client.post("/license/activate", data={"key": "not-a-real-key"})
    assert resp.status_code == 429


def test_api_license_activate_missing_key_counts_as_a_failed_attempt(client):
    for _ in range(RATE_LIMIT_MAX):
        resp = client.post("/api/license/activate", json={})
        assert resp.status_code == 400

    resp = client.post("/api/license/activate", json={"key": "still-blocked"})
    assert resp.status_code == 429
