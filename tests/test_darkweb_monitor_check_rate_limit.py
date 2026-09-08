"""
Tests for rate limiting on POST /api/darkweb/monitor/{id}/check
(web/routers/darkweb_monitor.py).

run_check_and_persist() -> run_monitor_check() calls the exact same
gather_darkweb_intelligence() as POST /api/osint/darkweb-scan (already
rate-limited, see tests/test_osint_router_rate_limits.py) plus LeakCheck --
multiple shared, instance-wide-keyed external APIs. Without its own limit,
this endpoint was a second, unprotected path to the same calls, bypassing
that earlier fix entirely.

Same TestClient + dependency-override + rate_limit._buckets-reset
conventions as tests/test_osint_router_rate_limits.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
from web.models import User, DarkWebMonitor
import web.app as app_module
import web.rate_limit as rate_limit
import web.routers.darkweb_monitor as monitor_router


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    rate_limit._buckets.clear()
    yield
    rate_limit._buckets.clear()


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
            user = User(
                username="monitoruser", email="monitoruser@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused-dwm",
                subscription_tier="enterprise",
            )
            session.add(user)
            await session.flush()
            session.add(DarkWebMonitor(user_id=user.id, target="example.com", target_type="domain", label="t"))
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == "monitoruser"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[monitor_router._user] = _user_override
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


def test_check_monitor_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_DARKWEB_MONITOR_CHECK", "2")

    async def fake_run_check_and_persist(monitor, db):
        return [], {"events": [], "exposure": {}}

    monkeypatch.setattr(monitor_router, "run_check_and_persist", fake_run_check_and_persist)

    r1 = client.post("/api/darkweb/monitor/1/check")
    r2 = client.post("/api/darkweb/monitor/1/check")
    r3 = client.post("/api/darkweb/monitor/1/check")

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
