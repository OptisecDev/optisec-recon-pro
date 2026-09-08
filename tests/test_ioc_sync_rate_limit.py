"""
Tests for rate limiting on POST /api/iocs/sync and POST /api/iocs/sync/urlhaus
(web/routers/ioc.py).

sync_from_otx()/sync_from_urlhaus() call out to shared, instance-wide-keyed
external feeds (OTX_API_KEY / URLHAUS_API_KEY) with no request cap of
their own -- same shape as the fixes already applied to
web/routers/{bug_bounty,ai_security,osint,darkweb_monitor}.py.

Uses a real TestClient (unlike tests/test_ioc_router.py's direct handler
calls) because the rate limiter is a route-level Depends(...) dependency
that only runs through FastAPI's actual request dispatch. Same
rate_limit._buckets-reset convention as tests/test_osint_router_rate_limits.py.
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
from web.models import User
import web.app as app_module
import web.rate_limit as rate_limit
import web.routers.ioc as ioc_router


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    rate_limit._buckets.clear()
    yield
    rate_limit._buckets.clear()


@pytest.fixture
def client(monkeypatch):
    import config
    monkeypatch.setattr(config, "OTX_API_KEY", "")
    monkeypatch.setattr(config, "URLHAUS_API_KEY", "")

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
            session.add(User(
                username="iocuser", email="iocuser@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused-ioc",
                subscription_tier="free",
            ))
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == "iocuser"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[ioc_router._user] = _user_override
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


def test_sync_otx_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_IOC_SYNC_OTX", "2")

    r1 = client.post("/api/iocs/sync")
    r2 = client.post("/api/iocs/sync")
    r3 = client.post("/api/iocs/sync")

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429


def test_sync_urlhaus_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_IOC_SYNC_URLHAUS", "2")

    r1 = client.post("/api/iocs/sync/urlhaus")
    r2 = client.post("/api/iocs/sync/urlhaus")
    r3 = client.post("/api/iocs/sync/urlhaus")

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
