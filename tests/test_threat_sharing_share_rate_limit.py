"""
Tests for rate limiting on POST /api/threat-feed/share
(web/routers/threat_sharing.py).

share_ioc() can still publish a real public OTX pulse for TLP:WHITE/CLEAR
indicators (TLP:RED is rejected outright and GREEN/AMBER always share
privately -- commit 2d44363) against the platform's actual OTX account --
the same account a prior incident (commit aa530cb) accidentally created 3
public pulses on. Unbounded calls could still flood it with public pulses
one at a time.

Uses a real TestClient (unlike tests/test_threat_sharing.py's direct
module-function calls) because the rate limiter is a route-level
Depends(...) dependency that only runs through FastAPI's actual request
dispatch. Same rate_limit._buckets-reset convention as
tests/test_ioc_sync_rate_limit.py.
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
import web.routers.threat_sharing as sharing_router


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
            session.add(User(
                username="sharinguser", email="sharinguser@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused-share",
                subscription_tier="pro",
            ))
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == "sharinguser"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[sharing_router._user] = _user_override
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


def test_share_ioc_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_THREAT_SHARING_SHARE", "2")

    async def fake_share_ioc(**kwargs):
        return {"status": "disabled", "message_ar": "x", "message_en": "x"}

    monkeypatch.setattr(sharing_router.sharing, "share_ioc", fake_share_ioc)

    payload = {"type": "ip", "value": "1.2.3.4", "tlp": "WHITE"}
    r1 = client.post("/api/threat-feed/share", json=payload)
    r2 = client.post("/api/threat-feed/share", json=payload)
    r3 = client.post("/api/threat-feed/share", json=payload)

    assert r1.status_code != 429
    assert r2.status_code != 429
    assert r3.status_code == 429
