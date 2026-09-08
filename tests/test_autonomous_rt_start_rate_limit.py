"""
Tests for rate limiting on POST /autonomous-redteam/api/start
(web/routers/autonomous_rt.py).

start_autonomous_simulation() calls Groq under GROQ_API_KEY -- one
instance-wide credential, not per-user (same shape as the fixes in
web/routers/{bug_bounty,ai_security,osint}.py) -- and also runs real,
expensive scanners (nmap, port scan, XSS/SQLi/SSRF) for Phases 1/3, with
no request cap. Target ownership (tests/test_autonomous_rt_router.py) was
already enforced, so this couldn't be pointed at someone else's
infrastructure, but a single account could still flood the scan pipeline
and the shared Groq quota with repeat calls.

Uses a real TestClient (unlike test_autonomous_rt_router.py's direct
handler calls) because the rate limiter is a route-level
Depends(...) dependency that only runs through FastAPI's actual request
dispatch, not a bare Python function call. Same rate_limit._buckets-reset
convention as tests/test_ai_security_controls.py.
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
from web.models import User, Target
import web.app as app_module
import web.rate_limit as rate_limit
import web.routers.autonomous_rt as art_router
import modules.ai_advanced.autonomous_redteam as autonomous_redteam


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
                username="artuser", email="artuser@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused-art",
                subscription_tier="enterprise",
            )
            session.add(user)
            await session.flush()
            session.add(Target(user_id=user.id, url="https://example.com", name="t1"))
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == "artuser"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[art_router._user] = _user_override
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


def test_start_simulation_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_AUTONOMOUS_RT_START", "2")

    async def fake_start(**kwargs):
        return {"id": "sess-1", "target": kwargs.get("target"), "user_id": kwargs.get("user_id")}

    monkeypatch.setattr(autonomous_redteam, "start_autonomous_simulation", fake_start)

    payload = {"target_id": 1, "attack_types": ["web"]}
    r1 = client.post("/autonomous-redteam/api/start", json=payload)
    r2 = client.post("/autonomous-redteam/api/start", json=payload)
    r3 = client.post("/autonomous-redteam/api/start", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
