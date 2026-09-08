"""
Tests for rate limiting on GET /api/cve/search (web/routers/cve_submission.py).

search_nvd() hits the public NVD API -- free, no cost/reputation risk
unlike this audit series' other shared-credential fixes (Groq/OTX/
HackerOne), but still a resource this installation shares with itself
(predict_zero_days() in web/routers/ai_security.py also calls NVD).
Capped mainly to avoid this installation's own IP/key getting
rate-limited by NVD under load, for consistency with the rest of this
audit series rather than a real abuse concern.

Same TestClient + dependency-override + rate_limit._buckets-reset
conventions as tests/test_ioc_sync_rate_limit.py.
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
import web.routers.cve_submission as cve_router
import modules.bug_bounty.cve_pipeline as cve_pipeline


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
                username="cveuser", email="cveuser@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused-cve",
                subscription_tier="pro",
            ))
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == "cveuser"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[cve_router._user] = _user_override
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


def test_cve_search_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_CVE_SEARCH_NVD", "2")

    async def fake_search_nvd(**kwargs):
        return {"vulnerabilities": [], "total": 0, "source": "nvd"}

    monkeypatch.setattr(cve_pipeline, "search_nvd", fake_search_nvd)

    r1 = client.get("/api/cve/search?keyword=nginx")
    r2 = client.get("/api/cve/search?keyword=nginx")
    r3 = client.get("/api/cve/search?keyword=nginx")

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
