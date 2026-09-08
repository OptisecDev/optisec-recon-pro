"""
Tests for GET /api/correlations and GET /api/correlations/{cluster_id}
(web/app.py) -- the JSON API behind the /correlations page
(web/routers/correlations.py), which already gates itself with
require_feature_or_402("ioc_correlations", user). These two endpoints did
not, despite backing the same feature: any authenticated user of any tier
could call them directly. Also, ?refresh=true had no rate limit despite
triggering real clustering CPU work (and, when OTX_API_KEY is set, an
instance-wide-shared-credential OTX fetch) on every call.

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
from web.models import User
import web.app as app_module
import web.rate_limit as rate_limit


def _run(coro):
    return asyncio.run(coro)


def _fake_correlation_data() -> dict:
    return {
        "generated_at": "2026-01-01T00:00:00Z", "otx_enabled": False,
        "total_iocs": 0, "unique_iocs": 0, "total_clusters": 0,
        "critical_clusters": 0, "high_clusters": 0, "average_score": 0.0,
        "ioc_type_summary": {}, "sources_active": [],
        "clusters": [{"cluster_id": "c1", "name": "Test Cluster", "severity": "LOW"}],
    }


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    rate_limit._buckets.clear()
    yield
    rate_limit._buckets.clear()


def _make_client(tier: str):
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
                username=f"{tier}-user", email=f"{tier}@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash=f"unused-corr-{tier}",
                subscription_tier=tier,
            ))
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == f"{tier}-user"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[app_module.web_user] = _user_override
    client = TestClient(app_module.app)
    return client, engine


@pytest.fixture
def free_client():
    client, engine = _make_client("free")
    yield client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


@pytest.fixture
def enterprise_client():
    client, engine = _make_client("enterprise")
    yield client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


class TestFeatureGating:
    def test_free_tier_cannot_reach_correlations_list(self, free_client, monkeypatch):
        monkeypatch.setattr(app_module, "load_cached", lambda: _fake_correlation_data())
        resp = free_client.get("/api/correlations")
        assert resp.status_code == 402

    def test_free_tier_cannot_reach_correlation_cluster_detail(self, free_client, monkeypatch):
        monkeypatch.setattr(app_module, "load_cached", lambda: _fake_correlation_data())
        resp = free_client.get("/api/correlations/c1")
        assert resp.status_code == 402

    def test_enterprise_tier_can_reach_correlations_list(self, enterprise_client, monkeypatch):
        monkeypatch.setattr(app_module, "load_cached", lambda: _fake_correlation_data())
        resp = enterprise_client.get("/api/correlations")
        assert resp.status_code == 200

    def test_enterprise_tier_can_reach_correlation_cluster_detail(self, enterprise_client, monkeypatch):
        monkeypatch.setattr(app_module, "load_cached", lambda: _fake_correlation_data())
        resp = enterprise_client.get("/api/correlations/c1")
        assert resp.status_code == 200
        assert resp.json()["cluster"]["cluster_id"] == "c1"


class TestRefreshRateLimit:
    def test_refresh_true_is_rate_limited(self, enterprise_client, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_CORRELATIONS_REFRESH", "2")
        monkeypatch.setattr(app_module, "run_correlation", lambda save=True: _fake_correlation_data())

        r1 = enterprise_client.get("/api/correlations?refresh=true")
        r2 = enterprise_client.get("/api/correlations?refresh=true")
        r3 = enterprise_client.get("/api/correlations?refresh=true")

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 429

    def test_non_refresh_calls_also_count_against_the_same_limiter(self, enterprise_client, monkeypatch):
        # The rate limiter guards the route, not just the refresh branch --
        # confirms cached (non-refresh) reads aren't a bypass for the cap.
        monkeypatch.setenv("RATE_LIMIT_CORRELATIONS_REFRESH", "2")
        monkeypatch.setattr(app_module, "load_cached", lambda: _fake_correlation_data())

        r1 = enterprise_client.get("/api/correlations")
        r2 = enterprise_client.get("/api/correlations")
        r3 = enterprise_client.get("/api/correlations")

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 429
