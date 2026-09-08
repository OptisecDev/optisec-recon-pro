"""
Tests for rate limiting on POST /api/osint/network-scan,
POST /api/osint/darkweb-scan, and POST /api/osint/threat-analysis
(web/routers/osint.py).

Unlike /api/osint/unified-search (which already rate-limits per user via
modules/osint/unified_engine.py's own _check_rate()), these three had no
cap at all despite each calling multiple shared, instance-wide-keyed
external APIs -- Shodan/Censys, HIBP/IntelligenceX/RapidAPI/LeakLookup/
GitHub/OTX, and (threat-analysis with include_ai=True) Groq. Same fix
shape as web/routers/bug_bounty.py and web/routers/ai_security.py: reuse
web/rate_limit.py's per-IP rate_limiter() factory.

Same TestClient + dependency-override approach as
tests/test_ai_security_controls.py, adapted for osint.router's own local
`_user` dependency. Same _reset_rate_limit_buckets fixture as
tests/test_targets_idor.py, since web/rate_limit.py's _buckets dict is
shared module-level state across tests.
"""

import asyncio
import sys
import os

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
import web.routers.osint as osint_module
import modules.osint.network_intelligence as network_intelligence
import modules.osint.darkweb_intelligence as darkweb_intelligence
import modules.osint.mitre_mapping as mitre_mapping
import modules.osint.unified_engine as unified_engine


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
                username="analyst1", email="analyst1@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused-osint",
                subscription_tier="enterprise",  # osint_darkweb is enterprise-only
            )
            session.add(user)
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == "analyst1"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[osint_module._user] = _user_override
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


def test_network_scan_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_OSINT_NETWORK_SCAN", "2")

    async def fake_gather(*a, **kw):
        return {"target": "example.com", "ip": "93.184.216.34", "attack_surface": {"score": 0}}

    monkeypatch.setattr(network_intelligence, "gather_network_intelligence", fake_gather)

    payload = {"target": "example.com"}
    r1 = client.post("/api/osint/network-scan", json=payload)
    r2 = client.post("/api/osint/network-scan", json=payload)
    r3 = client.post("/api/osint/network-scan", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429


def test_darkweb_scan_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_OSINT_DARKWEB_SCAN", "2")

    async def fake_gather(*a, **kw):
        return {
            "target": "example.com", "target_type": "domain",
            "breaches": [], "pastes": [], "github_exposures": [], "threat_actors": [],
            "exposure": {"score": 0, "exposure_level": "none", "recommendations": []},
            "intelx": None, "breachdirectory": None, "leaklookup": None, "threat_actor_detail": None,
        }

    monkeypatch.setattr(darkweb_intelligence, "gather_darkweb_intelligence", fake_gather)

    payload = {"target": "example.com"}
    r1 = client.post("/api/osint/darkweb-scan", json=payload)
    r2 = client.post("/api/osint/darkweb-scan", json=payload)
    r3 = client.post("/api/osint/darkweb-scan", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429


def test_threat_analysis_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_OSINT_THREAT_ANALYSIS", "2")

    async def fake_map_findings(findings):
        return []

    async def fake_attack_path(findings):
        return {"total_findings_analyzed": 0, "mapped_findings": 0, "attack_path": [], "path_length": 0}

    monkeypatch.setattr(mitre_mapping, "map_findings_to_attack", fake_map_findings)
    monkeypatch.setattr(mitre_mapping, "generate_attack_path", fake_attack_path)

    payload = {"target": "example.com", "scan_results": {}}
    r1 = client.post("/api/osint/threat-analysis", json=payload)
    r2 = client.post("/api/osint/threat-analysis", json=payload)
    r3 = client.post("/api/osint/threat-analysis", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429


def test_unified_search_still_uses_its_own_per_user_limit_not_the_new_ones(client, monkeypatch):
    """Regression guard: unified-search's existing per-user _check_rate()
    (modules/osint/unified_engine.py) must keep working untouched -- this
    file only adds new per-IP limiters to the three endpoints that had
    none."""
    async def fake_search_unified(target, target_type, rate_key="global"):
        return {
            "target": target, "target_type": target_type, "elapsed_seconds": 0.0,
            "total_results": 0, "sources": [],
        }

    monkeypatch.setattr(unified_engine, "search_unified", fake_search_unified)

    resp = client.post("/api/osint/unified-search", json={"target": "example.com"})
    assert resp.status_code == 200
