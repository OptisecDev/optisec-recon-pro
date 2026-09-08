"""
Tests for web/routers/ai_security.py's abuse/resource guards, added
because none existed:

  - POST /ai-security/api/zero-day/predict and
    POST /ai-security/api/red-team/engagements both call Groq under
    GROQ_API_KEY -- one instance-wide credential, not per-user (same shape
    as HACKERONE_API_TOKEN, see web/routers/bug_bounty.py) -- with no
    request cap, so any PRO/ENTERPRISE user could loop either endpoint and
    run up real Groq usage on the platform's own account. Now rate-limited
    per IP via the existing rate_limiter() factory
    (RATE_LIMIT_ZERO_DAY_PREDICT / RATE_LIMIT_RED_TEAM_CREATE).
  - POST /ai-security/api/attack-patterns/analyze took unbounded
    text/events from the request body straight into a regex sweep across
    ~12 patterns with no size cap, letting one request drive arbitrarily
    large CPU work. Now capped (_MAX_ANALYZE_TEXT_CHARS /
    _MAX_ANALYZE_EVENTS / _MAX_ANALYZE_EVENT_CHARS).

The IDOR-scoping around zero-day predictions and red-team engagements
(commit 7ec15f0) is untouched and already covered by
tests/test_idor_zero_day_predictions.py / tests/test_idor_ai_red_team.py --
this file is only about the new rate limits and the input cap.

Same TestClient + dependency-override approach as
tests/test_bug_bounty_submission_controls.py, adapted for
ai_security.router's own local `_user` dependency. Same
_reset_rate_limit_buckets fixture as tests/test_targets_idor.py /
tests/test_subscription_redeem_controls.py, since web/rate_limit.py's
_buckets dict is shared module-level state across tests.
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
import web.routers.ai_security as ai_sec_module
import modules.ai_advanced.zero_day as zero_day
import modules.ai_advanced.red_team as red_team


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
                username="researcher", email="researcher@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused-ai-sec",
                # "ai_red_team" is enterprise-only (web/license.py TIER_FEATURES) --
                # "pro" alone would 402 before the rate limiter is ever reached.
                subscription_tier="enterprise",
            )
            session.add(user)
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == "researcher"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[ai_sec_module._user] = _user_override
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


# ─── Zero-day predict quota ─────────────────────────────────────────────────

def test_zero_day_predict_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ZERO_DAY_PREDICT", "2")

    async def fake_predict(**kwargs):
        return {"target_software": kwargs.get("target_software"), "risk_score": 0.1}

    monkeypatch.setattr(zero_day, "predict_zero_days", fake_predict)

    payload = {"software": "nginx", "version": "1.25"}
    r1 = client.post("/ai-security/api/zero-day/predict", json=payload)
    r2 = client.post("/ai-security/api/zero-day/predict", json=payload)
    r3 = client.post("/ai-security/api/zero-day/predict", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429


# ─── Red-team engagement quota ──────────────────────────────────────────────

def test_red_team_create_engagement_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_RED_TEAM_CREATE", "2")

    async def fake_create(**kwargs):
        return {"id": "RT-1", "target": kwargs.get("target")}

    monkeypatch.setattr(red_team, "create_engagement", fake_create)

    payload = {"target": "example.com", "scope": ["example.com"], "objectives": ["test"]}
    r1 = client.post("/ai-security/api/red-team/engagements", json=payload)
    r2 = client.post("/ai-security/api/red-team/engagements", json=payload)
    r3 = client.post("/ai-security/api/red-team/engagements", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429


# ─── attack-patterns/analyze size cap ───────────────────────────────────────

def test_analyze_patterns_caps_oversized_text(client, monkeypatch):
    captured = {}

    def fake_analyze_text(text):
        captured["text"] = text
        return {"analyzed_events": 1, "detected_patterns": 0,
                "kill_chain_coverage": {}, "campaign": {"detected": False}, "patterns": [],
                "analyzed_at": "now"}

    import modules.ai_advanced.attack_patterns as attack_patterns
    monkeypatch.setattr(attack_patterns, "analyze_text", fake_analyze_text)

    huge_text = "nmap scan detected\n" * 50_000  # well over _MAX_ANALYZE_TEXT_CHARS
    resp = client.post("/ai-security/api/attack-patterns/analyze", json={"text": huge_text})
    assert resp.status_code == 200
    assert len(captured["text"]) == ai_sec_module._MAX_ANALYZE_TEXT_CHARS


def test_analyze_patterns_caps_event_count(client):
    events = [f"event {i}" for i in range(10_000)]
    resp = client.post("/ai-security/api/attack-patterns/analyze", json={"events": events})
    assert resp.status_code == 200
    assert resp.json()["analyzed_events"] == ai_sec_module._MAX_ANALYZE_EVENTS


def test_analyze_patterns_caps_individual_event_length(client, monkeypatch):
    captured = {}

    def fake_analyze_events(events):
        captured["events"] = events
        return {"analyzed_events": len(events), "detected_patterns": 0,
                "kill_chain_coverage": {}, "campaign": {"detected": False}, "patterns": [],
                "analyzed_at": "now"}

    import modules.ai_advanced.attack_patterns as attack_patterns
    monkeypatch.setattr(attack_patterns, "analyze_events", fake_analyze_events)

    resp = client.post("/ai-security/api/attack-patterns/analyze",
                        json={"events": ["A" * 10_000]})
    assert resp.status_code == 200
    assert len(captured["events"][0]) == ai_sec_module._MAX_ANALYZE_EVENT_CHARS
