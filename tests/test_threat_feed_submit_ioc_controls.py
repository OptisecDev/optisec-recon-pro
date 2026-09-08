"""
Tests for modules/threat_intel/global_feed.py::submit_ioc() and
web/routers/threat_feed.py's POST /api/submit-ioc.

submit_ioc() previously took type/value/malware/tlp completely unvalidated
and stored them straight into data["shared_iocs"], which get_live_ioc_feed()
merges into the feed every threat_feed-entitled account sees via
GET /api/feed -- with no length caps, no enum validation on type/tlp, no
attribution (no submitted_by field), and no rate limit on the endpoint.
Client-side, web/templates/threat_feed.html's refreshFeed() then inserted
those exact fields into innerHTML via unescaped template literals -- a
stored-XSS payload in `value`/`malware`/`tlp` would execute for every
other viewer of the page (see tests/test_threat_feed_xss_escaping.py for
the template-side fix).

Same DATA_FILE-isolation and rate_limit._buckets-reset conventions as
tests/test_idor_darkweb_intelligence.py / tests/test_subscription_redeem_controls.py.
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
import web.routers.threat_feed as threat_feed_router
import modules.threat_intel.global_feed as global_feed


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolated_feed_data(tmp_path, monkeypatch):
    monkeypatch.setattr(global_feed, "DATA_FILE", tmp_path / "global_threat_feed.json")


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    rate_limit._buckets.clear()
    yield
    rate_limit._buckets.clear()


# ─── Module-level: validation ───────────────────────────────────────────────

class TestSubmitIocValidation:
    def test_unknown_ioc_type_is_rejected(self):
        with pytest.raises(ValueError):
            global_feed.submit_ioc(ioc_type="<script>", value="1.2.3.4", malware="x", confidence=70)

    def test_empty_value_is_rejected(self):
        with pytest.raises(ValueError):
            global_feed.submit_ioc(ioc_type="ip", value="   ", malware="x", confidence=70)

    def test_value_is_length_capped(self):
        huge = "a" * 10_000
        ioc = global_feed.submit_ioc(ioc_type="domain", value=huge, malware="x", confidence=70)
        assert len(ioc["value"]) == global_feed._MAX_IOC_VALUE_LEN

    def test_malware_is_length_capped(self):
        huge = "m" * 10_000
        ioc = global_feed.submit_ioc(ioc_type="ip", value="1.2.3.4", malware=huge, confidence=70)
        assert len(ioc["malware"]) == global_feed._MAX_IOC_MALWARE_LEN

    def test_invalid_tlp_falls_back_to_amber(self):
        ioc = global_feed.submit_ioc(ioc_type="ip", value="1.2.3.4", malware="x", confidence=70,
                                      tlp="<img src=x onerror=alert(1)>")
        assert ioc["tlp"] == "AMBER"

    def test_valid_tlp_is_normalized_uppercase(self):
        ioc = global_feed.submit_ioc(ioc_type="ip", value="1.2.3.4", malware="x", confidence=70, tlp="red")
        assert ioc["tlp"] == "RED"

    def test_valid_submission_is_accepted(self):
        ioc = global_feed.submit_ioc(ioc_type="ip", value="1.2.3.4", malware="TrickBot", confidence=80)
        assert ioc["type"] == "ip"
        assert ioc["value"] == "1.2.3.4"


class TestSubmitIocAttribution:
    def test_submission_is_stamped_with_submitted_by(self):
        ioc = global_feed.submit_ioc(ioc_type="ip", value="1.2.3.4", malware="x", confidence=70, user_id=42)
        assert ioc["submitted_by"] == 42

    def test_default_user_id_is_none(self):
        ioc = global_feed.submit_ioc(ioc_type="ip", value="1.2.3.4", malware="x", confidence=70)
        assert ioc["submitted_by"] is None


# ─── Router-level ────────────────────────────────────────────────────────────

def _enterprise_user() -> User:
    return User(id=7, username="analyst", email="a@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused", subscription_tier="enterprise")


class TestSubmitIocRouter:
    def test_valid_submission_stamps_requesting_user(self):
        result = _run(threat_feed_router.submit_ioc(
            _FakeRequest({"type": "ip", "value": "5.6.7.8", "malware": "Emotet", "confidence": 90}),
            user=_enterprise_user(),
        ))
        assert result["submitted_by"] == 7


class _FakeRequest:
    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


def test_submit_ioc_router_rejects_invalid_type_with_400():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        _run(threat_feed_router.submit_ioc(
            _FakeRequest({"type": "not-a-real-type", "value": "x"}),
            user=_enterprise_user(),
        ))
    assert exc_info.value.status_code == 400


# ─── Rate limiting (full app, via TestClient) ───────────────────────────────

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
                username="analyst2", email="analyst2@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused-tf",
                subscription_tier="enterprise",
            ))
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == "analyst2"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[threat_feed_router._user] = _user_override
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


def test_submit_ioc_endpoint_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_THREAT_FEED_SUBMIT", "2")
    payload = {"type": "ip", "value": "9.9.9.9", "malware": "x", "confidence": 50}

    r1 = client.post("/threat-feed/api/submit-ioc", json=payload)
    r2 = client.post("/threat-feed/api/submit-ioc", json=payload)
    r3 = client.post("/threat-feed/api/submit-ioc", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
