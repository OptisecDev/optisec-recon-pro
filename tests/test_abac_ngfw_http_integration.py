"""End-to-end HTTP test for the NGFW business-hours rule.

Unlike the Depends() tests in test_abac_dependencies.py, nothing on the ABAC
path is stubbed: the user is authenticated by web.auth.get_current_user from
a real JWT against a real (in-memory SQLite) users table, the policy is the
shipped config via get_policy(), and request_time comes from the default
clock in build_attributes(). Only datetime.now() is frozen, and its naive
form returns server-local time, so a regression to naive time would shift
the window.

No production route adopts require_abac() yet (the Phase 1 notes leave that
as an owner decision), so the protected route lives on a test app at the
real NGFW rules path.
"""

import asyncio
import os
import sys
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import auth.dependencies as abac
from auth.dependencies import require_abac
from web.auth import create_access_token
from web.database import Base
from web.models import User

UTC = timezone.utc
BGW = ZoneInfo("Asia/Baghdad")


@pytest.fixture(autouse=True)
def _shipped_policy(monkeypatch):
    monkeypatch.delenv("ABAC_TIMEZONE", raising=False)
    monkeypatch.delenv("ABAC_RULES_PATH", raising=False)
    abac.reset_policy_cache()
    yield
    abac.reset_policy_cache()


@pytest.fixture
def server_utc(monkeypatch):
    """Run as Render does: process-local zone UTC."""
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is unavailable on this platform")
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def _freeze(monkeypatch, instant):
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            if tz is None:
                return instant.astimezone().replace(tzinfo=None)
            return instant.astimezone(tz)

    monkeypatch.setattr(abac, "datetime", FrozenDatetime)


@pytest.fixture
def client():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
                                 connect_args={"check_same_thread": False})
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with sessions() as db:
            db.add(User(id=7, username="ngfw-analyst", email="ngfw@example.com",
                        password_hash="x", role="analyst", is_active=True))
            await db.commit()

    asyncio.run(setup())

    async def get_test_db():
        async with sessions() as db:
            yield db

    app = FastAPI()

    @app.get("/ngfw/api/rules")
    async def ngfw_rules(user=Depends(require_abac("ngfw_rules"))):
        return {"ok": True, "user_id": user.id}

    app.dependency_overrides[abac.get_db] = get_test_db
    yield TestClient(app)
    asyncio.run(engine.dispose())


def _auth():
    return {"Authorization": f"Bearer {create_access_token(7, 'analyst')}"}


@pytest.mark.parametrize("instant, status", [
    (datetime(2026, 10, 13, 6, 0, tzinfo=UTC), 200),    # Tue 09:00 Baghdad: start, inclusive
    (datetime(2026, 10, 11, 10, 0, tzinfo=UTC), 200),   # Sun 13:00 Baghdad
    (datetime(2026, 10, 15, 13, 59, tzinfo=UTC), 200),  # Thu 16:59 Baghdad
    (datetime(2026, 10, 13, 14, 0, tzinfo=UTC), 403),   # Tue 17:00 Baghdad: end, exclusive (14:00 UTC)
    (datetime(2026, 10, 13, 5, 59, tzinfo=UTC), 403),   # Tue 08:59 Baghdad
    (datetime(2026, 10, 16, 8, 0, tzinfo=UTC), 403),    # Fri 11:00 Baghdad
    (datetime(2026, 10, 17, 8, 0, tzinfo=UTC), 403),    # Sat 11:00 Baghdad
])
def test_ngfw_rules_http_business_hours_in_baghdad(monkeypatch, server_utc, client, instant, status):
    _freeze(monkeypatch, instant)
    r = client.get("/ngfw/api/rules", headers=_auth())
    assert r.status_code == status, (instant.astimezone(BGW), r.text)
    if status == 200:
        assert r.json() == {"ok": True, "user_id": 7}
    else:
        assert r.json()["detail"] == "Access denied by context policy"


def test_ngfw_rules_http_window_is_not_server_local(monkeypatch, server_utc, client):
    """06:30 UTC is outside 09:00-17:00 read as UTC but inside it in Baghdad."""
    _freeze(monkeypatch, datetime(2026, 10, 13, 6, 30, tzinfo=UTC))
    assert client.get("/ngfw/api/rules", headers=_auth()).status_code == 200
    _freeze(monkeypatch, datetime(2026, 10, 13, 15, 0, tzinfo=UTC))   # inside as UTC, 18:00 Baghdad
    assert client.get("/ngfw/api/rules", headers=_auth()).status_code == 403


def test_ngfw_rules_http_requires_real_authentication(monkeypatch, client):
    _freeze(monkeypatch, datetime(2026, 10, 13, 7, 0, tzinfo=UTC))
    assert client.get("/ngfw/api/rules").status_code == 401
    assert client.get("/ngfw/api/rules", headers={"Authorization": "Bearer nope"}).status_code == 401
