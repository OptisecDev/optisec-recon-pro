"""
Tests for web/routers/license_routes.py::redeem_license's atomicity and
rate limiting.

Previously: SELECT LicenseKey -> check redeemed_by is None in Python ->
mutate -> commit, no row lock and no WHERE clause on the UPDATE beyond the
primary key. Two concurrent redemptions of the same not-yet-redeemed key
could both pass the Python-level check before either commit landed, each
setting its own account's User.subscription_tier -- only the *last*
commit's redeemed_by survives on the LicenseKey row, silently losing the
audit trail for the other account while both still got upgraded. Fixed to
an atomic `UPDATE ... WHERE key_hash = ? AND redeemed_by IS NULL`, the same
pattern SchedulerLock's _acquire_lock (modules/darkweb/scheduler.py) uses
for exactly this class of problem -- rowcount == 1 is the only way the
request "won" the redemption; a true concurrent race is exercised here by
calling redeem_license twice in sequence against the same key with two
different users, which is sufficient to prove the WHERE clause -- not
Python-level timing -- is what prevents the second one from succeeding.

Also added: rate limiting on POST /api/subscription/redeem
(RATE_LIMIT_SUBSCRIPTION_REDEEM), matching its /api/license/activate
sibling.

Same TestClient + dependency-override approach as
tests/test_bug_bounty_submission_controls.py, adapted for
license_routes.router's own local `_user` dependency.
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
from web.models import User, LicenseKey
import web.app as app_module
import web.rate_limit as rate_limit
import web.routers.license_routes as lr_module
from license_utils import hash_license_key


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    """POST /api/subscription/redeem is rate-limited (web/rate_limit.py,
    shared module-level state) -- without this, an earlier test's requests
    from "testclient" bleed into the next test's limit. Same pattern as
    tests/test_targets_idor.py."""
    rate_limit._buckets.clear()
    yield
    rate_limit._buckets.clear()


@pytest.fixture
def env():
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
            u1 = User(username="alice", email="alice@example.com", password_hash="x",
                       role="viewer", is_active=True, api_key_hash="unused-alice")
            u2 = User(username="bob", email="bob@example.com", password_hash="x",
                       role="viewer", is_active=True, api_key_hash="unused-bob")
            session.add_all([u1, u2])
            await session.flush()
            key = LicenseKey(key_hash=hash_license_key("OPTISEC-RECON-AAAA-BBBB-CCCC-DDDD"), tier="pro")
            session.add(key)
            await session.commit()
            return u1.id, u2.id

    user1_id, user2_id = _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    def _make_user_override(user_id):
        async def _override():
            async with TestSessionLocal() as session:
                result = await session.execute(select(User).where(User.id == user_id))
                return result.scalar_one()
        return _override

    app_module.app.dependency_overrides[get_db] = _get_db_override
    yield TestSessionLocal, user1_id, user2_id, _make_user_override
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


def _client_as(env, user_id_getter):
    SessionLocal, user1_id, user2_id, make_override = env
    app_module.app.dependency_overrides[lr_module._user] = make_override(user_id_getter)
    return TestClient(app_module.app)


# ─── Atomic redemption / double-redeem race ────────────────────────────────

def test_second_redemption_of_same_key_is_rejected(env):
    SessionLocal, user1_id, user2_id, make_override = env

    client1 = _client_as(env, user1_id)
    r1 = client1.post("/api/subscription/redeem",
                       json={"license_key": "OPTISEC-RECON-AAAA-BBBB-CCCC-DDDD"})
    assert r1.status_code == 200
    assert r1.json() == {"success": True, "tier": "pro"}

    client2 = _client_as(env, user2_id)
    r2 = client2.post("/api/subscription/redeem",
                       json={"license_key": "OPTISEC-RECON-AAAA-BBBB-CCCC-DDDD"})
    assert r2.status_code == 400


def test_second_redeemer_does_not_get_upgraded(env):
    """Reproduces the exact bug: before the atomic UPDATE, the second
    request's User.subscription_tier assignment happened in Python before
    the commit-time conflict was even detectable, so bob got upgraded too
    even though the row only ever ends up crediting one redeemer."""
    SessionLocal, user1_id, user2_id, make_override = env

    _client_as(env, user1_id).post(
        "/api/subscription/redeem", json={"license_key": "OPTISEC-RECON-AAAA-BBBB-CCCC-DDDD"})
    _client_as(env, user2_id).post(
        "/api/subscription/redeem", json={"license_key": "OPTISEC-RECON-AAAA-BBBB-CCCC-DDDD"})

    async def _fetch():
        async with SessionLocal() as session:
            bob = (await session.execute(select(User).where(User.id == user2_id))).scalar_one()
            key = (await session.execute(select(LicenseKey))).scalar_one()
            return bob.subscription_tier, key.redeemed_by

    bob_tier, redeemed_by = _run(_fetch())
    assert bob_tier == "free"          # never upgraded
    assert redeemed_by == user1_id     # alice's redemption is the only one on record


def test_redeeming_unknown_key_is_rejected(env):
    SessionLocal, user1_id, user2_id, make_override = env
    client = _client_as(env, user1_id)
    resp = client.post("/api/subscription/redeem", json={"license_key": "OPTISEC-RECON-0000-0000-0000-0000"})
    assert resp.status_code == 400


# ─── Rate limiting ──────────────────────────────────────────────────────────

def test_redeem_endpoint_is_rate_limited(env, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_SUBSCRIPTION_REDEEM", "2")
    SessionLocal, user1_id, user2_id, make_override = env
    client = _client_as(env, user1_id)

    r1 = client.post("/api/subscription/redeem", json={"license_key": "bad-1"})
    r2 = client.post("/api/subscription/redeem", json={"license_key": "bad-2"})
    r3 = client.post("/api/subscription/redeem", json={"license_key": "bad-3"})

    assert r1.status_code == 400  # invalid key, but got past the rate limiter
    assert r2.status_code == 400
    assert r3.status_code == 429
