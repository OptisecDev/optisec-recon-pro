"""
Ownership / IDOR regression coverage for the core Targets CRUD routes in
web/app.py (GET /targets, POST /targets/add, DELETE /targets/{target_id}).

Added during the Targets feature audit (2026-09-07): there was no dedicated
test file for these routes at all (only a generic "page renders 200" smoke
test in test_app_own_pages_render.py). This does not change any production
code -- it only documents/locks in current behavior so a future change can't
silently reintroduce an IDOR on target deletion.

Same TestClient + in-memory-SQLite + _seed_user_token pattern as
tests/test_app_own_pages_render.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.app as app_module
import web.rate_limit as rate_limit
from web.database import Base, get_db
from web.models import User, Target
from web.auth import create_access_token, hash_password
from web import auth as auth_module

# DELETE /targets/{id} now requires the same cookie-bound CSRF token as
# /license (web/app.py CSRF_COOKIE_NAME / verify_csrf_token) -- these tests
# predate that change, so they need a real (non-empty) csrf_secret cookie
# plus a matching X-CSRF-Token header, same fixture pattern as
# tests/test_csrf_protection.py.
FAKE_CSRF_SECRET = "targets-idor-fixture-csrf-secret"
VALID_CSRF_TOKEN = auth_module.generate_csrf_token(FAKE_CSRF_SECRET)


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    """POST /targets/add is rate-limited (web/rate_limit.py, shared
    module-level state) -- without this, an earlier test's requests from
    "testclient" bleed into the next test's limit. Same pattern as
    tests/test_payment_rate_limit.py."""
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
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db
    c = TestClient(app_module.app)
    yield c, session_factory
    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def _seed_user_token(session_factory, username: str, role: str = "analyst", subscription_tier: str = "enterprise") -> tuple:
    async def go():
        async with session_factory() as db:
            user = User(
                username=username, email=f"{username}@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role=role, subscription_tier=subscription_tier, is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id
    user_id = _run(go())
    return user_id, create_access_token(user_id, role)


def _seed_target(session_factory, user_id: int, url: str = "https://victim-owned.example") -> int:
    async def go():
        async with session_factory() as db:
            t = Target(user_id=user_id, url=url, name="victim target", notes="")
            db.add(t)
            await db.commit()
            await db.refresh(t)
            return t.id
    return _run(go())


def _target_still_exists(session_factory, target_id: int) -> bool:
    async def go():
        async with session_factory() as db:
            from sqlalchemy import select
            row = (await db.execute(select(Target).where(Target.id == target_id))).scalar_one_or_none()
            return row is not None
    return _run(go())


def test_delete_target_owned_by_another_user_is_rejected(client):
    """IDOR check: user B must not be able to delete user A's target by
    guessing/incrementing target_id in DELETE /targets/{target_id}."""
    c, session_factory = client
    victim_id, _ = _seed_user_token(session_factory, "victim")
    _, attacker_token = _seed_user_token(session_factory, "attacker")
    target_id = _seed_target(session_factory, victim_id)

    resp = c.delete(
        f"/targets/{target_id}",
        cookies={"access_token": attacker_token, "csrf_secret": FAKE_CSRF_SECRET},
        headers={"X-CSRF-Token": VALID_CSRF_TOKEN},
    )

    assert resp.status_code == 404, (
        f"expected 404 (not found / not owned), got {resp.status_code}: {resp.text[:300]}"
    )
    assert _target_still_exists(session_factory, target_id), (
        "target belonging to another user was deleted -- IDOR on DELETE /targets/{target_id}"
    )


def test_delete_own_target_succeeds(client):
    """Sanity check for the negative test above: the owning user can still
    delete their own target through the same route."""
    c, session_factory = client
    owner_id, owner_token = _seed_user_token(session_factory, "owner")
    target_id = _seed_target(session_factory, owner_id)

    resp = c.delete(
        f"/targets/{target_id}",
        cookies={"access_token": owner_token, "csrf_secret": FAKE_CSRF_SECRET},
        headers={"X-CSRF-Token": VALID_CSRF_TOKEN},
    )

    assert resp.status_code == 200, resp.text[:300]
    assert not _target_still_exists(session_factory, target_id)


def test_delete_own_target_rejects_missing_or_invalid_csrf(client):
    """S2: DELETE /targets/{id} must enforce the same CSRF check as POST
    /targets/add, independent of ownership -- a valid owner with no/forged
    X-CSRF-Token must still be rejected."""
    c, session_factory = client
    owner_id, owner_token = _seed_user_token(session_factory, "csrflessdeleter")
    target_id = _seed_target(session_factory, owner_id)

    # No X-CSRF-Token header at all.
    resp_missing = c.delete(
        f"/targets/{target_id}",
        cookies={"access_token": owner_token, "csrf_secret": FAKE_CSRF_SECRET},
    )
    assert resp_missing.status_code == 403, resp_missing.text[:300]

    # Wrong X-CSRF-Token header.
    resp_wrong = c.delete(
        f"/targets/{target_id}",
        cookies={"access_token": owner_token, "csrf_secret": FAKE_CSRF_SECRET},
        headers={"X-CSRF-Token": "not-the-real-token"},
    )
    assert resp_wrong.status_code == 403, resp_wrong.text[:300]

    assert _target_still_exists(session_factory, target_id), (
        "target was deleted despite a missing/invalid CSRF token"
    )


def _add_target(c, token, url, csrf_token=VALID_CSRF_TOKEN, csrf_secret=FAKE_CSRF_SECRET):
    return c.post(
        "/targets/add",
        data={"url": url, "name": "", "notes": "", "csrf_token": csrf_token},
        cookies={"access_token": token, "csrf_secret": csrf_secret},
    )


def test_add_target_rejects_missing_or_invalid_csrf(client):
    c, session_factory = client
    _, token = _seed_user_token(session_factory, "csrfless")

    resp = _add_target(c, token, "https://ok.example", csrf_token="not-the-real-token")

    assert resp.status_code == 403
    assert resp.json()["success"] is False


def test_add_target_rejects_ssrf_local_and_private_hosts(client):
    """S3: POST /targets/add must reject targets pointing at localhost,
    loopback, the cloud metadata address, and RFC1918 private ranges."""
    c, session_factory = client
    _, token = _seed_user_token(session_factory, "ssrftest")

    for bad_url in [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "127.0.0.1",  # bare host (no scheme), still resolved via the https:// prepend path
    ]:
        resp = _add_target(c, token, bad_url)
        assert resp.status_code == 400, f"{bad_url!r} should be rejected, got {resp.status_code}: {resp.text[:200]}"
        assert resp.json()["success"] is False


def test_add_target_rejects_disallowed_url_schemes(client):
    """S3: only http:// and https:// target URLs may be added -- file://
    and other schemes must be rejected even when the hostname itself
    isn't a local/private address."""
    c, session_factory = client
    _, token = _seed_user_token(session_factory, "schemetest")

    for bad_url in [
        "file:///etc/passwd",
        "file://attacker.example/x",
        "ftp://attacker.example/",
    ]:
        resp = _add_target(c, token, bad_url)
        assert resp.status_code == 400, f"{bad_url!r} should be rejected, got {resp.status_code}: {resp.text[:200]}"
        assert resp.json()["success"] is False


def test_add_target_allows_ordinary_public_host(client):
    c, session_factory = client
    _, token = _seed_user_token(session_factory, "normaladd")

    resp = _add_target(c, token, "https://tesla.com")

    assert resp.status_code == 200, resp.text[:300]
    assert resp.json()["success"] is True


def test_add_target_rejects_over_max_targets_limit(client):
    """S1: max_targets must come from the requesting user's own
    subscription_tier (web.license.TIER_LIMITS, free=3) -- a free-tier
    user at their limit gets a clear 403, not an unlimited add."""
    c, session_factory = client
    owner_id, owner_token = _seed_user_token(session_factory, "capped", subscription_tier="free")
    _seed_target(session_factory, owner_id, url="https://one.example")
    _seed_target(session_factory, owner_id, url="https://two.example")
    _seed_target(session_factory, owner_id, url="https://three.example")

    resp = _add_target(c, owner_token, "https://four.example")

    assert resp.status_code == 403
    assert resp.json()["success"] is False


def test_add_target_unlimited_tier_bypasses_max_targets_check(client):
    c, session_factory = client
    owner_id, owner_token = _seed_user_token(session_factory, "unlimited", subscription_tier="enterprise")
    for i in range(5):
        _seed_target(session_factory, owner_id, url=f"https://existing-{i}.example")

    resp = _add_target(c, owner_token, "https://sixth.example")

    assert resp.status_code == 200, resp.text[:300]


def test_add_target_instance_wide_license_does_not_override_per_user_free_limit(client, monkeypatch):
    """S1 regression: an active instance-wide PRO/enterprise license (e.g.
    data/license.json, activated via /license for the installation) must
    NOT let a free-tier account exceed its own plan's target cap -- this
    mirrors the exact per-user-vs-instance-wide bug already fixed for
    require_feature_or_402 (see web/license.py's module docstring). Before
    the fix, /targets/add read get_license() (instance-wide) instead of
    the requesting user's own subscription_tier, so every user on an
    installation with an active PRO license got the 50-target PRO cap
    regardless of their individual tier."""
    c, session_factory = client
    owner_id, owner_token = _seed_user_token(session_factory, "freeuser", subscription_tier="free")
    _seed_target(session_factory, owner_id, url="https://one.example")
    _seed_target(session_factory, owner_id, url="https://two.example")
    _seed_target(session_factory, owner_id, url="https://three.example")

    from datetime import datetime, timedelta
    from web.license import License
    instance_pro_lic = License(
        tier="pro", issued_to="t", email="", issued_at=datetime.utcnow().isoformat(),
        expires_at=(datetime.utcnow() + timedelta(days=1)).isoformat(), key="OPS4-PRO-x",
        features=[], max_targets=50, max_scans_day=500, max_users=5,
    )
    monkeypatch.setattr(app_module, "get_license", lambda: instance_pro_lic)

    resp = _add_target(c, owner_token, "https://four.example")

    assert resp.status_code == 403, (
        "free-tier user was allowed past their own limit because the instance-wide "
        f"license is PRO -- got {resp.status_code}: {resp.text[:300]}"
    )
    assert resp.json()["success"] is False


def test_add_target_is_rate_limited(client):
    """S1: POST /targets/add caps requests per IP (default 10/min, see
    RATE_LIMIT_TARGETS_ADD / _targets_add_limiter in web/app.py)."""
    c, session_factory = client
    _, token = _seed_user_token(session_factory, "spammer")

    last_status = None
    for i in range(11):
        last_status = _add_target(c, token, f"https://spam-{i}.example").status_code

    assert last_status == 429


def test_targets_list_page_does_not_leak_other_users_targets(client):
    """IDOR check on the listing itself: GET /targets must be scoped to
    Target.user_id == current_user.id, never show every user's targets."""
    c, session_factory = client
    victim_id, _ = _seed_user_token(session_factory, "victim2")
    _, viewer_token = _seed_user_token(session_factory, "onlooker", role="viewer")
    _seed_target(session_factory, victim_id, url="https://should-not-leak.example")

    resp = c.get("/targets", cookies={"access_token": viewer_token})

    assert resp.status_code == 200
    assert "should-not-leak.example" not in resp.text
