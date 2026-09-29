"""
Regression tests for the license-route access-control fix (web/app.py
GET /license, POST /license/activate, POST /license/deactivate).

Prior state (introduced by e433df3, "Fix license activate/deactivate:
allow any logged-in user, not just admin", 2026-09-02): the two POST
routes had been swapped from require_admin(user) to require_login(user)
(any authenticated user, any role) in a fix aimed at unblocking a
*different* flow -- a regular user activating a license key they'd
personally purchased. But activate_license()/deactivate_license()
(web/license.py) operate on the single instance-wide license file
(data/license.json), shared by every account on the installation, not a
per-user record. The per-user purchase flow that fix was actually meant
to unblock lives entirely separately, at POST /api/subscription/redeem
(web/routers/license_routes.py), which upgrades only the calling
account's own User.subscription_tier and was never gated by
require_admin/require_login in the first place. The Sept 2 fix therefore
let any FREE-tier account activate or deactivate the shared installation
license for every user -- confirmed by /api/license/activate (the JSON
API for the same action) having been require_admin-gated the entire
time, an inconsistency between the two surfaces for the identical
operation. GET /license had no role check at all on either side of that
commit.

This file now asserts the corrected behavior: all three routes require
admin, while the actual per-user purchase path (/api/subscription/redeem
and the /redeem page) remains open to any authenticated account,
untouched by this fix.

Same TestClient + dependency-override approach as
tests/test_license_activate_rate_limit.py and tests/test_csrf_protection.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy import select
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
from web.models import User, LicenseKey
import web.app as app_module
import web.routers.license_routes as lr_module
import web.rate_limit as rate_limit
from web import auth as auth_module
from license_utils import hash_license_key

RATE_LIMIT_MAX = auth_module.RATE_LIMIT_MAX

# The web_user dependency is overridden below for the authenticated
# fixtures, bypassing the real cookie-login flow -- but the CSRF check
# reads request.cookies directly, so the test client still needs a real
# (non-empty) access_token cookie set by hand, plus the dedicated
# csrf_secret cookie the CSRF token is actually bound to (see
# web/auth.py generate_csrf_secret()), and a CSRF token computed from
# that same csrf_secret value.
FAKE_SESSION_COOKIE = "fixture-session-value"
FAKE_CSRF_SECRET = "fixture-csrf-secret-value"
CSRF_TOKEN = auth_module.generate_csrf_token(FAKE_CSRF_SECRET)


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    """/api/subscription/redeem is rate-limited (web/rate_limit.py, shared
    module-level state) -- same pattern as
    tests/test_subscription_redeem_controls.py."""
    rate_limit._buckets.clear()
    yield
    rate_limit._buckets.clear()


@pytest.fixture
def db_engine():
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
            session.add_all([
                User(username="admin", email="admin@example.com", password_hash="x",
                     role="admin", is_active=True, api_key_hash="unused-admin"),
                User(username="viewer", email="viewer@example.com", password_hash="x",
                     role="viewer", subscription_tier="free", is_active=True,
                     api_key_hash="unused-viewer"),
            ])
            session.add(LicenseKey(
                key_hash=hash_license_key("PERSONAL-KEY-1"), tier="pro",
            ))
            await session.commit()

    _run(_setup())
    yield engine, TestSessionLocal
    _run(engine.dispose())


def _authenticated_client(db_engine, username):
    engine, TestSessionLocal = db_engine

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == username))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[app_module.web_user] = _user_override
    # license_routes.py's /api/subscription/redeem and /redeem page use
    # their own local `_user`/`_user_optional` dependencies (not
    # app_module.web_user), so overriding just the latter leaves them
    # exercising the real JWT/cookie flow, which the fixture's fake
    # session cookie can't satisfy -- override them too.
    app_module.app.dependency_overrides[lr_module._user] = _user_override
    app_module.app.dependency_overrides[lr_module._user_optional] = _user_override
    auth_module._login_attempts.clear()
    test_client = TestClient(app_module.app)
    test_client.cookies.set("access_token", FAKE_SESSION_COOKIE)
    test_client.cookies.set("csrf_secret", FAKE_CSRF_SECRET)
    return test_client


@pytest.fixture
def viewer_client(db_engine):
    client = _authenticated_client(db_engine, "viewer")
    yield client
    app_module.app.dependency_overrides.clear()
    auth_module._login_attempts.clear()


@pytest.fixture
def admin_client(db_engine):
    client = _authenticated_client(db_engine, "admin")
    yield client
    app_module.app.dependency_overrides.clear()
    auth_module._login_attempts.clear()


@pytest.fixture
def anon_client(db_engine):
    # No web_user override, no cookie: exercises the real get_current_user
    # dependency chain, which is what actually rejects unauthenticated
    # callers (401 -> redirected to /login by app.py's exception handler).
    engine, TestSessionLocal = db_engine

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = _get_db_override
    auth_module._login_attempts.clear()
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    auth_module._login_attempts.clear()


# ─── A non-admin ("viewer"/FREE) account is rejected on all three routes ────

def test_viewer_cannot_view_license_page(viewer_client):
    resp = viewer_client.get("/license")
    assert resp.status_code == 403
    assert "Access denied" in resp.text


def test_viewer_cannot_activate_instance_license(viewer_client):
    resp = viewer_client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": CSRF_TOKEN},
    )
    assert resp.status_code == 403
    assert "Access denied" in resp.text


def test_viewer_cannot_deactivate_instance_license(viewer_client):
    resp = viewer_client.post(
        "/license/deactivate",
        data={"csrf_token": CSRF_TOKEN},
    )
    assert resp.status_code == 403
    assert "Access denied" in resp.text


# ─── An admin account still has full access to all three routes ────────────

def test_admin_can_view_license_page(admin_client):
    resp = admin_client.get("/license")
    assert resp.status_code == 200
    assert "Access denied" not in resp.text


def test_admin_can_reach_activate_logic(admin_client):
    resp = admin_client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": CSRF_TOKEN},
    )
    # Must get past the role gate: an invalid key re-renders the form with
    # a flash error (200), not a 403.
    assert resp.status_code == 200
    assert "Access denied" not in resp.text


def test_admin_can_reach_deactivate_logic(admin_client):
    resp = admin_client.post(
        "/license/deactivate",
        data={"csrf_token": CSRF_TOKEN},
        follow_redirects=False,
    )
    assert resp.status_code == 302  # redirected back to /license, not 403


# ─── Unauthenticated requests are still rejected (unchanged) ───────────────

def test_unauthenticated_view_is_still_rejected(anon_client):
    resp = anon_client.get("/license", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("/login")


def test_unauthenticated_activate_is_still_rejected(anon_client):
    resp = anon_client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": CSRF_TOKEN},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("/login")


def test_unauthenticated_deactivate_is_still_rejected(anon_client):
    resp = anon_client.post(
        "/license/deactivate",
        data={"csrf_token": CSRF_TOKEN},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("/login")


# ─── The separate per-user redemption flow is untouched by this fix ────────

def test_non_admin_can_still_redeem_a_personal_license_key(viewer_client):
    """POST /api/subscription/redeem (web/routers/license_routes.py) is a
    completely separate, per-user flow -- upgrading only the caller's own
    User.subscription_tier via a one-time SellApp key -- independent of
    the instance-wide engine this fix locks down. It must keep working
    for a plain non-admin account."""
    resp = viewer_client.post(
        "/api/subscription/redeem",
        json={"license_key": "PERSONAL-KEY-1"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["tier"] == "pro"


def test_redeem_page_loads_for_a_non_admin(viewer_client):
    resp = viewer_client.get("/redeem")
    assert resp.status_code == 200


# ─── CSRF and rate-limit still apply ahead of the role gate for an admin ───

def test_csrf_missing_token_rejected_for_admin(admin_client):
    resp = admin_client.post("/license/activate", data={"key": "not-a-real-key"})
    assert resp.status_code == 422  # Form(...) field missing entirely


def test_csrf_wrong_token_rejected_for_admin(admin_client):
    resp = admin_client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": "wrong-token"},
    )
    assert resp.status_code == 200
    assert "session was refreshed" in resp.text


def test_rate_limit_still_works_for_admin(admin_client):
    for _ in range(RATE_LIMIT_MAX):
        resp = admin_client.post(
            "/license/activate",
            data={"key": "not-a-real-key", "csrf_token": CSRF_TOKEN},
        )
        assert resp.status_code == 200

    resp = admin_client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": CSRF_TOKEN},
    )
    assert resp.status_code == 429
