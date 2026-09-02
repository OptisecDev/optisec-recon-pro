"""
Regression tests for the license-activation role-gate bug fix
(web/app.py POST /license/activate and POST /license/deactivate).

These two routes previously called require_admin(user) before any
CSRF/rate-limit/license logic, so a normal logged-in "viewer" -- the
default role for every new registration, see web/models.py -- was
rejected with 403 "Insufficient permissions" before ever reaching license
key validation, even though activating a license the user purchased is
meant to be available to any authenticated account, not just admins.

The fix swaps require_admin(user) for require_login(user) (web/auth.py),
a new dependency-style check that only requires an authenticated user,
with no role restriction, following the same calling convention as
require_admin/require_analyst_or_admin.

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
from web.models import User
import web.app as app_module
from web import auth as auth_module

RATE_LIMIT_MAX = auth_module.RATE_LIMIT_MAX

# The web_user dependency is overridden below for the authenticated
# fixtures, bypassing the real cookie-login flow -- but the CSRF check
# reads request.cookies directly, so the client still needs a real
# (non-empty) access_token cookie set by hand, and a CSRF token computed
# from that same value.
FAKE_SESSION_COOKIE = "fixture-session-value"
CSRF_TOKEN = auth_module.generate_csrf_token(FAKE_SESSION_COOKIE)


def _run(coro):
    return asyncio.run(coro)


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
                     role="viewer", is_active=True, api_key_hash="unused-viewer"),
            ])
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
    auth_module._login_attempts.clear()
    test_client = TestClient(app_module.app)
    test_client.cookies.set("access_token", FAKE_SESSION_COOKIE)
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


# ─── (a) a "viewer" role is no longer blocked by the role check ────────────

def test_viewer_can_reach_license_activate_logic_not_blocked_by_role(viewer_client):
    resp = viewer_client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": CSRF_TOKEN},
    )
    # Must get past the role gate: an invalid key re-renders the form with
    # a flash error (200), it must NOT be the old require_admin 403
    # "Insufficient permissions" / "Access denied" rejection.
    assert resp.status_code == 200
    assert "Access denied" not in resp.text


def test_viewer_can_reach_license_deactivate_logic_not_blocked_by_role(viewer_client):
    resp = viewer_client.post(
        "/license/deactivate",
        data={"csrf_token": CSRF_TOKEN},
        follow_redirects=False,
    )
    assert resp.status_code == 302  # redirected back to /license, not 403


def test_admin_still_works_after_role_gate_swap(admin_client):
    resp = admin_client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": CSRF_TOKEN},
    )
    assert resp.status_code == 200
    assert "Access denied" not in resp.text


# ─── (b) unauthenticated requests are still rejected ───────────────────────

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


# ─── (c) CSRF and rate-limit still work exactly as before, for a viewer ────

def test_csrf_missing_token_still_rejected_for_viewer(viewer_client):
    resp = viewer_client.post("/license/activate", data={"key": "not-a-real-key"})
    assert resp.status_code == 422  # Form(...) field missing entirely


def test_csrf_wrong_token_still_rejected_for_viewer(viewer_client):
    resp = viewer_client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": "wrong-token"},
    )
    assert resp.status_code == 403


def test_rate_limit_still_works_for_viewer(viewer_client):
    for _ in range(RATE_LIMIT_MAX):
        resp = viewer_client.post(
            "/license/activate",
            data={"key": "not-a-real-key", "csrf_token": CSRF_TOKEN},
        )
        assert resp.status_code == 200

    resp = viewer_client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": CSRF_TOKEN},
    )
    assert resp.status_code == 429
