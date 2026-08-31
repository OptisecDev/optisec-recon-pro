"""
Tests for CSRF protection on /license/activate and /license/deactivate
(web/app.py). These are the two state-changing endpoints that are (a)
authenticated purely via the session's access_token cookie and (b)
submitted by a plain HTML <form method="POST"> in web/templates/license.html
-- exactly the combination a cross-site form/fetch("...", {credentials:
"include"}) on an attacker-controlled page can replay, since a browser
attaches cookies automatically to a cross-site form submission.

web.auth.generate_csrf_token()/verify_csrf_token() implement a stateless
double-submit-style token: an HMAC of the caller's access_token cookie
value. license.html embeds it as a hidden form field; app.py recomputes it
from the request's own access_token cookie and rejects the POST with 403
if the submitted value doesn't match. An attacker page can force the
cookie to be sent but can't read it (httponly) to compute a matching
token.

/api/license/activate and /api/license/generate are pure JSON endpoints
(request.json(), not Form(...)) meant to be called programmatically with
an X-API-Key or Authorization header -- out of scope for this CSRF fix,
per web.auth.get_current_user's header-first precedence, and left
untouched here.

Same TestClient + dependency-override approach as
tests/test_license_activate_rate_limit.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
from web.models import User
import web.app as app_module
from web import auth as auth_module

# The web_user dependency is overridden in the fixture below, bypassing the
# real cookie-login flow -- but the CSRF check reads request.cookies
# directly, so the client still needs a real (non-empty) access_token
# cookie set by hand. verify_csrf_token() deliberately rejects an empty
# session value, since a real browser session always carries a real cookie.
FAKE_SESSION_COOKIE = "fixture-session-value"
VALID_CSRF_TOKEN = auth_module.generate_csrf_token(FAKE_SESSION_COOKIE)


def _run(coro):
    return asyncio.run(coro)


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
            admin = User(
                username="admin", email="admin@example.com", password_hash="x",
                role="admin", is_active=True, api_key_hash="unused",
            )
            session.add(admin)
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _admin_user_override():
        async with TestSessionLocal() as session:
            from sqlalchemy import select
            result = await session.execute(select(User).where(User.username == "admin"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[app_module.web_user] = _admin_user_override
    auth_module._login_attempts.clear()
    test_client = TestClient(app_module.app)
    test_client.cookies.set("access_token", FAKE_SESSION_COOKIE)
    yield test_client
    app_module.app.dependency_overrides.clear()
    auth_module._login_attempts.clear()
    _run(engine.dispose())


# ─── Token generation / verification helpers ───────────────────────────────

def test_csrf_token_is_deterministic_for_same_session_value():
    assert auth_module.generate_csrf_token("abc") == auth_module.generate_csrf_token("abc")


def test_csrf_token_differs_across_sessions():
    assert auth_module.generate_csrf_token("abc") != auth_module.generate_csrf_token("xyz")


def test_verify_csrf_token_accepts_matching_token():
    token = auth_module.generate_csrf_token("session-value")
    assert auth_module.verify_csrf_token("session-value", token) is True


def test_verify_csrf_token_rejects_forged_token():
    assert auth_module.verify_csrf_token("session-value", "0" * 64) is False


def test_verify_csrf_token_rejects_empty_submission():
    token = auth_module.generate_csrf_token("session-value")
    assert auth_module.verify_csrf_token("session-value", "") is False


def test_verify_csrf_token_rejects_empty_session_even_with_matching_token():
    # A real browser session always carries a non-empty access_token
    # cookie; an empty session value means "not actually logged in via
    # cookie" and must never verify, even if someone submits the token
    # that would otherwise match HMAC(secret, "").
    token = auth_module.generate_csrf_token("")
    assert auth_module.verify_csrf_token("", token) is False


# ─── /license page renders a usable token ──────────────────────────────────

def test_license_page_embeds_valid_csrf_token(client):
    resp = client.get("/license")
    assert resp.status_code == 200
    assert f'name="csrf_token" value="{VALID_CSRF_TOKEN}"' in resp.text


# ─── /license/activate ──────────────────────────────────────────────────────

def test_license_activate_without_csrf_token_is_rejected(client):
    resp = client.post("/license/activate", data={"key": "not-a-real-key"})
    assert resp.status_code == 422  # Form(...) field missing entirely


def test_license_activate_with_wrong_csrf_token_is_rejected(client):
    resp = client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": "wrong-token"},
    )
    assert resp.status_code == 403


def test_license_activate_with_valid_csrf_token_is_accepted(client):
    resp = client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": VALID_CSRF_TOKEN},
    )
    # Invalid license key -> re-renders the form with a flash error, but
    # crucially it got *past* the CSRF gate (not a 403).
    assert resp.status_code == 200
    assert resp.status_code != 403


# ─── /license/deactivate ────────────────────────────────────────────────────

def test_license_deactivate_without_csrf_token_is_rejected(client):
    resp = client.post("/license/deactivate")
    assert resp.status_code == 422


def test_license_deactivate_with_wrong_csrf_token_is_rejected(client):
    resp = client.post("/license/deactivate", data={"csrf_token": "wrong-token"})
    assert resp.status_code == 403


def test_license_deactivate_with_valid_csrf_token_is_accepted(client):
    resp = client.post(
        "/license/deactivate", data={"csrf_token": VALID_CSRF_TOKEN}, follow_redirects=False,
    )
    assert resp.status_code == 302  # redirected back to /license, not 403


# ─── JSON API siblings stay untouched (out of CSRF scope) ─────────────────

def test_json_license_activate_api_has_no_csrf_requirement(client):
    # Pure JSON endpoint, called programmatically -- must keep working
    # with no csrf_token field at all.
    resp = client.post("/api/license/activate", json={"key": "not-a-real-key"})
    assert resp.status_code == 422  # rejected for being an invalid key, not CSRF
