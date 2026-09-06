"""
Tests for CSRF protection on /license/activate and /license/deactivate
(web/app.py). These are the two state-changing endpoints that are (a)
authenticated purely via the session's access_token cookie and (b)
submitted by a plain HTML <form method="POST"> in web/templates/license.html
-- exactly the combination a cross-site form/fetch("...", {credentials:
"include"}) on an attacker-controlled page can replay, since a browser
attaches cookies automatically to a cross-site form submission (SameSite
=lax adds a second layer of defense against that specific case, but the
HMAC token here is what defends against SameSite being bypassed or
misconfigured).

web.auth.generate_csrf_token()/verify_csrf_token() implement a stateless
double-submit-style token: an HMAC of a dedicated `csrf_secret` cookie's
value. license.html embeds it as a hidden form field; app.py recomputes it
from the request's own csrf_secret cookie and rejects the POST if the
submitted value doesn't match. An attacker page can force the cookie to
be sent but can't read it (httponly) to compute a matching token.

--- Why csrf_secret is a *separate* cookie from access_token -----------------

Originally the CSRF token was bound to the access_token JWT cookie's exact
value. That broke under normal use: web/app.py's session_refresh_middleware
re-mints access_token (new `exp`, new JWT signature bytes) on *every*
request that returns < 400, to implement a sliding 30-minute session. So a
token embedded in a /license page at GET time was already stale by the
time of a POST if literally anything else touched the cookie in between --
another tab, a background request, or just enough elapsed time for the
slide to have happened -- not merely the "re-login in another tab" edge
case. Any authenticated user activating a license from a tab that had sat
open for a bit, or that wasn't the most recently active tab, could hit a
dead-end "Access denied" 403.

The fix (see web/auth.py generate_csrf_secret() and web/app.py
CSRF_COOKIE_NAME) introduces a separate `csrf_secret` cookie: a random
value minted once at login and left untouched by the sliding-session
middleware (which now only extends its `max_age`, never its value). A
CSRF token bound to it stays valid for as long as the session itself is
alive, regardless of how many times access_token gets rotated underneath
it. It only changes on a fresh login (correct: a new login is a new
session and should invalidate old tokens) or logout.

For that one remaining case -- a stale tab left open across a fresh login
elsewhere -- a CSRF mismatch no longer renders a dead-end error page: the
POST handlers catch it specifically and re-render /license with a fresh
token and an inline "session was refreshed" message (see
test_csrf_retry_on_stale_token below), rather than FastAPI's generic 403
"Access denied" error page (reserved for actual 403s, e.g. role checks).

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
# directly, so the client still needs a real (non-empty) csrf_secret
# cookie set by hand. verify_csrf_token() deliberately rejects an empty
# session value, since a real browser session always carries a real
# cookie. access_token is set too since it's what the (unoverridden) auth
# dependency and the sliding-session middleware key off of.
FAKE_SESSION_COOKIE = "fixture-session-value"
FAKE_CSRF_SECRET = "fixture-csrf-secret-value"
VALID_CSRF_TOKEN = auth_module.generate_csrf_token(FAKE_CSRF_SECRET)


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
    test_client.cookies.set("csrf_secret", FAKE_CSRF_SECRET)
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
    # A real browser session always carries a non-empty csrf_secret
    # cookie; an empty session value means "not actually logged in via
    # cookie" and must never verify, even if someone submits the token
    # that would otherwise match HMAC(secret, "").
    token = auth_module.generate_csrf_token("")
    assert auth_module.verify_csrf_token("", token) is False


def test_generate_csrf_secret_returns_distinct_high_entropy_values():
    a = auth_module.generate_csrf_secret()
    b = auth_module.generate_csrf_secret()
    assert a != b
    assert len(a) >= 32  # secrets.token_hex(32) -> 64 hex chars


# ─── /license page renders a usable token ──────────────────────────────────

def test_license_page_embeds_valid_csrf_token(client):
    resp = client.get("/license")
    assert resp.status_code == 200
    assert f'name="csrf_token" value="{VALID_CSRF_TOKEN}"' in resp.text


def test_license_page_mints_csrf_secret_cookie_when_missing(client):
    # A session that predates this fix (or one whose cookies were partially
    # cleared) has access_token but no csrf_secret yet. GET /license must
    # self-heal by minting one, rather than embedding a token nobody could
    # ever submit successfully.
    client.cookies.delete("csrf_secret")
    resp = client.get("/license")
    assert resp.status_code == 200
    assert "csrf_secret" in resp.cookies
    minted_secret = resp.cookies["csrf_secret"]
    expected_token = auth_module.generate_csrf_token(minted_secret)
    assert f'name="csrf_token" value="{expected_token}"' in resp.text


# ─── /license/activate ──────────────────────────────────────────────────────

def test_license_activate_without_csrf_token_is_rejected(client):
    resp = client.post("/license/activate", data={"key": "not-a-real-key"})
    assert resp.status_code == 422  # Form(...) field missing entirely


def test_license_activate_with_wrong_csrf_token_is_rejected(client):
    resp = client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": "wrong-token"},
    )
    # No longer a dead-end 403: re-renders /license with a fresh token and
    # a retry message. The activation itself must still not go through.
    assert resp.status_code == 200
    assert "session was refreshed" in resp.text
    assert "not-a-real-key" in resp.text  # key is preserved for the retry


def test_license_activate_with_valid_csrf_token_is_accepted(client):
    resp = client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": VALID_CSRF_TOKEN},
    )
    # Invalid license key -> re-renders the form with a flash error, but
    # crucially it got *past* the CSRF gate.
    assert resp.status_code == 200
    assert "session was refreshed" not in resp.text


# ─── /license/deactivate ────────────────────────────────────────────────────

def test_license_deactivate_without_csrf_token_is_rejected(client):
    resp = client.post("/license/deactivate")
    assert resp.status_code == 422


def test_license_deactivate_with_wrong_csrf_token_is_rejected(client):
    resp = client.post("/license/deactivate", data={"csrf_token": "wrong-token"})
    assert resp.status_code == 200
    assert "session was refreshed" in resp.text


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


# ─── Regression: the original staleness bug is fixed ───────────────────────
#
# These reproduce the exact bug this file's fix addresses: a CSRF token
# minted at GET /license time must still verify at POST time even after
# the access_token cookie's value has changed underneath it, as long as
# the underlying session (csrf_secret) is still the same one. Previously
# the token was bound to access_token's exact value, so any of the
# scenarios below reproduced the "Access denied" 403.

def test_csrf_token_survives_access_token_rotation_same_session(client):
    """Reproduces the diagnosed bug directly: mint a token, then simulate
    the sliding-session middleware rotating access_token to a brand new
    JWT (as it does on literally every successful request) *without* the
    csrf_secret cookie changing -- e.g. another tab was active, or enough
    time passed for the 30-minute slide. The token must still verify,
    because it was never bound to access_token in the first place."""
    resp = client.get("/license")
    assert resp.status_code == 200

    # Simulate what session_refresh_middleware does on every request:
    # access_token gets a new value, csrf_secret does not.
    client.cookies.set("access_token", "a-completely-different-rotated-jwt-value")

    resp = client.post(
        "/license/activate",
        data={"key": "not-a-real-key", "csrf_token": VALID_CSRF_TOKEN},
    )
    assert resp.status_code == 200
    assert "session was refreshed" not in resp.text  # got past the CSRF gate


def test_csrf_token_survives_long_idle_time_before_submit(client):
    """The 'long idle time before submitting' scenario: nothing about a
    token minted at GET time depends on wall-clock time now that it's
    bound to a stable secret rather than a JWT with a moving `exp`. This
    is a direct assertion that the token is still exactly what /license
    would mint fresh right now, i.e. it never goes stale on its own."""
    resp = client.get("/license")
    token_from_page_load = VALID_CSRF_TOKEN
    assert f'value="{token_from_page_load}"' in resp.text

    # No time-based invalidation: same csrf_secret -> same valid token,
    # no matter how long the user takes to submit.
    resp = client.post(
        "/license/deactivate",
        data={"csrf_token": token_from_page_load},
        follow_redirects=False,
    )
    assert resp.status_code == 302


def test_csrf_retry_on_stale_token_from_relogin_in_another_tab(client):
    """The one case that *should* still invalidate an old token -- a fresh
    login (e.g. in a second tab) mints a brand new csrf_secret, correctly
    invalidating tokens tied to the previous login/session. Verifies this
    no longer dead-ends on a generic 403 "Access denied" page: it must
    re-render /license with a working, freshly-generated token and a
    clear inline explanation, so the user can just retry immediately."""
    stale_token = VALID_CSRF_TOKEN  # minted under FAKE_CSRF_SECRET

    # Simulate a fresh login elsewhere rotating csrf_secret to a new value.
    client.cookies.set("csrf_secret", "a-brand-new-secret-from-relogin")

    resp = client.post(
        "/license/activate",
        data={"key": "some-key", "csrf_token": stale_token},
    )
    assert resp.status_code == 200
    assert "Access denied" not in resp.text
    assert "session was refreshed" in resp.text

    # The retry page must embed a token that actually verifies against the
    # *current* csrf_secret, so a second submit succeeds without the user
    # needing to reload the page.
    new_token = auth_module.generate_csrf_token("a-brand-new-secret-from-relogin")
    assert f'name="csrf_token" value="{new_token}"' in resp.text

    resp = client.post(
        "/license/activate",
        data={"key": "some-key", "csrf_token": new_token},
    )
    assert resp.status_code == 200
    assert "session was refreshed" not in resp.text


def test_csrf_secret_cookie_is_stable_across_session_refresh_middleware(client):
    """End-to-end: hit an ordinary authenticated route (which passes
    through session_refresh_middleware and rotates access_token) several
    times, then confirm a token minted before those hits is still valid --
    the middleware must never rotate csrf_secret's value, only slide its
    expiry."""
    resp = client.get("/license")
    assert resp.status_code == 200
    original_csrf_secret = client.cookies.get("csrf_secret")
    assert original_csrf_secret == FAKE_CSRF_SECRET

    for _ in range(3):
        client.get("/license")

    assert client.cookies.get("csrf_secret") == original_csrf_secret

    resp = client.post(
        "/license/deactivate",
        data={"csrf_token": VALID_CSRF_TOKEN},
        follow_redirects=False,
    )
    assert resp.status_code == 302


# ─── Expired / unauthenticated session still behaves correctly ────────────

def test_expired_session_never_reaches_csrf_check():
    """An expired/absent access_token must be rejected by authentication
    (401 -> redirect to /login) before the CSRF check ever runs -- CSRF
    failures and auth failures must stay distinguishable. Exercises the
    real (non-overridden) get_current_user dependency, unlike the `client`
    fixture above."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    TestSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = _get_db_override
    auth_module._login_attempts.clear()
    try:
        anon_client = TestClient(app_module.app)
        # No access_token cookie at all -- the "expired session" case
        # (an expired JWT is likewise rejected by jose's decode()).
        resp = anon_client.post(
            "/license/activate",
            data={"key": "not-a-real-key", "csrf_token": VALID_CSRF_TOKEN},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["location"].startswith("/login")
    finally:
        app_module.app.dependency_overrides.clear()
        auth_module._login_attempts.clear()
        _run(engine.dispose())
