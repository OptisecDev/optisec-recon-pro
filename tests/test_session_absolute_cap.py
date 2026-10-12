"""
Tests for the absolute session lifetime cap (web/auth.py, web/app.py).

The sliding refresh in session_refresh_middleware used to call
create_access_token() on every successful request, minting a brand-new
token with a fresh 24h exp -- so a session that saw any activity at least
once per idle window (or just an open tab pinging /session/heartbeat) never
ended. A cookie stolen in September stayed valid forever.

Tokens now carry an `auth_time` claim stamped once, at login, by
create_access_token(). The middleware uses refresh_access_token(), which
copies auth_time unchanged and clamps exp to auth_time + cap, and
decode_session_token() rejects any token older than the cap even if its
`exp` is still valid. Tokens minted before this change (no auth_time) are
accepted until their exp and get auth_time on their first refresh.

Time is simulated by monkeypatching time.time (via web.auth.time), which
the app, auth helpers and the TestClient cookie jar all read. jose's own
`exp` check uses the real clock, which is fine: simulated time only ever
moves forward, so exps minted in simulated time are always in the real
future and the cap is enforced by our check, which is what's under test.
"""

import asyncio
import importlib
import os
import sys
import time
from http.cookies import SimpleCookie
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
import web.app as app_module
from web import auth as auth_module
from web.auth import SECRET_KEY, ALGORITHM

HOUR = 3600
DAY = 24 * HOUR
CAP = auth_module.ABSOLUTE_MAX_SECONDS
IDLE = auth_module.ACCESS_TOKEN_EXPIRE_MINUTES * 60


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def clock(monkeypatch):
    """Simulated wall clock, starting at the real current time."""
    state = {"now": float(int(time.time()))}
    monkeypatch.setattr(auth_module.time, "time", lambda: state["now"])

    class _Clock:
        @property
        def now(self) -> int:
            return int(state["now"])

        def advance(self, seconds: float) -> None:
            state["now"] += seconds

    return _Clock()


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

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = _get_db_override
    auth_module._login_attempts.clear()
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    auth_module._login_attempts.clear()
    _run(engine.dispose())


PASSWORD = "StrongPass1!"


def _register(client, username="capuser"):
    payload = {"username": username, "email": f"{username}@example.com", "password": PASSWORD}
    resp = client.post("/register", data=payload, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    return resp


def _claims(token):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def _set_cookies(resp):
    """Parse every Set-Cookie header into {name: morsel}."""
    out = {}
    for header in resp.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        parsed.load(header)
        out.update(parsed)
    return out


def _mint(sub, role="viewer", **claims):
    return jwt.encode({"sub": str(sub), "role": role, **claims}, SECRET_KEY, algorithm=ALGORITHM)


def _user_id(client):
    return int(_claims(client.cookies.get("access_token"))["sub"])


# ─── a. September regression: activity alone no longer keeps a session alive forever

def _ride_session_to_just_before_cap(client, clock):
    _register(client)
    reg_time = clock.now
    assert _claims(client.cookies.get("access_token"))["auth_time"] == reg_time

    previous = client.cookies.get("access_token")
    elapsed = 0
    while elapsed + 20 * HOUR <= 6.5 * DAY:
        clock.advance(20 * HOUR)
        elapsed += 20 * HOUR
        resp = client.get("/session/heartbeat", follow_redirects=False)
        assert resp.status_code == 204
        assert "access_token" in _set_cookies(resp), "heartbeat inside the idle window must slide the cookie"
        current = client.cookies.get("access_token")
        assert current != previous
        assert _claims(current)["auth_time"] == reg_time
        previous = current
    return reg_time


def test_active_session_slides_but_keeps_registration_auth_time(client, clock):
    _ride_session_to_just_before_cap(client, clock)


# ─── b. ...and is logged out at exactly the cap, not before

def test_active_session_is_logged_out_at_absolute_cap(client, clock):
    reg_time = _ride_session_to_just_before_cap(client, clock)

    # Still active right up to the cap: once within one idle window of it,
    # each refresh clamps exp (and the cookie max_age) to the cap.
    for at in (CAP - 8 * HOUR, CAP - HOUR, CAP - 1):
        clock.advance(reg_time + at - clock.now)
        resp = client.get("/session/heartbeat", follow_redirects=False)
        assert resp.status_code == 204
        cookie = _set_cookies(resp)["access_token"]
        assert _claims(cookie.value)["exp"] == reg_time + CAP
        assert int(cookie["max-age"]) == CAP - at
    last_token = client.cookies.get("access_token")

    clock.advance(reg_time + CAP + 1 - clock.now)

    # The cookie jar has already expired the cookie (max_age was clamped to
    # the cap), so a browser-like client is simply logged out...
    resp = client.get("/session/heartbeat", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("/login")

    # ...and the server rejects the token even if a client replays it.
    client.cookies.clear()
    cookie_header = {"Cookie": f"access_token={last_token}"}
    resp = client.get("/session/heartbeat", headers=cookie_header, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("/login")
    assert "access_token" not in _set_cookies(resp)

    resp = client.get("/api/scans", headers=cookie_header)
    assert resp.status_code == 401
    assert "access_token" not in _set_cookies(resp)


# ─── c. /login must show the form, not bounce a capped session back to /

def test_login_page_shows_form_for_capped_token(client, clock):
    _register(client)
    uid = _user_id(client)
    client.cookies.clear()
    capped = _mint(uid, auth_time=clock.now - 8 * DAY, exp=clock.now + HOUR)

    resp = client.get("/login", headers={"Cookie": f"access_token={capped}"}, follow_redirects=False)
    assert resp.status_code == 200
    assert 'name="password"' in resp.text
    assert "access_token" not in _set_cookies(resp)


# ─── d. Old/stolen cookie with a still-valid exp is rejected on every auth path

@pytest.fixture
def capped_token(client, clock):
    _register(client)
    uid = _user_id(client)
    client.cookies.clear()
    return _mint(uid, auth_time=clock.now - 8 * DAY, exp=clock.now + HOUR)


def test_capped_token_rejected_via_cookie(client, capped_token):
    resp = client.get("/api/scans", headers={"Cookie": f"access_token={capped_token}"})
    assert resp.status_code == 401
    assert resp.json() == {"error": "Invalid or expired token"}


def test_capped_token_rejected_via_bearer(client, capped_token):
    resp = client.get("/api/scans", headers={"Authorization": f"Bearer {capped_token}"})
    assert resp.status_code == 401
    assert resp.json() == {"error": "Invalid or expired token"}


def test_capped_token_rejected_via_websocket_bearer(capped_token):
    ws = SimpleNamespace(headers={"authorization": f"Bearer {capped_token}"}, cookies={})
    with pytest.raises(HTTPException) as exc:
        _run(auth_module.get_ws_user(ws, db=None))
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid or expired token"


def test_get_current_user_rejects_capped_token_directly(capped_token):
    req = SimpleNamespace(headers={}, cookies={"access_token": capped_token})
    with pytest.raises(HTTPException) as exc:
        _run(auth_module.get_current_user(req, db=None))
    assert exc.value.status_code == 401


def test_decode_session_token_rejects_non_int_auth_time(clock):
    token = _mint(1, auth_time="yesterday", exp=clock.now + HOUR)
    with pytest.raises(auth_module.JWTError):
        auth_module.decode_session_token(token)


# ─── e. The middleware can never reset auth_time

def test_refresh_access_token_keeps_auth_time_constant(clock):
    payload = _claims(auth_module.create_access_token(7, "analyst"))
    auth_time = payload["auth_time"]
    for _ in range(20):
        clock.advance(10 * HOUR)
        token = auth_module.refresh_access_token(payload)
        if clock.now >= auth_time + CAP:
            assert token is None
            break
        payload = _claims(token)
        assert payload["auth_time"] == auth_time
        assert payload["sub"] == "7" and payload["role"] == "analyst"
        assert payload["exp"] == min(clock.now + IDLE, auth_time + CAP)
    else:
        pytest.fail("refresh never hit the cap")


def test_fifty_requests_never_move_auth_time_or_exceed_cap(client, clock):
    _register(client)
    auth_time = clock.now
    for _ in range(50):
        clock.advance(HOUR)
        resp = client.get("/session/heartbeat", follow_redirects=False)
        assert resp.status_code == 204
        cookies = _set_cookies(resp)
        claims = _claims(cookies["access_token"].value)
        assert claims["auth_time"] == auth_time
        assert claims["exp"] <= auth_time + CAP
        assert int(cookies["access_token"]["max-age"]) <= auth_time + CAP - clock.now


# ─── f. A fresh login does start a new session

def test_fresh_login_resets_auth_time(client, clock):
    _register(client)
    first = _claims(client.cookies.get("access_token"))["auth_time"]

    clock.advance(5 * DAY)
    client.cookies.clear()
    resp = client.post("/login", data={"username": "capuser", "password": PASSWORD}, follow_redirects=False)
    assert resp.status_code == 302
    second = _claims(_set_cookies(resp)["access_token"].value)["auth_time"]
    assert second == clock.now
    assert second == first + 5 * DAY


# ─── g. Pre-deploy tokens (no auth_time) -- Option C

def test_legacy_token_without_auth_time_is_accepted_then_stamped(client, clock):
    _register(client)
    uid = _user_id(client)
    client.cookies.clear()
    legacy = _mint(uid, exp=clock.now + 10 * HOUR)
    client.cookies.set("access_token", legacy)

    resp = client.get("/api/scans")
    assert resp.status_code == 200
    stamped = _claims(_set_cookies(resp)["access_token"].value)["auth_time"]
    assert stamped == clock.now

    for _ in range(3):
        clock.advance(HOUR)
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        assert _claims(_set_cookies(resp)["access_token"].value)["auth_time"] == stamped


def test_legacy_token_past_exp_is_rejected(client, clock):
    _register(client)
    uid = _user_id(client)
    client.cookies.clear()
    expired = _mint(uid, exp=int(time.time()) - 60)
    resp = client.get("/api/scans", headers={"Cookie": f"access_token={expired}"})
    assert resp.status_code == 401


# ─── h. Config precedence and the startup guard

_JWT_ENV = ("JWT_IDLE_HOURS", "JWT_EXPIRE_HOURS", "JWT_ABSOLUTE_MAX_HOURS", "JWT_EXPIRE_MINUTES")


@pytest.fixture
def reload_config(monkeypatch):
    import config
    for name in _JWT_ENV:
        monkeypatch.delenv(name, raising=False)

    def _reload(**env):
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        return importlib.reload(config)

    yield _reload
    monkeypatch.undo()
    importlib.reload(config)


def test_config_defaults(reload_config):
    cfg = reload_config()
    assert cfg.JWT_IDLE_HOURS == 24
    assert cfg.JWT_EXPIRE_HOURS == 24
    assert cfg.JWT_ABSOLUTE_MAX_HOURS == 168


def test_config_legacy_jwt_expire_hours_alone_sets_idle(reload_config):
    cfg = reload_config(JWT_EXPIRE_HOURS="12")
    assert cfg.JWT_IDLE_HOURS == 12
    assert cfg.JWT_EXPIRE_HOURS == 12


def test_config_jwt_idle_hours_wins_over_legacy(reload_config):
    cfg = reload_config(JWT_EXPIRE_HOURS="12", JWT_IDLE_HOURS="6")
    assert cfg.JWT_IDLE_HOURS == 6
    assert cfg.JWT_EXPIRE_HOURS == 6


def test_config_refuses_cap_not_greater_than_idle(reload_config):
    with pytest.raises(RuntimeError, match="JWT_ABSOLUTE_MAX_HOURS"):
        reload_config(JWT_ABSOLUTE_MAX_HOURS="24", JWT_IDLE_HOURS="24")


def test_config_refuses_cap_below_large_jwt_expire_minutes(reload_config):
    with pytest.raises(RuntimeError, match="JWT_ABSOLUTE_MAX_HOURS"):
        reload_config(JWT_EXPIRE_MINUTES=str(200 * 60))


# ─── i. CSRF cookie follows the cap

def test_csrf_cookie_max_age_clamped_and_not_slid_after_cap(client, clock):
    auth_time = _ride_session_to_just_before_cap(client, clock)
    assert client.cookies.get("csrf_secret")

    clock.advance(auth_time + CAP - 6 * HOUR - clock.now)
    resp = client.get("/session/heartbeat", follow_redirects=False)
    assert resp.status_code == 204
    cookies = _set_cookies(resp)
    assert int(cookies["csrf_secret"]["max-age"]) == auth_time + CAP - clock.now
    assert int(cookies["access_token"]["max-age"]) == auth_time + CAP - clock.now

    # Past the cap (replaying the cookies a browser would already have dropped):
    token = client.cookies.get("access_token")
    secret = client.cookies.get("csrf_secret")
    clock.advance(6 * HOUR + 1)
    client.cookies.clear()
    resp = client.get("/", headers={"Cookie": f"access_token={token}; csrf_secret={secret}"}, follow_redirects=False)
    cookies = _set_cookies(resp)
    assert "csrf_secret" not in cookies
    assert "access_token" not in cookies


def test_refresh_returns_none_exactly_at_cap(clock):
    payload = _claims(auth_module.create_access_token(1, "viewer"))
    clock.advance(CAP)
    assert auth_module.refresh_access_token(payload) is None


def test_middleware_reissues_nothing_at_exact_cap(client, clock):
    """At auth_time + cap the token still authenticates this one request
    (the cap check is strictly greater-than) but refresh_access_token()
    returns None, and the middleware must then set no cookies at all --
    in particular it must not fall back to minting a fresh login token."""
    _register(client)
    uid = _user_id(client)
    client.cookies.clear()
    at_cap = _mint(uid, auth_time=clock.now - CAP, exp=clock.now + HOUR)
    resp = client.get("/api/scans", headers={"Cookie": f"access_token={at_cap}; csrf_secret=s3cret"})
    assert resp.status_code == 200
    cookies = _set_cookies(resp)
    assert "access_token" not in cookies
    assert "csrf_secret" not in cookies
