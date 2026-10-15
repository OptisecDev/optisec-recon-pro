"""
Logout must revoke the session server-side, not just delete the browser's
cookie (web/app.py logout, web/auth.py get_current_user /
_load_user_from_bearer, web/app.py session_refresh_middleware).

Previously /logout only called delete_cookie: the JWT itself stayed valid
until its exp, so any copy of the cookie captured before logout (shared
machine, proxy log, stolen via another bug) kept working -- and
session_refresh_middleware, which re-minted any cookie whose signature
verified, would slide that stale copy forward indefinitely.

Now every token carries the user's token_version as a "tv" claim, logout
bumps the column, and both the auth path and the refresh middleware reject
a "tv" that no longer matches. Same TestClient + isolated in-memory DB
pattern as tests/test_session_cookie_secure.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
import web.app as app_module
from web import auth as auth_module
import web.migrate_add_user_token_version as token_version_migration


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


def _register_and_login(client, username="logoutuser"):
    password = "StrongPass1!"
    client.post(
        "/register",
        data={"username": username, "email": f"{username}@example.com", "password": password},
        follow_redirects=False,
    )
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    assert resp.status_code == 302
    token = resp.cookies.get("access_token") or client.cookies.get("access_token")
    assert token
    return token


# Any cookie/bearer-authenticated JSON endpoint will do; non-/api/ paths
# turn a 401 into a redirect to /login (on_http_exception).
AUTHED_API = "/api/domains"


def test_old_cookie_is_rejected_after_logout(client):
    old_token = _register_and_login(client)
    assert client.get(AUTHED_API).status_code == 200

    resp = client.get("/logout", follow_redirects=False)
    assert resp.status_code == 302

    client.cookies.clear()
    client.cookies.set("access_token", old_token)
    assert client.get(AUTHED_API).status_code == 401
    # The HTML side bounces to /login instead of serving the page.
    resp = client.get("/session/heartbeat", follow_redirects=False)
    assert resp.status_code in (302, 303, 307)
    assert "/login" in resp.headers["location"]


def test_old_token_as_bearer_is_rejected_after_logout(client):
    old_token = _register_and_login(client)
    client.get("/logout", follow_redirects=False)
    client.cookies.clear()
    resp = client.get(AUTHED_API, headers={"Authorization": f"Bearer {old_token}"})
    assert resp.status_code == 401


def test_revoked_cookie_is_not_refreshed(client):
    old_token = _register_and_login(client)
    client.get("/logout", follow_redirects=False)
    client.cookies.clear()
    client.cookies.set("access_token", old_token)
    # A public page (status < 400) must not re-mint the revoked cookie.
    resp = client.get("/landing")
    assert resp.status_code == 200
    assert "access_token=" not in resp.headers.get("set-cookie", "")


def test_login_page_does_not_loop_on_revoked_cookie(client):
    old_token = _register_and_login(client)
    client.get("/logout", follow_redirects=False)
    client.cookies.clear()
    client.cookies.set("access_token", old_token)
    assert client.get("/login", follow_redirects=False).status_code == 200


def test_fresh_login_after_logout_works_and_is_refreshed(client):
    _register_and_login(client)
    client.get("/logout", follow_redirects=False)
    new_token = _register_and_login(client)
    resp = client.get("/session/heartbeat")
    assert resp.status_code == 204
    # The verified session still slides forward.
    assert "access_token=" in resp.headers.get("set-cookie", "")
    assert new_token


def test_token_without_tv_claim_matches_version_zero(client):
    _register_and_login(client)
    import jwt
    from datetime import datetime, timedelta
    legacy = jwt.encode(
        {"sub": "1", "role": "admin", "exp": datetime.utcnow() + timedelta(minutes=5)},
        auth_module.SECRET_KEY, algorithm=auth_module.ALGORITHM,
    )
    client.cookies.clear()
    assert client.get("/session/heartbeat", headers={"Authorization": f"Bearer {legacy}"}).status_code == 204


def test_token_version_migration_is_idempotent(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)

    async def go():
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(50))"))
            await conn.execute(text("INSERT INTO users (id, username) VALUES (1, 'old')"))
        monkeypatch.setattr(token_version_migration, "engine", engine)
        first = await token_version_migration.migrate()
        second = await token_version_migration.migrate()
        async with engine.connect() as conn:
            cols = await conn.run_sync(lambda c: {x["name"] for x in inspect(c).get_columns("users")})
            row = (await conn.execute(text("SELECT token_version FROM users WHERE id = 1"))).one()
        return first, second, cols, row

    try:
        first, second, cols, row = _run(go())
    finally:
        _run(engine.dispose())
    assert first is True
    assert second is False
    assert "token_version" in cols
    assert row[0] == 0


def test_startup_sequence_runs_token_version_migration():
    import inspect as pyinspect
    src = pyinspect.getsource(app_module._startup_db_sequence)
    assert "migrate_add_user_token_version" in src
