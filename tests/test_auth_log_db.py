"""
Tests for the Auth Log DB migration.

Context: the Admin Panel's "Auth Log" card (web/templates/admin.html) always
showed "No entries" in production even though real logins were happening --
confirmed by users.last_login being populated correctly. Root cause: the
feed came from logs/auth.log, a file on each instance's local disk. Render
runs this app with 2 uvicorn workers/instances (README.md) and no
persistent disk backing logs/, so that file is never a reliable read path
the way the Postgres/Neon-backed `users` table already is.

Fix: web/models.py AuthEvent is a new durable table; web/auth.py
record_auth_event() writes both the existing log line (unchanged, kept for
local grep/debugging) and a row in that table; GET /api/admin/auth-log
(web/app.py) now reads the table instead of the file.

Drives the real FastAPI app end-to-end via TestClient, against an isolated
in-memory SQLite DB (same fixture pattern as
tests/test_register_rate_limit.py and tests/test_license_activate_rate_limit.py)
so nothing here touches the real dev/prod DB.
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
from web import auth as auth_module


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
                username="admin", email="admin@example.com",
                password_hash=auth_module.hash_password("AdminPass1!"),
                role="admin", is_active=True, api_key_hash="unused-admin-key",
            )
            session.add(admin)
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _admin_user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == "admin"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[app_module.web_user] = _admin_user_override
    auth_module._login_attempts.clear()
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    auth_module._login_attempts.clear()
    _run(engine.dispose())


def _auth_log(client, **params):
    resp = client.get("/api/admin/auth-log", params=params)
    assert resp.status_code == 200
    return resp.json()


def test_failed_login_writes_failure_row(client):
    resp = client.post(
        "/login",
        data={"username": "admin", "password": "WrongPass1!", "next": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 401

    entries = _auth_log(client)
    assert entries[0]["status"] == "FAILURE"
    assert entries[0]["event"] == "LOGIN"
    assert entries[0]["user"] == "admin"
    assert entries[0]["detail"] == "invalid_credentials"


def test_successful_login_writes_success_row(client):
    resp = client.post(
        "/login",
        data={"username": "admin", "password": "AdminPass1!", "next": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 302

    entries = _auth_log(client)
    assert entries[0]["status"] == "SUCCESS"
    assert entries[0]["event"] == "LOGIN"
    assert entries[0]["user"] == "admin"


def test_registration_writes_success_row(client):
    resp = client.post(
        "/register",
        data={"username": "newanalyst", "email": "newanalyst@example.com", "password": "Strong1!Pass"},
        follow_redirects=False,
    )
    assert resp.status_code == 302

    entries = _auth_log(client)
    assert entries[0]["status"] == "SUCCESS"
    assert entries[0]["event"] == "REGISTER"
    assert entries[0]["user"] == "newanalyst"


def test_logout_writes_row_with_username_not_user_id(client):
    # Regression: logout previously took the JWT "sub" claim -- the numeric
    # user id, per create_access_token's {"sub": str(user_id), ...} -- and
    # used it directly as the username. Fixed by resolving it back to a
    # username via the DB, same as every other Auth Log row.
    login_resp = client.post(
        "/login",
        data={"username": "admin", "password": "AdminPass1!", "next": "/"},
        follow_redirects=False,
    )
    token = login_resp.cookies.get("access_token")
    assert token
    client.cookies.set("access_token", token)

    resp = client.get("/logout", follow_redirects=False)
    assert resp.status_code == 302

    entries = _auth_log(client)
    logout_rows = [e for e in entries if e["event"] == "LOGOUT"]
    assert logout_rows, "no LOGOUT row was written"
    assert logout_rows[0]["user"] == "admin"
    assert logout_rows[0]["user"] != "1"


def test_auth_log_orders_newest_first(client):
    client.post("/login", data={"username": "admin", "password": "WrongPass1!", "next": "/"}, follow_redirects=False)
    client.post("/login", data={"username": "admin", "password": "AdminPass1!", "next": "/"}, follow_redirects=False)

    entries = _auth_log(client)
    assert entries[0]["status"] == "SUCCESS"  # the later, successful attempt
    assert entries[1]["status"] == "FAILURE"  # the earlier, failed attempt


def _js_filter(entries, filter_value):
    """Mirrors filterLog() in web/templates/admin.html exactly:
    entries.filter(e => e.status === filter || e.event.includes(filter))
    """
    if not filter_value:
        return entries
    return [e for e in entries if e["status"] == filter_value or filter_value in e["event"]]


def test_every_log_filter_dropdown_value_returns_the_right_rows(client):
    # Reproduce all six <option> values from web/templates/admin.html's
    # #log-filter select against a known mix of events.
    client.post("/login", data={"username": "admin", "password": "WrongPass1!", "next": "/"}, follow_redirects=False)
    client.post("/login", data={"username": "admin", "password": "AdminPass1!", "next": "/"}, follow_redirects=False)
    client.post(
        "/register",
        data={"username": "filteruser", "email": "filteruser@example.com", "password": "Strong1!Pass"},
        follow_redirects=False,
    )
    login_resp = client.post(
        "/login",
        data={"username": "admin", "password": "AdminPass1!", "next": "/"},
        follow_redirects=False,
    )
    client.cookies.set("access_token", login_resp.cookies.get("access_token"))
    client.get("/logout", follow_redirects=False)

    entries = _auth_log(client)
    events_present = {e["event"] for e in entries}
    assert events_present == {"LOGIN", "REGISTER", "LOGOUT"}

    assert len(_js_filter(entries, "")) == len(entries)
    assert all(e["status"] == "SUCCESS" for e in _js_filter(entries, "SUCCESS"))
    assert all(e["status"] == "FAILURE" for e in _js_filter(entries, "FAILURE"))
    assert {e["event"] for e in _js_filter(entries, "LOGIN")} == {"LOGIN"}
    assert {e["event"] for e in _js_filter(entries, "LOGOUT")} == {"LOGOUT"}
    assert {e["event"] for e in _js_filter(entries, "REGISTER")} == {"REGISTER"}

    # Every filter value must actually narrow the set for this fixture --
    # an empty result for any of them would mean that option is dead.
    for value in ("SUCCESS", "FAILURE", "LOGIN", "LOGOUT", "REGISTER"):
        assert _js_filter(entries, value), f"filter {value!r} returned no rows"


def test_ip_is_captured_from_cf_connecting_ip_on_render(client, monkeypatch):
    monkeypatch.setattr(auth_module, "_ON_RENDER", True)
    resp = client.post(
        "/login",
        data={"username": "admin", "password": "AdminPass1!", "next": "/"},
        headers={"CF-Connecting-IP": "203.0.113.7"},
        follow_redirects=False,
    )
    assert resp.status_code == 302

    entries = _auth_log(client)
    assert entries[0]["ip"] == "203.0.113.7"


def test_auth_log_never_contains_the_plaintext_password(client):
    password = "SuperSecretPass1!"
    client.post("/login", data={"username": "admin", "password": password, "next": "/"}, follow_redirects=False)
    client.post(
        "/register",
        data={"username": "secretcheck", "email": "secretcheck@example.com", "password": password},
        follow_redirects=False,
    )

    entries = _auth_log(client)
    for entry in entries:
        for value in entry.values():
            assert password not in str(value)


