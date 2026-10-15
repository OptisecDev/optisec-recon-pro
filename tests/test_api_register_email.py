import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, func
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
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())

    async def _override():
        async with Session() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = _override
    auth_module._login_attempts.clear()
    c = TestClient(app_module.app)
    c.session_factory = Session
    yield c
    app_module.app.dependency_overrides.clear()
    auth_module._login_attempts.clear()
    _run(engine.dispose())


def _count_users(session_factory):
    async def _q():
        async with session_factory() as session:
            return (await session.execute(select(func.count()).select_from(User))).scalar()
    return _run(_q())


@pytest.mark.parametrize("bad", ["abc", "a@", "@x.com", "a b@x.com"])
def test_invalid_email_rejected_with_400(client, bad):
    r = client.post(
        "/api/auth/register",
        json={"username": "bad_email_user", "password": "StrongPass1!", "email": bad},
    )
    assert r.status_code == 400, r.text


@pytest.mark.parametrize("bad", ["abc", "a@", "@x.com", "a b@x.com", "", None, 123])
def test_invalid_email_does_not_create_user(client, bad):
    before = _count_users(client.session_factory)
    r = client.post(
        "/api/auth/register",
        json={"username": "bad_email_user", "password": "StrongPass1!", "email": bad},
    )
    assert r.status_code == 400, r.text
    assert _count_users(client.session_factory) == before


def test_valid_email_still_registers(client):
    before = _count_users(client.session_factory)
    r = client.post(
        "/api/auth/register",
        json={"username": "good_email_user", "password": "StrongPass1!", "email": "good@example.com"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["api_key"]
    assert _count_users(client.session_factory) == before + 1


# ─── form-data paths ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["abc", "a@", "@x.com", "a b@x.com", ""])
def test_html_register_rejects_invalid_email(client, bad):
    before = _count_users(client.session_factory)
    r = client.post(
        "/register",
        data={"username": "form_bad_email", "password": "StrongPass1!", "email": bad},
        follow_redirects=False,
    )
    assert r.status_code == 400, r.text
    assert "Invalid email address" in r.text
    assert "access_token" not in r.cookies
    assert _count_users(client.session_factory) == before


def test_html_register_valid_email_creates_user(client):
    before = _count_users(client.session_factory)
    r = client.post(
        "/register",
        data={"username": "form_good_email", "password": "StrongPass1!", "email": "form@example.com"},
        follow_redirects=False,
    )
    assert r.status_code == 302, r.text
    assert _count_users(client.session_factory) == before + 1


def test_api_register_form_data_invalid_email_is_400_not_500(client):
    before = _count_users(client.session_factory)
    r = client.post(
        "/api/auth/register",
        data={"username": "api_form_bad", "password": "StrongPass1!", "email": "abc"},
    )
    assert r.status_code == 400, r.text
    assert _count_users(client.session_factory) == before


def test_api_register_form_data_valid_email_creates_user(client):
    before = _count_users(client.session_factory)
    r = client.post(
        "/api/auth/register",
        data={"username": "api_form_good", "password": "StrongPass1!", "email": "apiform@example.com"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["api_key"]
    assert _count_users(client.session_factory) == before + 1


@pytest.mark.parametrize("body,ctype", [
    (b"{not json", "application/json"),
    (b"[1, 2]", "application/json"),
    (b"username=x", "text/plain"),
])
def test_api_register_malformed_body_is_400_not_500(client, body, ctype):
    before = _count_users(client.session_factory)
    r = client.post("/api/auth/register", content=body, headers={"content-type": ctype})
    assert r.status_code == 400, r.text
    assert _count_users(client.session_factory) == before


def test_api_register_multipart_file_field_is_400_not_500(client):
    before = _count_users(client.session_factory)
    r = client.post(
        "/api/auth/register",
        data={"username": "api_multipart", "password": "StrongPass1!"},
        files={"email": ("e.txt", b"x@example.com", "text/plain")},
    )
    assert r.status_code == 400, r.text
    assert _count_users(client.session_factory) == before
