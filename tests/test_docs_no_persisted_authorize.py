"""
/docs must not persist Swagger Authorize values in browser storage.

With persistAuthorization: true, Swagger UI saves whatever a user types into
the Authorize dialog in localStorage, where any script running on /docs can
read it. The option is now false, so the value lives only in page memory and
is gone after a reload. Same TestClient + isolated in-memory DB pattern as
tests/test_docs_no_token_in_page.py.
"""

import asyncio
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
from web.models import User
from web.auth import hash_password, create_access_token
import web.app as app_module

SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)


def _run(coro):
    return asyncio.run(coro)


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


@pytest.fixture
def token(client):
    """A valid session token for a logged-in analyst."""
    _, session_factory = client

    async def go():
        async with session_factory() as db:
            user = User(
                username="docs_persist_user", email="docs_persist_user@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role="analyst", is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id

    user_id = _run(go())
    return create_access_token(user_id, "analyst")


def _get_docs(c, token):
    c.cookies.set("access_token", token)
    try:
        return c.get("/docs")
    finally:
        c.cookies.clear()


def _scripts(resp):
    scripts = SCRIPT_RE.findall(resp.text)
    assert scripts, "expected the SwaggerUIBundle init script"
    return scripts


def test_docs_renders_with_session_cookie(client, token):
    c, _ = client
    resp = _get_docs(c, token)
    assert resp.status_code == 200
    assert "SwaggerUIBundle" in resp.text


def test_docs_script_disables_persist_authorization(client, token):
    c, _ = client
    resp = _get_docs(c, token)
    assert resp.status_code == 200
    assert any("persistAuthorization: false" in body for body in _scripts(resp))


def test_docs_script_does_not_enable_persist_authorization(client, token):
    c, _ = client
    resp = _get_docs(c, token)
    assert resp.status_code == 200
    for body in _scripts(resp):
        assert "persistAuthorization: true" not in body
