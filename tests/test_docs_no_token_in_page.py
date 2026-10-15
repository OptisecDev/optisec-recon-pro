"""
/docs must not copy the session token into page JavaScript (Issue #2).

The access_token cookie is HttpOnly so that script on the page cannot read
it. custom_swagger() used to read that cookie and write its value into the
SwaggerUIBundle requestInterceptor, which handed it to any XSS on /docs.
Swagger UI's same-origin "Try it out" calls carry the cookie on their own,
so the page needs no copy of it. Same TestClient + isolated in-memory DB
pattern as tests/test_token_not_in_query.py.
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
                username="docs_token_user", email="docs_token_user@example.com",
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


def test_docs_renders_with_session_cookie(client, token):
    c, _ = client
    resp = _get_docs(c, token)
    assert resp.status_code == 200
    assert "SwaggerUIBundle" in resp.text


def test_docs_body_does_not_contain_session_token(client, token):
    c, _ = client
    resp = _get_docs(c, token)
    assert resp.status_code == 200
    # Plain boolean so a failure never echoes the token into the test output.
    leaked = token in resp.text
    assert not leaked, "session token value found in /docs response body"


def test_docs_scripts_do_not_handle_access_token(client, token):
    c, _ = client
    resp = _get_docs(c, token)
    scripts = SCRIPT_RE.findall(resp.text)
    assert scripts, "expected the SwaggerUIBundle init script"
    for body in scripts:
        assert "access_token" not in body
        assert "headers['Cookie']" not in body
