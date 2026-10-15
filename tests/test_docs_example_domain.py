"""
Public API docs must use example.com as the example scan target and must not
advertise that API endpoints are not rate-limited.

tesla.com is a real third-party domain; example.com is reserved for
documentation (RFC 2606). The "API endpoints are not currently rate-limited"
sentence told readers exactly where brute-forcing was cheap, so it was
removed. /docs is a Swagger shell that loads its text from /openapi.json, so
the spec and the /api-docs page are checked too. Same TestClient + isolated
in-memory DB pattern as tests/test_docs_no_persisted_authorize.py.

Bodies are reduced to a bool before asserting so a failure never dumps the
page into the test output.
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
from web.auth import hash_password, create_access_token
import web.app as app_module

REAL_DOMAIN = "tesla.com"
RATE_LIMIT_CLAIM = "API endpoints are not currently rate-limited"


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
                username="docs_example_user", email="docs_example_user@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role="analyst", is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id

    user_id = _run(go())
    return create_access_token(user_id, "analyst")


def _get(c, token, path):
    c.cookies.set("access_token", token)
    try:
        return c.get(path)
    finally:
        c.cookies.clear()


@pytest.mark.parametrize("path", ["/docs", "/openapi.json", "/api-docs"])
def test_docs_do_not_use_real_target_domain(client, token, path):
    c, _ = client
    resp = _get(c, token, path)
    assert resp.status_code == 200
    found = REAL_DOMAIN in resp.text
    assert not found, f"{path} still contains the real example domain"


@pytest.mark.parametrize("path", ["/docs", "/openapi.json", "/api-docs"])
def test_docs_do_not_claim_api_is_not_rate_limited(client, token, path):
    c, _ = client
    resp = _get(c, token, path)
    assert resp.status_code == 200
    found = RATE_LIMIT_CLAIM in resp.text
    assert not found, f"{path} still states that API endpoints are not rate-limited"
