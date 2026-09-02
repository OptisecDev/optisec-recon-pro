"""
Regression test: GET /redeem must not wall off pricing/purchase info
behind a login redirect for anonymous visitors.

web/routers/license_routes.py::redeem_page used to require an
authenticated user (Depends(_user)), so an anonymous visitor hit a 401,
which web/app.py's global exception handler turns into a 302 to /login
for any non-/api/ path -- they never saw the page, the price, or the
"Buy PRO" link at all. redeem_page now depends on _user_optional, which
returns None instead of raising, and web/templates/redeem.html guards the
per-user "current plan" row with `{% if user %}`. The actual redemption
action (POST /api/subscription/redeem) is untouched and still requires a
real login -- verified below alongside the page-level fix so the two
don't drift apart.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.app as app_module
from web.database import Base, get_db


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
    yield c

    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def test_anonymous_visitor_sees_redeem_page_not_a_login_redirect(client):
    resp = client.get("/redeem", follow_redirects=False)
    assert resp.status_code == 200
    assert "Buy PRO" in resp.text
    assert "$399" in resp.text


def test_anonymous_redeem_action_still_requires_login(client):
    resp = client.post(
        "/api/subscription/redeem",
        json={"license_key": "OPTISEC-RECON-AAAA-BBBB-CCCC-DDDD"},
    )
    assert resp.status_code == 401
