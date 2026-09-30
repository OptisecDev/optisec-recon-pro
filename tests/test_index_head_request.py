"""
PRIORITY 3 item 9 of the live-walkthrough audit (BATCH 2):

`@app.get("/")` (web/app.py) registers a FastAPI APIRoute with
methods={"GET"} only. Unlike bare starlette.routing.Route, this installed
FastAPI/Starlette version's APIRoute does not implicitly add HEAD to a
GET-only route (confirmed by inspecting the running route object's
.methods attribute), so Render's health probe -- which sends HEAD / --
previously got a 405 Method Not Allowed instead of 200.

Fix: a dedicated `@app.head("/")` handler returns a bare 200/no-body
response, skipping index()'s authenticated DB-query/template-render path
entirely (a health probe needs neither).
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
import web.app as app_module


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


def test_head_slash_returns_200_not_405(client):
    resp = client.head("/", follow_redirects=False)
    assert resp.status_code == 200
    assert resp.content == b""


def test_head_slash_requires_no_authentication(client):
    """A Render health probe has no session cookie -- HEAD / must not
    depend on web_user (unlike GET /'s index())."""
    resp = client.head("/", follow_redirects=False)
    assert resp.status_code == 200


def test_get_slash_is_unaffected_by_the_new_head_route(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
