"""
Tests for the 402 branch of web/app.py's on_http_exception handler.

Before this fix, an HTTPException(402) raised by require_feature_or_402()
(web/license.py) always fell through to the handler's final catch-all --
JSONResponse({"error": exc.detail}) -- even on a plain browser GET to an
HTML page like /compliance. A free-tier user clicking a locked nav item
got a raw JSON blob instead of a page, unlike the 401/403 branches just
above it which already render styled HTML for non-/api/ paths.

The fix adds a 402 branch, mirroring the existing 401/403 pattern exactly
(same "not path.startswith('/api/')" condition): a non-/api/ 402 now
renders error.html with a "Upgrade Plan" CTA pointing at /redeem (the
per-user upgrade flow, web/routers/license_routes.py), while /api/* paths
keep the original JSON shape untouched.
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


def _free_user_token(session_factory) -> str:
    async def go():
        async with session_factory() as db:
            user = User(
                username="free_user", email="free_user@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role="viewer", subscription_tier="free", is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id
    user_id = _run(go())
    return create_access_token(user_id, "viewer")


def test_402_on_html_page_renders_styled_upgrade_page(client):
    c, session_factory = client
    token = _free_user_token(session_factory)
    resp = c.get("/compliance", cookies={"access_token": token})
    assert resp.status_code == 402
    assert resp.headers["content-type"].startswith("text/html")
    assert "/redeem" in resp.text
    assert "Upgrade Plan" in resp.text


def test_402_on_api_path_still_returns_json(client):
    c, session_factory = client
    token = _free_user_token(session_factory)
    resp = c.get("/api/correlations", cookies={"access_token": token})
    assert resp.status_code == 402
    assert resp.headers["content-type"].startswith("application/json")
    body = resp.json()
    assert "error" in body
