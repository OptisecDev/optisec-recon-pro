"""
/privacy and /terms are public pages (no login), linked from the landing
page footer and the app sidebar footer.

Same TestClient + in-memory-SQLite fixture pattern as
tests/test_security_headers.py.
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
import web.app as app_module

BARE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)(?![^>]*\bnonce=)[^>]*>")


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
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


@pytest.mark.parametrize("path,heading", [
    ("/privacy", "<h1>Privacy Policy</h1>"),
    ("/terms", "<h1>Terms of Service</h1>"),
])
def test_legal_page_renders_without_login(client, path, heading):
    resp = client.get(path, follow_redirects=False)
    assert resp.status_code == 200
    assert heading in resp.text
    assert app_module.LEGAL_CONTACT_EMAIL in resp.text
    assert " style=\"" not in resp.text
    assert not BARE_SCRIPT_RE.search(resp.text)


def test_landing_footer_links_legal_pages(client):
    resp = client.get("/landing")
    assert resp.status_code == 200
    assert 'href="/privacy"' in resp.text
    assert 'href="/terms"' in resp.text


@pytest.mark.parametrize("path,title", [
    ("/privacy", "<title>Privacy Policy — "),
    ("/terms", "<title>Terms of Service — "),
])
def test_legal_page_title_and_draft_notice(client, path, title):
    resp = client.get(path)
    assert resp.status_code == 200
    assert title in resp.text
    # Both pages stay marked as drafts until the owner's legal review.
    assert "مسودة بانتظار المراجعة القانونية" in resp.text
