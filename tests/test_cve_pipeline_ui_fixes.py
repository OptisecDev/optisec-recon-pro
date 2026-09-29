"""
Tests for two small CVE Pipeline UI fixes, both on web/templates/
cve_pipeline.html and web/templates/base.html:

1. draftFromFinding() and draftCVE() (cve_pipeline.html) read only
   `d.detail` from a failed /api/cve/draft response. But web/app.py's
   on_http_exception handler (the app-wide @app.exception_handler(
   HTTPException)) renders every non-401/403/402 HTTPException as
   {"error": exc.detail}, not {"detail": ...} -- so the real backend
   message (invalid finding_id, missing title/description, credits
   validation, etc.) never reached the page; the user only ever saw the
   hardcoded "Failed to generate/save draft." fallback. Fixed to read
   `d.error` first, falling back to `d.detail` for any other error shape
   (e.g. FastAPI's own RequestValidationError, which isn't caught by that
   handler and still uses "detail").

2. The "CVE Pipeline" sidebar nav item (base.html) had no lock icon, even
   though every POST /api/cve/draft call is gated by
   require_feature_or_402("bug_bounty", user) -- the same entitlement the
   "Bounty Platform" item right above it already shows a lock for. The
   page itself has no feature gate (any authenticated user can view it,
   see GET /cve-pipeline in web/app.py), so a free-tier user could reach
   the page with no visual cue that drafting would 402.

There's no JS test runner in this suite, so (1) is asserted at the level
that's actually feasible here: the rendered template's inline <script>
source contains the corrected fallback chain for both functions, guarding
against a regression back to reading only `d.detail`.
"""

import asyncio
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from bs4 import BeautifulSoup
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


def _seed_user_token(session_factory, username: str, tier: str) -> str:
    async def go():
        async with session_factory() as db:
            user = User(
                username=username, email=f"{username}@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role="viewer", subscription_tier=tier, is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id
    user_id = _run(go())
    return create_access_token(user_id, "viewer")


def test_draft_error_handlers_read_error_with_detail_fallback(client):
    c, session_factory = client
    token = _seed_user_token(session_factory, "cve_ui_user", "free")
    html = c.get("/cve-pipeline", cookies={"access_token": token}).text

    draft_from_finding = re.search(
        r"async function draftFromFinding\(\).*?\n}", html, re.DOTALL
    )
    draft_cve = re.search(r"async function draftCVE\(\).*?\n}", html, re.DOTALL)
    assert draft_from_finding, "draftFromFinding() not found in rendered page"
    assert draft_cve, "draftCVE() not found in rendered page"

    assert "d.error || d.detail" in draft_from_finding.group(0)
    assert "d.error || d.detail" in draft_cve.group(0)


def test_cve_pipeline_nav_item_shows_lock_for_free_tier(client):
    c, session_factory = client
    token = _seed_user_token(session_factory, "cve_nav_free", "free")
    html = c.get("/", cookies={"access_token": token}).text
    soup = BeautifulSoup(html, "html.parser")
    link = soup.select_one('a[href="/cve-pipeline"]')
    assert link is not None
    assert link.select_one(".nav-lock") is not None, \
        "CVE Pipeline nav item should show a lock icon for a free-tier user"


def test_cve_pipeline_nav_item_has_no_lock_for_pro_tier(client):
    c, session_factory = client
    token = _seed_user_token(session_factory, "cve_nav_pro", "pro")
    html = c.get("/", cookies={"access_token": token}).text
    soup = BeautifulSoup(html, "html.parser")
    link = soup.select_one('a[href="/cve-pipeline"]')
    assert link is not None
    assert link.select_one(".nav-lock") is None, \
        "CVE Pipeline nav item should not show a lock icon once bug_bounty is entitled"
