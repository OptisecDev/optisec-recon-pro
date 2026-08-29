"""Regression test for the Jinja global registration bug in
web/shared_templates.py.

web/app.py and web/shared_templates.py each create their own
Jinja2Templates instance (fastapi.templating.Jinja2Templates does not
share environments across instances). web/templates/base.html — extended
by every page in the app — calls the `user_has_feature` Jinja global to
render the sidebar's pro/enterprise lock icons. That global used to be
registered only on web/app.py's instance; every router below renders its
page through web/shared_templates.py's separate instance, which never
had it registered, so every one of these pages raised a Jinja
UndefinedError (surfaced to callers as an unhandled 500) the moment it
tried to render base.html's sidebar.

The fix centralizes registration in
web.shared_templates.register_template_globals(), called on both
instances. This test loads every HTML page served through the
shared_templates.py instance (the full list documented via `grep -rl
"from web.shared_templates import templates" web/routers/`) and asserts
each one actually renders (200, well-formed HTML, no exception) instead
of just checking the import wires up cleanly.
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
import web.routers.threat_feed as threat_feed_router
from web.database import Base, get_db
from web.models import User
from web.auth import create_access_token, hash_password


def _run(coro):
    return asyncio.run(coro)


# Every GET route, across all 16 routers importing `templates` from
# web.shared_templates, that actually renders an HTML page (as opposed to
# a JSON API route). web/routers/osint.py imports `templates` but never
# calls TemplateResponse with it, so it contributes no page here.
SHARED_TEMPLATE_PAGES = [
    "/ai-security/behavioral",
    "/ai-security/zero-day",
    "/ai-security/attack-patterns",
    "/ai-security/red-team",
    "/firewall",
    "/honeypot",
    "/vpn",
    "/ngfw",
    "/bug-bounty",
    "/redeem",
    "/federation",
    "/compliance",
    "/threat-feed",
    "/quantum",
    "/darkweb",
    "/correlations",
    "/attack-navigator",
    "/autonomous-redteam",
]


@pytest.fixture
def client(monkeypatch):
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

    # Guarantee zero real OTX network traffic regardless of the host
    # environment's OTX_API_KEY: force the falsy-key short-circuit path in
    # web/routers/threat_feed.py, and fail loudly if it's bypassed.
    monkeypatch.setattr(threat_feed_router, "OTX_API_KEY", "")

    def _otx_should_not_be_called(*args, **kwargs):
        raise AssertionError("fetch_otx_pulses must not be called in tests")

    monkeypatch.setattr(
        "modules.threat_intel.otx_feed.fetch_otx_pulses", _otx_should_not_be_called
    )

    c = TestClient(app_module.app)
    yield c, session_factory

    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def _seed_user_token(session_factory, username: str, role: str, tier: str) -> str:
    async def go():
        async with session_factory() as db:
            user = User(
                username=username, email=f"{username}@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role=role, subscription_tier=tier, is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id
    user_id = _run(go())
    return create_access_token(user_id, role)


class TestAllSharedTemplatePagesRender:
    """Every page served through web/shared_templates.py's Jinja2Templates
    instance must render 200 with real HTML, not a 500 from a missing
    Jinja global. Uses an enterprise-tier user ("*" in TIER_FEATURES) so
    every route's require_feature_or_402 gate passes and execution
    actually reaches the TemplateResponse call being tested."""

    @pytest.mark.parametrize("path", SHARED_TEMPLATE_PAGES)
    def test_page_renders_200(self, client, path):
        c, session_factory = client
        token = _seed_user_token(session_factory, f"ent_{abs(hash(path))}", "admin", "enterprise")
        resp = c.get(path, cookies={"access_token": token})
        assert resp.status_code == 200, (
            f"{path} returned {resp.status_code}, expected 200. Body: {resp.text[:500]}"
        )
        assert "<html" in resp.text.lower()
        assert "user_has_feature" not in resp.text  # Jinja error page leaks the expression, not the value

    def test_all_documented_routers_are_covered(self):
        """Guards against this list silently drifting from the routers
        that actually import web.shared_templates.templates."""
        import subprocess
        result = subprocess.run(
            ["grep", "-rl", "from web.shared_templates import", "web/routers/"],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            capture_output=True, text=True,
        )
        router_files = {os.path.basename(p) for p in result.stdout.strip().splitlines()}
        assert len(router_files) == 16, (
            f"Expected 16 routers importing shared_templates, found {len(router_files)}: {router_files}. "
            "Update SHARED_TEMPLATE_PAGES in this file if a router was added/removed."
        )
