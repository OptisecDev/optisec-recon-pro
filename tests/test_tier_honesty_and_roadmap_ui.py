"""
Tests for the "tier honesty" and roadmap-consistency template fixes:

- index.html's dashboard subtitle used to hardcode "OPTISEC Enterprise"
  regardless of the viewing account's actual subscription_tier. Now uses
  web.license.user_tier_label(user), the same per-user helper base.html's
  sidebar badges already use.
- base.html labeled the NGFW feature "NGFW v2 (ML/DPI)" and
  web.license.FEATURE_LABELS["ngfw"] said "NGFW v2 ML/DPI" -- both
  implying a machine-learning model backs it, when it's rule-based/
  heuristic scoring (entropy, signature patterns) -- see landing.html's
  roadmap description, which already said as much. Renamed to
  "NGFW v2 (Heuristic DPI)" in both places, and the NGFW/AI Firewall
  pages themselves now carry a bilingual notice saying so.
- landing.html's public roadmap section marks ATT&CK Navigator,
  Autonomous RedTeam, Quantum Crypto, Compliance Checker, NGFW, and
  Global Threat Feed as still in active development / coming soon. The
  in-app sidebar (base.html) previously showed these as regular, finished
  nav items -- now each carries a "Beta" badge so the two surfaces agree.
"""

import asyncio
import os
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
from web.license import FEATURE_LABELS
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


def test_dashboard_subtitle_reflects_the_viewers_own_tier_not_hardcoded_enterprise(client):
    c, session_factory = client
    token = _seed_user_token(session_factory, "free_dash", "free")
    html = c.get("/", cookies={"access_token": token}).text
    assert "OPTISEC Enterprise" not in html
    assert "OPTISEC FREE" in html


def test_dashboard_subtitle_shows_enterprise_for_an_enterprise_account(client):
    c, session_factory = client
    token = _seed_user_token(session_factory, "ent_dash", "enterprise")
    html = c.get("/", cookies={"access_token": token}).text
    assert "OPTISEC ENTERPRISE" in html


def test_ngfw_feature_label_no_longer_claims_ml():
    label = FEATURE_LABELS["ngfw"]
    assert "ML" not in label
    assert "Heuristic" in label


def test_ngfw_sidebar_label_no_longer_claims_ml(client):
    c, session_factory = client
    token = _seed_user_token(session_factory, "ngfw_nav", "enterprise")
    html = c.get("/", cookies={"access_token": token}).text
    soup = BeautifulSoup(html, "html.parser")
    link = soup.select_one('a[href="/ngfw"]')
    assert link is not None
    assert "ML/DPI" not in link.get_text()
    assert "Heuristic DPI" in link.get_text()


@pytest.mark.parametrize("href", [
    "/attack-navigator", "/autonomous-redteam", "/quantum",
    "/compliance", "/ngfw", "/threat-feed",
])
def test_roadmap_items_carry_a_beta_badge_in_the_sidebar(client, href):
    c, session_factory = client
    token = _seed_user_token(session_factory, f"beta_nav_{href.strip('/').replace('-', '_')}", "enterprise")
    html = c.get("/", cookies={"access_token": token}).text
    soup = BeautifulSoup(html, "html.parser")
    link = soup.select_one(f'a[href="{href}"]')
    assert link is not None, f"nav item for {href!r} not found"
    assert link.select_one(".nav-beta-badge") is not None, \
        f"{href} should carry a Beta badge, matching landing.html's roadmap section"


def test_ngfw_page_carries_a_heuristic_not_ml_notice(client):
    c, session_factory = client
    token = _seed_user_token(session_factory, "ngfw_page", "enterprise")
    html = c.get("/ngfw", cookies={"access_token": token}).text
    assert "machine learning" in html.lower()
    assert "heuristic" in html.lower()


def test_firewall_page_carries_a_heuristic_not_ml_notice(client):
    c, session_factory = client
    token = _seed_user_token(session_factory, "firewall_page", "enterprise")
    html = c.get("/firewall", cookies={"access_token": token}).text
    assert "machine learning" in html.lower()
    assert "heuristic" in html.lower()
