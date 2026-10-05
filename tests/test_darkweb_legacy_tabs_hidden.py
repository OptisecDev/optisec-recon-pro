"""The /darkweb page renders only its live tabs, and the legacy simulated
endpoints are flagged deprecated.

The Breach Detection, Tor Intelligence, Ransomware Groups, Keyword Alerts
and Threat Report surfaces were all generated locally from static lists and
a random/hash-seeded generator (modules/darkweb/intelligence.py). They are
hidden from the page; only Continuous Monitoring (live HIBP / IntelX /
LeakCheck / OTX) and the regex Paste Scanner remain, with Continuous
Monitoring as the default tab.

The four simulated JSON endpoints are kept for existing consumers, but each
response now carries deprecated=True alongside the existing simulated=True.
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
import web.routers.darkweb as darkweb_router
import modules.darkweb.intelligence as darkweb_module
from web.database import Base, get_db
from web.models import User
from web.auth import create_access_token, hash_password


def _run(coro):
    return asyncio.run(coro)


def _fake_user(user_id: int = 1) -> User:
    return User(id=user_id, username=f"u{user_id}", email=f"u{user_id}@example.com",
                password_hash="x", role="analyst", subscription_tier="enterprise")


class _JsonRequest:
    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


@pytest.fixture
def isolated_darkweb_data(tmp_path, monkeypatch):
    monkeypatch.setattr(darkweb_module, "DATA_FILE", tmp_path / "darkweb_intel.json")


@pytest.fixture
def page_html():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with session_factory() as db:
            user = User(username="dw_page", email="dw_page@example.com",
                        password_hash=hash_password("Passw0rd!1"),
                        role="analyst", subscription_tier="enterprise", is_active=True)
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id

    user_id = _run(setup())

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db
    try:
        resp = TestClient(app_module.app).get(
            "/darkweb", cookies={"access_token": create_access_token(user_id, "analyst")})
        assert resp.status_code == 200, resp.text[:500]
        yield resp.text
    finally:
        app_module.app.dependency_overrides.pop(get_db, None)
        _run(engine.dispose())


class TestDarkwebPageTabs:
    def test_only_live_tabs_are_rendered(self, page_html):
        assert 'id="tab-monitor"' in page_html
        assert 'id="tab-paste"' in page_html
        for hidden in ("tab-breach", "tab-tor", "tab-keywords", "tab-ransomware"):
            assert f'id="{hidden}"' not in page_html

    def test_continuous_monitoring_is_the_default_tab(self, page_html):
        assert 'id="tab-monitor" class="is-hidden"' not in page_html
        assert 'id="tab-paste" class="is-hidden"' in page_html
        assert "tab-btn active\" data-onclick=\"showTab\" data-onclick-args='[\"monitor\"]'" in page_html

    def test_simulated_stats_and_widgets_are_gone(self, page_html):
        for text in ("Tor Services Monitored", "Keyword Alerts", "Add Keyword Monitor",
                     "Active Monitors", "Generate Threat Report", "Simulated data"):
            assert text not in page_html
        for endpoint in ("/darkweb/api/check-domain", "/darkweb/api/check-email",
                         "/darkweb/api/threat-report", "/darkweb/api/tor-monitor"):
            assert endpoint not in page_html


class TestLegacyEndpointsDeprecated:
    def _assert_flags(self, result: dict):
        assert result["deprecated"] is True
        assert result["simulated"] is True

    def test_check_domain(self, isolated_darkweb_data):
        self._assert_flags(_run(darkweb_router.check_domain(
            _JsonRequest({"domain": "example.com"}), user=_fake_user())))

    def test_check_email(self, isolated_darkweb_data):
        self._assert_flags(_run(darkweb_router.check_email(
            _JsonRequest({"email": "a@example.com"}), user=_fake_user())))

    def test_threat_report(self, isolated_darkweb_data):
        self._assert_flags(_run(darkweb_router.threat_report(
            _JsonRequest({"domain": "example.com"}), user=_fake_user())))

    def test_tor_monitor(self):
        self._assert_flags(_run(darkweb_router.tor_monitor(user=_fake_user())))

    def test_live_paste_scanner_is_not_flagged(self):
        result = _run(darkweb_router.scan_paste(
            _JsonRequest({"content": "nothing sensitive here"}), user=_fake_user()))
        assert "deprecated" not in result
        assert "simulated" not in result
