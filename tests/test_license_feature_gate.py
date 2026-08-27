"""
Tests for the license-tier feature gate (web/license.py::require_feature_or_402),
wired into every pro/enterprise-classified endpoint across web/routers/.

Before this gate existed, require_feature() was defined but never called
anywhere outside its own module -- any authenticated user, regardless of
license tier, could reach VPN, AI Firewall, Honeypot, Quantum, NGFW, ATT&CK
Navigator, Federation, Autonomous Red Team, Threat Sharing and every other
pro/enterprise router. require_feature_or_402() wraps require_feature()'s
(allowed, message) tuple into an HTTPException(402), mirroring
web.auth.require_roles's inline-call pattern (require_analyst_or_admin(user)).

Three layers, mirroring tests/test_autonomous_rt_router.py's conventions:
  1. Unit tests directly against require_feature_or_402 (no HTTP, no DB).
  2. A representative router handler per tier (pro + enterprise), called
     directly like tests/test_autonomous_rt_router.py does, to prove the
     gate is actually wired into real endpoints, not just exercised in
     isolation.
  3. One full-stack TestClient test proving the license-tier gate and the
     pre-existing RBAC gate (require_admin) compose -- neither bypasses the
     other -- on web/routers/vpn.py's POST /vpn/api/peers, which requires
     both an admin role and the "vpn" (pro) feature.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.license as license_module
from web.license import require_feature_or_402, TIER_FEATURES, License
from web.database import Base, get_db
from web.models import User
from web.auth import create_access_token, hash_password
import web.app as app_module
import web.routers.vpn as vpn_router
import web.routers.attack_navigator as navigator_router
import web.routers.autonomous_rt as art_router


def _run(coro):
    return asyncio.run(coro)


def _license(tier: str) -> License:
    return License(
        tier=tier, issued_to="test", email="",
        issued_at="2026-01-01T00:00:00", expires_at="2099-01-01T00:00:00", key="TEST",
        features=TIER_FEATURES[tier],
        max_targets=-1, max_scans_day=-1, max_users=-1,
    )


def _set_license(monkeypatch, tier: str) -> None:
    monkeypatch.setattr(license_module, "get_license", lambda: _license(tier))


def _fake_user(role: str = "viewer") -> User:
    return User(id=1, username="u", email="u@example.com", password_hash="x", role=role)


# ── 1. Unit tests on require_feature_or_402 ──────────────────────────────────

class TestRequireFeatureOr402:
    def test_free_tier_rejects_pro_feature(self, monkeypatch):
        _set_license(monkeypatch, "free")
        with pytest.raises(HTTPException) as exc_info:
            require_feature_or_402("vpn")
        assert exc_info.value.status_code == 402
        assert "PRO" in exc_info.value.detail or "ENTERPRISE" in exc_info.value.detail

    def test_free_tier_rejects_enterprise_feature(self, monkeypatch):
        _set_license(monkeypatch, "free")
        with pytest.raises(HTTPException) as exc_info:
            require_feature_or_402("federation")
        assert exc_info.value.status_code == 402

    def test_pro_tier_allows_pro_feature(self, monkeypatch):
        _set_license(monkeypatch, "pro")
        require_feature_or_402("vpn")  # must not raise

    def test_pro_tier_rejects_enterprise_feature(self, monkeypatch):
        _set_license(monkeypatch, "pro")
        with pytest.raises(HTTPException) as exc_info:
            require_feature_or_402("attack_navigator")
        assert exc_info.value.status_code == 402
        assert "ENTERPRISE" in exc_info.value.detail

    def test_enterprise_tier_allows_pro_feature(self, monkeypatch):
        _set_license(monkeypatch, "enterprise")
        require_feature_or_402("vpn")  # must not raise

    def test_enterprise_tier_allows_enterprise_feature(self, monkeypatch):
        _set_license(monkeypatch, "enterprise")
        require_feature_or_402("attack_navigator")  # must not raise


# ── 2. Representative router handlers, called directly ──────────────────────

class TestVpnRouterIsGated:
    """vpn.py's feature is "vpn", classified pro."""

    def test_free_tier_rejected(self, monkeypatch):
        _set_license(monkeypatch, "free")
        with pytest.raises(HTTPException) as exc_info:
            _run(vpn_router.vpn_status(user=_fake_user()))
        assert exc_info.value.status_code == 402

    def test_pro_tier_succeeds(self, monkeypatch):
        _set_license(monkeypatch, "pro")
        monkeypatch.setattr(
            "modules.vpn.wireguard.get_wg_status",
            lambda: asyncio.sleep(0, result={"running": True}),
        )
        result = _run(vpn_router.vpn_status(user=_fake_user()))
        assert result == {"running": True}


class TestAttackNavigatorRouterIsGated:
    """attack_navigator.py's feature is "attack_navigator", classified enterprise."""

    def test_pro_tier_rejected(self, monkeypatch):
        _set_license(monkeypatch, "pro")
        with pytest.raises(HTTPException) as exc_info:
            _run(navigator_router.get_matrix(user=_fake_user()))
        assert exc_info.value.status_code == 402
        assert "ENTERPRISE" in exc_info.value.detail

    def test_enterprise_tier_succeeds(self, monkeypatch):
        _set_license(monkeypatch, "enterprise")
        monkeypatch.setattr(
            "modules.threat_intel.attack_navigator.get_full_matrix",
            lambda: {"tactics": []},
        )
        result = _run(navigator_router.get_matrix(user=_fake_user()))
        assert result == {"tactics": []}


class TestAutonomousRedTeamRouterIsGated:
    """autonomous_rt.py's feature is "autonomous_redteam", classified enterprise."""

    def test_free_tier_rejected(self, monkeypatch):
        _set_license(monkeypatch, "free")
        with pytest.raises(HTTPException) as exc_info:
            _run(art_router.list_sessions(user=_fake_user()))
        assert exc_info.value.status_code == 402

    def test_enterprise_tier_succeeds(self, monkeypatch):
        _set_license(monkeypatch, "enterprise")
        monkeypatch.setattr(
            "modules.ai_advanced.autonomous_redteam.list_sessions",
            lambda: [],
        )
        result = _run(art_router.list_sessions(user=_fake_user()))
        assert result == {"sessions": []}


# ── 3. RBAC (role) and license-tier gates compose, via the real app ─────────

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
    monkeypatch.setattr(
        "modules.vpn.wireguard.add_peer",
        lambda **kw: {"name": kw.get("name"), "config": "stub"},
    )

    c = TestClient(app_module.app)
    yield c, session_factory

    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def _seed_user_token(session_factory, username: str, role: str) -> str:
    async def go():
        async with session_factory() as db:
            user = User(
                username=username, email=f"{username}@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role=role, is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id
    user_id = _run(go())
    return create_access_token(user_id, role)


class TestVpnAddPeerComposesRbacAndLicenseGate:
    """POST /vpn/api/peers requires both an admin role (RBAC, pre-existing)
    and the "vpn" pro feature (license tier, this change) -- neither gate
    should let the other's failure through."""

    def test_admin_role_but_free_tier_is_rejected_by_license_gate(self, client, monkeypatch):
        c, session_factory = client
        _set_license(monkeypatch, "free")
        token = _seed_user_token(session_factory, "admin1", "admin")
        resp = c.post(
            "/vpn/api/peers", json={"name": "peer1"},
            cookies={"access_token": token},
        )
        assert resp.status_code == 402

    def test_analyst_role_with_enterprise_tier_is_rejected_by_rbac(self, client, monkeypatch):
        c, session_factory = client
        _set_license(monkeypatch, "enterprise")
        token = _seed_user_token(session_factory, "analyst1", "analyst")
        resp = c.post(
            "/vpn/api/peers", json={"name": "peer1"},
            cookies={"access_token": token},
        )
        assert resp.status_code == 403

    def test_admin_role_with_pro_tier_succeeds(self, client, monkeypatch):
        c, session_factory = client
        _set_license(monkeypatch, "pro")
        token = _seed_user_token(session_factory, "admin2", "admin")
        resp = c.post(
            "/vpn/api/peers", json={"name": "peer1"},
            cookies={"access_token": token},
        )
        assert resp.status_code == 200
