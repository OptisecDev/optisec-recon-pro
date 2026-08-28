"""
Tests for the per-user license-tier feature gate (web/license.py::
require_feature_or_402), wired into every pro/enterprise-classified
endpoint across web/routers/.

Before this fix, require_feature_or_402() read a single installation-wide
license from data/license.json (web.license.get_license()) and applied it
to every request regardless of who made it. A freshly registered
FREE-tier account (users.subscription_tier == "free") got full PRO access
to all 63 gated endpoints whenever the *installation* happened to hold an
active PRO/ENTERPRISE license -- the gate never looked at the requesting
user at all. require_feature_or_402() now takes the requesting `user` and
checks that account's own subscription_tier (upgraded per-user by
redeeming a LicenseKey via web/routers/license_routes.py, independent of
the instance-wide engine in this module).

The instance-wide engine (get_license()/data/license.json) still exists
for the two machine-to-machine federation endpoints (no user identity to
check), now gated by require_instance_feature_or_402() -- see
TestInstanceWideGateForFederationPeers below -- and for the admin
/license page that activates a self-hosted deployment's own key.

Five layers, mirroring tests/test_autonomous_rt_router.py's conventions:
  1. Unit tests directly against require_feature_or_402 (no HTTP, no DB).
  2. A representative router handler per tier (pro + enterprise), called
     directly like tests/test_autonomous_rt_router.py does, to prove the
     gate is actually wired into real endpoints, not just exercised in
     isolation.
  3. One full-stack TestClient test proving the license-tier gate and the
     pre-existing RBAC gate (require_admin) compose -- neither bypasses the
     other -- on web/routers/vpn.py's POST /vpn/api/peers, which requires
     both an admin role and the "vpn" (pro) feature.
  4. A full-stack TestClient matrix seeding three real users -- free, pro,
     enterprise -- against a pro endpoint and an enterprise endpoint, to
     prove per-user gating end to end (this is the scenario that was
     broken: a free-tier user reaching pro/enterprise routes).
  5. Rendered-HTML assertions (TestRenderedTemplatesMatchUserTier below):
     the 402 gate above was the real vulnerability and is now fixed, but
     web/templates/base.html and license.html independently called
     lic.has_feature() -- the *installation's* instance-wide license --
     for their upgrade lock icons and feature-comparison table, instead of
     looking at the signed-in user's own subscription_tier like the 402
     gate now does. That meant a free-tier user could see a feature
     rendered as unlocked (no lock icon / highlighted table row) while
     still getting a 402 the moment they actually used it. Both templates
     now call the shared web.license.user_has_feature(user, feature)
     helper (a Jinja global), so these tests parse the actual rendered
     HTML body -- not just the status code -- to confirm the lock icons
     in base.html's sidebar and the active-row highlighting in
     license.html's feature table agree with the requesting user's real
     tier, for all three tiers.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from bs4 import BeautifulSoup
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.license as license_module
from web.license import require_feature_or_402, require_instance_feature_or_402, TIER_FEATURES, License
from web.database import Base, get_db
from web.models import User
from web.auth import create_access_token, hash_password
import web.app as app_module
import web.routers.vpn as vpn_router
import web.routers.attack_navigator as navigator_router
import web.routers.autonomous_rt as art_router


def _run(coro):
    return asyncio.run(coro)


def _fake_user(tier: str, role: str = "viewer") -> User:
    return User(id=1, username="u", email="u@example.com", password_hash="x",
                role=role, subscription_tier=tier)


# ── 1. Unit tests on require_feature_or_402 ──────────────────────────────────

class TestRequireFeatureOr402:
    def test_free_tier_rejects_pro_feature(self):
        with pytest.raises(HTTPException) as exc_info:
            require_feature_or_402("vpn", _fake_user("free"))
        assert exc_info.value.status_code == 402
        assert "PRO" in exc_info.value.detail or "ENTERPRISE" in exc_info.value.detail

    def test_free_tier_rejects_enterprise_feature(self):
        with pytest.raises(HTTPException) as exc_info:
            require_feature_or_402("federation", _fake_user("free"))
        assert exc_info.value.status_code == 402

    def test_pro_tier_allows_pro_feature(self):
        require_feature_or_402("vpn", _fake_user("pro"))  # must not raise

    def test_pro_tier_rejects_enterprise_feature(self):
        with pytest.raises(HTTPException) as exc_info:
            require_feature_or_402("attack_navigator", _fake_user("pro"))
        assert exc_info.value.status_code == 402
        assert "ENTERPRISE" in exc_info.value.detail

    def test_enterprise_tier_allows_pro_feature(self):
        require_feature_or_402("vpn", _fake_user("enterprise"))  # must not raise

    def test_enterprise_tier_allows_enterprise_feature(self):
        require_feature_or_402("attack_navigator", _fake_user("enterprise"))  # must not raise

    def test_missing_subscription_tier_defaults_to_free(self):
        """A user row with no subscription_tier set (e.g. never flushed
        through the ORM, or a pre-migration row) must not silently pass
        as an unrecognized/all-access tier."""
        user = User(id=1, username="u", email="u@example.com", password_hash="x", role="viewer")
        user.subscription_tier = None
        with pytest.raises(HTTPException) as exc_info:
            require_feature_or_402("vpn", user)
        assert exc_info.value.status_code == 402

    def test_unrecognized_subscription_tier_defaults_to_free(self):
        user = _fake_user("not-a-real-tier")
        with pytest.raises(HTTPException) as exc_info:
            require_feature_or_402("vpn", user)
        assert exc_info.value.status_code == 402

    def test_instance_license_no_longer_grants_per_user_access(self):
        """The bug this fix closes: activating a PRO/ENTERPRISE license on
        the installation must not, by itself, grant a free-tier account
        access to pro/enterprise features."""
        enterprise_lic = License(
            tier="enterprise", issued_to="test", email="",
            issued_at="2026-01-01T00:00:00", expires_at="2099-01-01T00:00:00", key="TEST",
            features=TIER_FEATURES["enterprise"], max_targets=-1, max_scans_day=-1, max_users=-1,
        )
        original = license_module._current_license
        license_module._current_license = enterprise_lic
        try:
            with pytest.raises(HTTPException) as exc_info:
                require_feature_or_402("vpn", _fake_user("free"))
            assert exc_info.value.status_code == 402
        finally:
            license_module._current_license = original


class TestRequireInstanceFeatureOr402:
    """The instance-wide gate, kept only for machine-to-machine endpoints
    with no user identity (web/routers/federation.py's /api/federation/*,
    authenticated by a shared node key)."""

    def test_free_instance_license_rejects(self, monkeypatch):
        free_lic = License(
            tier="free", issued_to="test", email="",
            issued_at="2026-01-01T00:00:00", expires_at="2099-01-01T00:00:00", key="FREE",
            features=TIER_FEATURES["free"], max_targets=3, max_scans_day=10, max_users=1,
        )
        monkeypatch.setattr(license_module, "get_license", lambda: free_lic)
        with pytest.raises(HTTPException) as exc_info:
            require_instance_feature_or_402("federation")
        assert exc_info.value.status_code == 402

    def test_enterprise_instance_license_allows(self, monkeypatch):
        """federation is enterprise-classified (see TIER_FEATURES)."""
        ent_lic = License(
            tier="enterprise", issued_to="test", email="",
            issued_at="2026-01-01T00:00:00", expires_at="2099-01-01T00:00:00", key="TEST",
            features=TIER_FEATURES["enterprise"], max_targets=-1, max_scans_day=-1, max_users=-1,
        )
        monkeypatch.setattr(license_module, "get_license", lambda: ent_lic)
        require_instance_feature_or_402("federation")  # must not raise


# ── 2. Representative router handlers, called directly ──────────────────────

class TestVpnRouterIsGated:
    """vpn.py's feature is "vpn", classified pro."""

    def test_free_tier_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            _run(vpn_router.vpn_status(user=_fake_user("free")))
        assert exc_info.value.status_code == 402

    def test_pro_tier_succeeds(self, monkeypatch):
        monkeypatch.setattr(
            "modules.vpn.wireguard.get_wg_status",
            lambda: asyncio.sleep(0, result={"running": True}),
        )
        result = _run(vpn_router.vpn_status(user=_fake_user("pro")))
        assert result == {"running": True}


class TestAttackNavigatorRouterIsGated:
    """attack_navigator.py's feature is "attack_navigator", classified enterprise."""

    def test_pro_tier_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            _run(navigator_router.get_matrix(user=_fake_user("pro")))
        assert exc_info.value.status_code == 402
        assert "ENTERPRISE" in exc_info.value.detail

    def test_enterprise_tier_succeeds(self, monkeypatch):
        monkeypatch.setattr(
            "modules.threat_intel.attack_navigator.get_full_matrix",
            lambda: {"tactics": []},
        )
        result = _run(navigator_router.get_matrix(user=_fake_user("enterprise")))
        assert result == {"tactics": []}


class TestAutonomousRedTeamRouterIsGated:
    """autonomous_rt.py's feature is "autonomous_redteam", classified enterprise."""

    def test_free_tier_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            _run(art_router.list_sessions(user=_fake_user("free")))
        assert exc_info.value.status_code == 402

    def test_enterprise_tier_succeeds(self, monkeypatch):
        monkeypatch.setattr(
            "modules.ai_advanced.autonomous_redteam.list_sessions",
            lambda: [],
        )
        result = _run(art_router.list_sessions(user=_fake_user("enterprise")))
        assert result == {"sessions": []}


# ── 3 & 4. Full-stack TestClient tests ───────────────────────────────────────

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


class TestVpnAddPeerComposesRbacAndLicenseGate:
    """POST /vpn/api/peers requires both an admin role (RBAC, pre-existing)
    and the "vpn" pro feature (license tier, this change) -- neither gate
    should let the other's failure through."""

    def test_admin_role_but_free_tier_is_rejected_by_license_gate(self, client, monkeypatch):
        c, session_factory = client
        token = _seed_user_token(session_factory, "admin1", "admin", "free")
        resp = c.post(
            "/vpn/api/peers", json={"name": "peer1"},
            cookies={"access_token": token},
        )
        assert resp.status_code == 402

    def test_analyst_role_with_enterprise_tier_is_rejected_by_rbac(self, client, monkeypatch):
        c, session_factory = client
        token = _seed_user_token(session_factory, "analyst1", "analyst", "enterprise")
        resp = c.post(
            "/vpn/api/peers", json={"name": "peer1"},
            cookies={"access_token": token},
        )
        assert resp.status_code == 403

    def test_admin_role_with_pro_tier_succeeds(self, client, monkeypatch):
        c, session_factory = client
        monkeypatch.setattr(
            "modules.vpn.wireguard.add_peer",
            lambda **kw: {"name": kw.get("name"), "config": "stub"},
        )
        token = _seed_user_token(session_factory, "admin2", "admin", "pro")
        resp = c.post(
            "/vpn/api/peers", json={"name": "peer1"},
            cookies={"access_token": token},
        )
        assert resp.status_code == 200


class TestThreeTierMatrixEndToEnd:
    """The core regression this fix closes: three real, DB-seeded accounts
    at free/pro/enterprise subscription_tier, hitting a pro-classified
    endpoint (VPN) and an enterprise-classified endpoint (ATT&CK
    Navigator) over the real HTTP stack (auth, RBAC, and the license
    gate all wired exactly as in production)."""

    def test_free_user_rejected_from_pro_and_enterprise_features(self, client):
        c, session_factory = client
        token = _seed_user_token(session_factory, "free_user", "admin", "free")
        cookies = {"access_token": token}
        assert c.get("/vpn/api/status", cookies=cookies).status_code == 402
        assert c.get("/attack-navigator/api/matrix", cookies=cookies).status_code == 402

    def test_pro_user_allowed_pro_rejected_enterprise(self, client, monkeypatch):
        c, session_factory = client
        monkeypatch.setattr(
            "modules.vpn.wireguard.get_wg_status",
            lambda: asyncio.sleep(0, result={"running": True}),
        )
        token = _seed_user_token(session_factory, "pro_user", "admin", "pro")
        cookies = {"access_token": token}
        assert c.get("/vpn/api/status", cookies=cookies).status_code == 200
        assert c.get("/attack-navigator/api/matrix", cookies=cookies).status_code == 402

    def test_enterprise_user_allowed_everything(self, client, monkeypatch):
        c, session_factory = client
        monkeypatch.setattr(
            "modules.vpn.wireguard.get_wg_status",
            lambda: asyncio.sleep(0, result={"running": True}),
        )
        monkeypatch.setattr(
            "modules.threat_intel.attack_navigator.get_full_matrix",
            lambda: {"tactics": []},
        )
        token = _seed_user_token(session_factory, "ent_user", "admin", "enterprise")
        cookies = {"access_token": token}
        assert c.get("/vpn/api/status", cookies=cookies).status_code == 200
        assert c.get("/attack-navigator/api/matrix", cookies=cookies).status_code == 200


# ── 5. Rendered-HTML assertions: templates must match the user's own tier ───

def _nav_locked(html: str, href: str) -> bool:
    """Whether the sidebar nav item linking to `href` (base.html) is
    rendered with a lock icon."""
    soup = BeautifulSoup(html, "html.parser")
    link = soup.select_one(f'a[href="{href}"]')
    assert link is not None, f"nav item for {href!r} not found in rendered HTML"
    return link.select_one(".nav-lock") is not None


def _feature_row_active(html: str, feat_id: str) -> bool:
    """Whether the feature-comparison table row (license.html) for
    `feat_id` carries the lic-row-active highlight class."""
    soup = BeautifulSoup(html, "html.parser")
    for row in soup.select("table.lic-table tbody tr"):
        divs = row.select("td div")
        if divs and divs[-1].get_text(strip=True) == feat_id:
            return "lic-row-active" in (row.get("class") or [])
    raise AssertionError(f"feature row for {feat_id!r} not found in rendered HTML")


class TestSidebarLockIconsMatchUserTier:
    """base.html's sidebar renders a lock icon per pro/enterprise nav item.
    "/" (the dashboard) is a good page to check it on because it has no
    feature gate of its own -- any authenticated user can load it -- so a
    free-tier user reaching it must still see every premium item locked."""

    def test_free_tier_sees_every_premium_item_locked(self, client):
        c, session_factory = client
        token = _seed_user_token(session_factory, "free_nav", "admin", "free")
        html = c.get("/", cookies={"access_token": token}).text
        for href in ("/vpn", "/bug-bounty", "/attack-navigator", "/federation"):
            assert _nav_locked(html, href), f"{href} should be locked for free tier"

    def test_pro_tier_sees_pro_unlocked_enterprise_locked(self, client):
        c, session_factory = client
        token = _seed_user_token(session_factory, "pro_nav", "admin", "pro")
        html = c.get("/", cookies={"access_token": token}).text
        # "vpn" and "bug_bounty" are pro-tier features (TIER_FEATURES["pro"]).
        assert not _nav_locked(html, "/vpn"), "vpn should be unlocked for pro tier"
        assert not _nav_locked(html, "/bug-bounty"), "bug_bounty should be unlocked for pro tier"
        # "attack_navigator" and "federation" are enterprise-only.
        assert _nav_locked(html, "/attack-navigator"), "attack_navigator should stay locked for pro tier"
        assert _nav_locked(html, "/federation"), "federation should stay locked for pro tier"

    def test_enterprise_tier_sees_nothing_locked(self, client):
        c, session_factory = client
        token = _seed_user_token(session_factory, "ent_nav", "admin", "enterprise")
        html = c.get("/", cookies={"access_token": token}).text
        for href in ("/vpn", "/bug-bounty", "/attack-navigator", "/federation"):
            assert not _nav_locked(html, href), f"{href} should be unlocked for enterprise tier"


class TestLicensePageFeatureTableMatchesUserTier:
    """license.html's feature-comparison table highlights the row for each
    feature the *requesting user* currently has, independent of whatever
    instance-wide license (data/license.json) the installation holds."""

    def test_free_tier_only_free_rows_active(self, client):
        c, session_factory = client
        token = _seed_user_token(session_factory, "free_lic", "admin", "free")
        html = c.get("/license", cookies={"access_token": token}).text
        assert _feature_row_active(html, "scan_xss"), "free feature should be active for free tier"
        assert not _feature_row_active(html, "vpn"), "pro feature should not be active for free tier"
        assert not _feature_row_active(html, "federation"), "enterprise feature should not be active for free tier"

    def test_pro_tier_pro_rows_active_enterprise_rows_not(self, client):
        c, session_factory = client
        token = _seed_user_token(session_factory, "pro_lic", "admin", "pro")
        html = c.get("/license", cookies={"access_token": token}).text
        assert _feature_row_active(html, "scan_xss"), "free feature should be active for pro tier"
        assert _feature_row_active(html, "vpn"), "pro feature should be active for pro tier"
        assert not _feature_row_active(html, "federation"), "enterprise feature should not be active for pro tier"

    def test_enterprise_tier_all_rows_active(self, client):
        c, session_factory = client
        token = _seed_user_token(session_factory, "ent_lic", "admin", "enterprise")
        html = c.get("/license", cookies={"access_token": token}).text
        assert _feature_row_active(html, "scan_xss")
        assert _feature_row_active(html, "vpn")
        assert _feature_row_active(html, "federation")
