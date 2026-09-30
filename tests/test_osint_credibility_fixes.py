"""
Regression coverage for the 2026-09-30 OSINT credibility audit fixes:

  - National ID: removed entirely (undocumented, unverified guess at the
    real NCCID field layout, presented with full confidence for any
    syntactically-valid 12-digit input -- see git history for the writeup).
  - Cell Tower: renamed to Carrier/MCC-MNC Lookup; LAC/Cell ID are only
    echoed back, never resolved to a real tower location, and every
    response now carries an explicit disclaimer.
  - Silent-fallback guard: OSINT sources that require an API key must
    degrade to an explicit `checked: False` / `status` message, never a
    "complete-looking" fabricated result.

Same TestClient + dependency-override pattern as
tests/test_osint_router_rate_limits.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
from web.models import User
import web.app as app_module
import web.routers.osint as osint_module
import modules.osint.cell_tower as cell_tower
import modules.osint.device_fingerprint as device_fingerprint
import modules.osint.phone_social as phone_social


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
        async with TestSessionLocal() as session:
            user = User(
                username="analyst1", email="analyst1@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused-osint",
                subscription_tier="enterprise",
            )
            session.add(user)
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.username == "analyst1"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[osint_module._user] = _user_override
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


class TestNationalIdRemoved:
    def test_endpoint_gone(self, client):
        r = client.post("/api/osint/national-id", json={"id": "100012345678"})
        assert r.status_code == 404

    def test_module_removed(self):
        with pytest.raises(ModuleNotFoundError):
            import modules.osint.national_id  # noqa: F401

    def test_router_source_has_no_reference(self):
        source = open(osint_module.__file__, encoding="utf-8").read()
        assert "national_id" not in source
        assert "national-id" not in source

    def test_template_has_no_national_id_tab(self):
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "web", "templates", "osint.html",
        )
        html = open(template_path, encoding="utf-8").read()
        assert "tab-natid" not in html
        assert "tab-btn-natid" not in html
        assert "runNatID" not in html
        assert "/api/osint/national-id" not in html


class TestCellTowerHonesty:
    def test_unknown_carrier_has_no_fabricated_location_claim(self):
        result = cell_tower.lookup_cell_tower(999, 99)
        assert result["found"] is False
        assert "coverage_pattern" not in result
        assert result["disclaimer"] == cell_tower.DISCLAIMER

    def test_known_carrier_echoes_lac_and_cell_id_without_resolving_them(self):
        result = cell_tower.lookup_cell_tower(418, 20, lac=12345, cell_id=98765)
        assert result["found"] is True
        assert "coverage_pattern" not in result, "old geolocation-flavored field must be gone"
        echoes = " ".join(result["input_echo"])
        assert "12345" in echoes and "not used in any real lookup" in echoes
        assert "98765" in echoes and "not used in any real lookup" in echoes
        assert result["disclaimer"] == cell_tower.DISCLAIMER

    def test_carrier_notes_never_mention_lac_or_cell_id(self):
        """carrier_notes is derived only from the static MCC/MNC table --
        it must never fold LAC/Cell ID in as if they were resolved."""
        result = cell_tower.lookup_cell_tower(418, 20, lac=12345, cell_id=98765)
        for note in result["carrier_notes"]:
            assert "LAC" not in note
            assert "Cell ID" not in note

    def test_no_real_tower_geolocation_call_exists(self):
        """The module docstring is allowed to *name* OpenCelliD/etc. to
        explain what this module deliberately does NOT do; what must be
        true is that it makes no outbound network call at all."""
        import ast
        tree = ast.parse(open(cell_tower.__file__, encoding="utf-8").read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert imported.isdisjoint({"aiohttp", "httpx", "requests", "socket", "urllib"}), imported


class TestDeviceChipsetHonesty:
    def test_brand_only_match_is_unconfirmed_and_lists_all_possibilities(self):
        # Samsung Galaxy S23 Ultra (SM-S918B) global variant actually ships
        # Snapdragon, not Exynos -- the exact case that motivated this fix.
        ua = ("Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.137 Mobile Safari/537.36")
        result = device_fingerprint.fingerprint_device(ua)
        hw = result["hardware"]
        assert hw["chipset_confirmed"] is False
        assert set(hw["possible_chipsets"]) == {"Exynos", "Snapdragon"}
        assert "chipset_family" not in hw

    def test_explicit_chipset_string_in_ua_is_confirmed(self):
        ua = "Mozilla/5.0 (Linux; Android 13; Snapdragon 8 Gen 2) AppleWebKit/537.36"
        result = device_fingerprint.fingerprint_device(ua)
        hw = result["hardware"]
        assert hw["chipset_confirmed"] is True
        assert hw["possible_chipsets"] == ["Qualcomm Snapdragon"]

    def test_guess_chipset_singular_function_removed(self):
        assert not hasattr(device_fingerprint, "_guess_chipset")


class TestNoSilentFallbackOnMissingApiKey:
    """An OSINT source that needs a key must say so explicitly -- never
    return a "complete" result (valid/carrier/location fields populated)
    when the key is absent."""

    @pytest.fixture(autouse=True)
    def _no_keys(self, monkeypatch):
        for key in ("HIBP_API_KEY", "NUMVERIFY_API_KEY", "ABSTRACTAPI_PHONE_KEY"):
            monkeypatch.delenv(key, raising=False)

    def test_hibp_explicit_not_checked(self):
        result = _run(phone_social._check_hibp(None, {"national": "07701234567", "e164": "+9647701234567"}))
        assert result["checked"] is False
        assert "HIBP_API_KEY" in result["status"]
        assert result["breach_count"] == 0 and result["pastes"] == []

    def test_numverify_explicit_not_checked(self):
        result = _run(phone_social._check_numverify(None, "+9647701234567"))
        assert result["checked"] is False
        assert "valid" not in result

    def test_abstractapi_explicit_not_checked(self):
        result = _run(phone_social._check_abstractapi(None, "+9647701234567"))
        assert result["checked"] is False
        assert "valid" not in result
