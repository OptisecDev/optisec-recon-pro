"""Tests for the real-data rewrite of modules/threat_intel/global_feed.py's
Threat Feed trio (get_threat_map, get_campaigns, correlate_iocs).

Background: these three used to be fabricated —
  - get_threat_map() jittered a hardcoded THREAT_MAP_POINTS table
    (random attacks_per_hour/active_campaigns) on every call.
  - get_campaigns() returned four hardcoded fictional APT campaigns
    (ATTACK_CAMPAIGNS) with invented 78-94% "confidence".
  - correlate_iocs() matched submitted IOCs against those same fictional
    campaigns and returned an "attribution_confidence" computed from that
    fake matching.

All three now derive from real data only (local `iocs` table for the map
and correlation matches, live AlienVault OTX pulses for campaigns) and
return an honest empty/unavailable state instead of a fabricated fallback
when no real data is available. Network calls (OTX, ip-api.com/ipinfo.io)
are mocked so these tests run fully offline.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base
from web.models import User, Ioc  # noqa: F401 — Ioc import registers the table on Base.metadata
from modules.ioc.ioc_engine import IOCRepository
import modules.threat_intel.global_feed as gf
import modules.threat_intel.otx_feed as otx_feed
import modules.osint.geo_intel as geo_intel


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def db_factory():
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
    yield session_factory
    _run(engine.dispose())


# ── get_threat_map(): real geolocated IPs, no jitter ──────────────────────────

async def _fake_geolocate_ip(ip: str) -> dict:
    mapping = {
        "1.2.3.4": {"lat": 10.0, "lon": 20.0, "country": "Testland", "country_code": "TL"},
        "5.6.7.8": {"lat": 10.5, "lon": 20.5, "country": "Testland", "country_code": "TL"},
        "9.9.9.9": {"error": "lookup failed"},  # simulates both providers failing
    }
    return mapping.get(ip, {"error": "not found"})


class TestGetThreatMapRealGeolocation:
    def test_empty_when_no_ip_iocs(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await gf.get_threat_map(db)
        result = _run(go())
        assert result["points"] == []
        assert result["total_known_malicious_ips"] == 0
        assert result["top_origin"] is None
        assert "map_jitter" not in result
        assert "attacks_per_hour" not in result

    def test_groups_real_ips_by_country_with_real_coordinates(self, monkeypatch, tmp_path, db_factory):
        monkeypatch.setattr(gf, "GEO_CACHE_FILE", tmp_path / "geo_cache.json")
        monkeypatch.setattr(geo_intel, "geolocate_ip", _fake_geolocate_ip)

        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "1.2.3.4", source="otx", confidence_score=80.0)
                await repo.create("ip", "5.6.7.8", source="otx", confidence_score=70.0)
                await repo.create("ip", "9.9.9.9", source="otx", confidence_score=60.0)
                await db.commit()
                return await gf.get_threat_map(db)

        result = _run(go())
        # 3 distinct real IPs total, even though one fails to geolocate.
        assert result["total_known_malicious_ips"] == 3
        assert len(result["points"]) == 1
        point = result["points"][0]
        assert point["country"] == "Testland"
        assert point["code"] == "TL"
        # Averaged real coordinates of the two IPs that resolved for this country.
        assert point["lat"] == pytest.approx(10.25)
        assert point["lon"] == pytest.approx(20.25)
        # Only the 2 geolocatable IPs count toward this country's bucket —
        # the unresolvable 9.9.9.9 is omitted, never guessed.
        assert point["known_malicious_ioc_count"] == 2
        assert result["top_origin"] == "Testland"
        assert "map_jitter" not in result
        assert "attacks_per_hour" not in point

    def test_geo_cache_avoids_a_second_network_call(self, monkeypatch, tmp_path, db_factory):
        monkeypatch.setattr(gf, "GEO_CACHE_FILE", tmp_path / "geo_cache.json")
        calls = []

        async def counting_geolocate(ip):
            calls.append(ip)
            return await _fake_geolocate_ip(ip)

        monkeypatch.setattr(geo_intel, "geolocate_ip", counting_geolocate)

        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "1.2.3.4", source="otx", confidence_score=80.0)
                await db.commit()
                await gf.get_threat_map(db)
                await gf.get_threat_map(db)

        _run(go())
        assert calls == ["1.2.3.4"], "second call should be served from the TTL cache, not refetched"


# ── get_campaigns(): real OTX pulses, honest empty state otherwise ───────────

class TestGetCampaignsRealOtx:
    def test_no_api_key_returns_honest_empty_state(self):
        result = _run(gf.get_campaigns(""))
        assert result["campaigns"] == []
        assert result["otx_connected"] is False
        assert result["note"]

    def test_otx_failure_returns_honest_empty_state(self, monkeypatch):
        def boom(api_key, limit=20):
            raise RuntimeError("OTX unreachable")
        monkeypatch.setattr(otx_feed, "fetch_otx_pulse_campaigns", boom)
        result = _run(gf.get_campaigns("fake-key"))
        assert result["campaigns"] == []
        assert result["otx_connected"] is False

    def test_real_pulse_fields_pass_through_with_no_invented_confidence(self, monkeypatch):
        real_pulse = {
            "id": "abc123", "name": "Real Pulse", "author": "AlienVault",
            "actor": "", "unverified_adversary": "Phishing Topic",
            "description": "A real pulse description.",
            "created": "2026-01-01T00:00:00", "modified": "2026-01-02T00:00:00",
            "target_sectors": [], "countries_targeted": [], "techniques": ["T1566"],
            "tags": [], "malware_families": [], "ioc_count": 5, "references": [],
        }
        monkeypatch.setattr(otx_feed, "fetch_otx_pulse_campaigns", lambda api_key, limit=20: [real_pulse])
        result = _run(gf.get_campaigns("fake-key"))
        assert result["otx_connected"] is True
        assert result["campaigns"] == [real_pulse]
        for camp in result["campaigns"]:
            assert "confidence" not in camp, "no fabricated confidence score may be synthesized"
            assert "status" not in camp, "no invented active/monitoring status"


# ── correlate_iocs(): real local-DB matches, no campaign attribution ─────────

class TestCorrelateIocsRealEvidence:
    def test_no_match_reports_zero_rate_not_a_guess(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await gf.correlate_iocs([{"type": "ip", "value": "203.0.113.99"}], db)
        result = _run(go())
        assert result["known_matches"] == []
        assert result["match_rate"] == 0.0
        assert "campaign_matches" not in result
        assert "attribution_confidence" not in result

    def test_real_db_match_surfaces_real_evidence_fields(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create(
                    "ip", "203.0.113.5", source="otx", confidence_score=91.0,
                    tags=["pulse:Real Pulse Name"],
                )
                await db.commit()
                return await gf.correlate_iocs([{"type": "ip", "value": "203.0.113.5"}], db)
        result = _run(go())
        assert len(result["known_matches"]) == 1
        match = result["known_matches"][0]
        assert match["source"] == "otx"
        assert match["confidence_score"] == 91.0
        assert match["pulses"] == ["Real Pulse Name"]
        assert result["match_rate"] == 100.0

    def test_shared_subnet_relationship_is_real_structural_math(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await gf.correlate_iocs(
                    [{"type": "ip", "value": "198.51.100.10"}, {"type": "ip", "value": "198.51.100.20"}], db,
                )
        result = _run(go())
        assert any(r["type"] == "shared_subnet" and r["subnet"] == "198.51.100.0/24" for r in result["relationships"])

    def test_no_fabricated_campaign_name_or_confidence_anywhere(self, db_factory):
        """Regression: the old version matched against four hardcoded
        fictional APT campaigns with 78-94% invented confidence. Neither
        concept should exist in the new output at all."""
        async def go():
            async with db_factory() as db:
                return await gf.correlate_iocs(
                    [{"type": "ip", "value": "203.0.113.5"}, {"type": "domain", "value": "evil.example"}], db,
                )
        result = _run(go())
        assert "campaign_matches" not in result
        assert "attribution_confidence" not in result
        assert not hasattr(gf, "ATTACK_CAMPAIGNS")
