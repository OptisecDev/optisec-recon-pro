"""
Tests for the Threat Sharing module: local IOC collection
(modules/threat_intel/threat_sharing.py), export (STIX/CSV/JSON), the
opt-in manual OTX share flow, and the router's persistence/query helpers
(web/routers/threat_sharing.py).

Mirrors tests/test_honeypot.py's conventions: plain pytest, async functions
driven via asyncio.run(), monkeypatch for isolation, an in-memory SQLite
engine wired in place of web.database.SessionLocal, and no real network
calls (requests.post is monkeypatched, never actually invoked).
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.database as database
from web.database import Base
from web.models import User, HoneypotEvent, DarkWebMonitor, DarkWebAlert, ThreatShare
import modules.threat_intel.threat_sharing as sharing
import web.routers.threat_sharing as ts_router


def _run(coro):
    return asyncio.run(coro)


# ── Isolated in-memory DB fixture (same pattern as test_honeypot.py) ───────

@pytest.fixture
def db(monkeypatch):
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
    monkeypatch.setattr(database, "SessionLocal", TestSessionLocal)
    yield TestSessionLocal
    _run(engine.dispose())


async def _seed_honeypot_event(session_factory, **overrides) -> int:
    defaults = dict(
        service="ssh", source_ip="1.2.3.4", source_port=1234, dest_port=2222,
        payload="x", session_data={}, country="RU", country_code="RU", city=None, isp=None,
        abuse_score=90, risk_level="CRITICAL", enrichment={}, created_at=datetime.utcnow(),
    )
    defaults.update(overrides)
    async with session_factory() as db_:
        row = HoneypotEvent(**defaults)
        db_.add(row)
        await db_.commit()
        await db_.refresh(row)
        return row.id


async def _seed_user(session_factory) -> int:
    async with session_factory() as db_:
        user = User(username="u1", email="u1@example.com", password_hash="x",
                    role="analyst", api_key_hash="k1", is_active=True)
        db_.add(user)
        await db_.commit()
        await db_.refresh(user)
        return user.id


async def _seed_monitor(session_factory, user_id: int, target: str = "example.com") -> int:
    async with session_factory() as db_:
        m = DarkWebMonitor(user_id=user_id, target=target, target_type="domain", label=target)
        db_.add(m)
        await db_.commit()
        await db_.refresh(m)
        return m.id


async def _seed_alert(session_factory, monitor_id: int, **overrides) -> int:
    defaults = dict(
        monitor_id=monitor_id, fingerprint="fp1", source="paste", severity="medium",
        title="Paste mention", detail={"url": "https://pastebin.com/raw/abc123"},
        discovered_at=datetime.utcnow(),
    )
    defaults.update(overrides)
    async with session_factory() as db_:
        row = DarkWebAlert(**defaults)
        db_.add(row)
        await db_.commit()
        await db_.refresh(row)
        return row.id


# ── 1. validate_ioc — strict shape checks, PII rejection ──────────────────

class TestValidateIoc:
    def test_valid_ipv4(self):
        assert sharing.validate_ioc("ip", "185.234.216.45") == (True, "")

    def test_valid_ipv6(self):
        valid, _ = sharing.validate_ioc("ip", "2001:db8::1")
        assert valid

    def test_invalid_ip(self):
        valid, err = sharing.validate_ioc("ip", "999.999.999.999")
        assert not valid and err

    def test_valid_domain(self):
        assert sharing.validate_ioc("domain", "evil-c2-domain.ru") == (True, "")

    def test_invalid_domain_with_space(self):
        valid, _ = sharing.validate_ioc("domain", "not a domain")
        assert not valid

    def test_valid_md5(self):
        assert sharing.validate_ioc("hash_md5", "d41d8cd98f00b204e9800998ecf8427e") == (True, "")

    def test_md5_wrong_length_rejected(self):
        valid, _ = sharing.validate_ioc("hash_md5", "abcd")
        assert not valid

    def test_valid_sha256(self):
        h = "a" * 64
        assert sharing.validate_ioc("hash_sha256", h) == (True, "")

    def test_valid_cve(self):
        assert sharing.validate_ioc("cve", "CVE-2021-44228") == (True, "")

    def test_invalid_cve_format(self):
        valid, _ = sharing.validate_ioc("cve", "NOT-A-CVE")
        assert not valid

    def test_valid_url(self):
        assert sharing.validate_ioc("url", "http://45.142.212.100/meterpreter.exe") == (True, "")

    def test_invalid_url(self):
        valid, _ = sharing.validate_ioc("url", "not-a-url")
        assert not valid

    def test_rejects_email_shaped_value_regardless_of_type(self):
        valid, err = sharing.validate_ioc("domain", "victim@example.com")
        assert not valid
        assert "email" in err.lower() or "identity" in err.lower()

    def test_rejects_empty_value(self):
        valid, _ = sharing.validate_ioc("ip", "")
        assert not valid

    def test_rejects_unsupported_type(self):
        valid, err = sharing.validate_ioc("username", "someuser")
        assert not valid
        assert "unsupported" in err.lower()


# ── 2. Local IOC collection — honeypot / dark web / vulnerability intel ───

class TestCollectHoneypotIocs:
    def test_collects_high_and_critical_only(self, db):
        async def go():
            await _seed_honeypot_event(db, source_ip="1.1.1.1", risk_level="CRITICAL")
            await _seed_honeypot_event(db, source_ip="2.2.2.2", risk_level="LOW")
            async with db() as db_:
                return await sharing.collect_honeypot_iocs(db_)
        iocs = _run(go())
        assert len(iocs) == 1
        assert iocs[0]["value"] == "1.1.1.1"
        assert iocs[0]["type"] == "ip"
        assert iocs[0]["source_module"] == "honeypot"

    def test_dedupes_by_ip(self, db):
        async def go():
            await _seed_honeypot_event(db, source_ip="1.1.1.1", risk_level="HIGH")
            await _seed_honeypot_event(db, source_ip="1.1.1.1", risk_level="CRITICAL")
            async with db() as db_:
                return await sharing.collect_honeypot_iocs(db_)
        iocs = _run(go())
        assert len(iocs) == 1

    def test_respects_limit(self, db):
        async def go():
            for i in range(5):
                await _seed_honeypot_event(db, source_ip=f"10.0.0.{i}", risk_level="HIGH")
            async with db() as db_:
                return await sharing.collect_honeypot_iocs(db_, limit=2)
        iocs = _run(go())
        assert len(iocs) == 2

    def test_empty_when_no_events(self, db):
        async def go():
            async with db() as db_:
                return await sharing.collect_honeypot_iocs(db_)
        assert _run(go()) == []


class TestCollectDarkwebIocs:
    def test_extracts_paste_url_not_monitor_identity(self, db):
        async def go():
            uid = await _seed_user(db)
            mid = await _seed_monitor(db, uid, target="secret-customer-domain.com")
            await _seed_alert(db, mid, source="paste", detail={"url": "https://pastebin.com/raw/xyz"})
            async with db() as db_:
                return await sharing.collect_darkweb_iocs(db_)
        iocs = _run(go())
        assert len(iocs) == 1
        assert iocs[0]["type"] == "url"
        assert iocs[0]["value"] == "https://pastebin.com/raw/xyz"
        # the monitored target/domain must never leak into the shareable IOC
        for v in iocs[0].values():
            assert "secret-customer-domain.com" not in str(v)

    def test_extracts_github_html_url(self, db):
        async def go():
            uid = await _seed_user(db)
            mid = await _seed_monitor(db, uid)
            await _seed_alert(db, mid, source="github_secret",
                               detail={"html_url": "https://github.com/foo/bar/blob/main/leak.py"})
            async with db() as db_:
                return await sharing.collect_darkweb_iocs(db_)
        iocs = _run(go())
        assert iocs[0]["value"] == "https://github.com/foo/bar/blob/main/leak.py"

    def test_skips_alerts_without_url(self, db):
        async def go():
            uid = await _seed_user(db)
            mid = await _seed_monitor(db, uid)
            await _seed_alert(db, mid, source="paste", detail={})
            async with db() as db_:
                return await sharing.collect_darkweb_iocs(db_)
        assert _run(go()) == []

    def test_ignores_breach_and_threat_actor_sources(self, db):
        async def go():
            uid = await _seed_user(db)
            mid = await _seed_monitor(db, uid)
            await _seed_alert(db, mid, source="breach", detail={"url": "https://example.com/x"})
            await _seed_alert(db, mid, source="threat_actor", detail={"actor": "LockBit"})
            async with db() as db_:
                return await sharing.collect_darkweb_iocs(db_)
        assert _run(go()) == []


class TestCollectVulnerabilityIocs:
    def _patch_kev(self, monkeypatch, vulns):
        async def fake_query_cisa_kev(*a, **kw):
            return {"source": "cisa_kev", "available": True, "cached": True,
                    "count": len(vulns), "vulnerabilities": vulns, "error": None}
        import modules.osint.vulnerability_intelligence as vi
        monkeypatch.setattr(vi, "_query_cisa_kev", fake_query_cisa_kev)

    def test_maps_kev_entries_to_cve_iocs(self, monkeypatch):
        self._patch_kev(monkeypatch, [
            {"cve_id": "CVE-2024-3400", "date_added": "2024-04-12", "vendor_project": "Palo Alto",
             "product": "PAN-OS", "known_ransomware_use": "Unknown"},
            {"cve_id": "CVE-2021-44228", "date_added": "2021-12-10", "vendor_project": "Apache",
             "product": "Log4j", "known_ransomware_use": "Known"},
        ])
        iocs = _run(sharing.collect_vulnerability_iocs())
        assert iocs[0]["value"] == "CVE-2024-3400"  # most recently added first
        assert iocs[0]["type"] == "cve"
        assert iocs[1]["severity"] == "CRITICAL"  # known ransomware use

    def test_skips_entries_without_cve_id(self, monkeypatch):
        self._patch_kev(monkeypatch, [{"date_added": "2024-01-01"}])
        assert _run(sharing.collect_vulnerability_iocs()) == []

    def test_respects_limit(self, monkeypatch):
        self._patch_kev(monkeypatch, [
            {"cve_id": f"CVE-2024-{1000+i}", "date_added": f"2024-01-{i+1:02d}"} for i in range(5)
        ])
        iocs = _run(sharing.collect_vulnerability_iocs(limit=2))
        assert len(iocs) == 2


class TestCollectLocalIocs:
    def test_merges_all_three_sources_with_ids(self, db, monkeypatch):
        async def fake_query_cisa_kev(*a, **kw):
            return {"vulnerabilities": [{"cve_id": "CVE-2024-3400", "date_added": "2024-04-12"}]}
        import modules.osint.vulnerability_intelligence as vi
        monkeypatch.setattr(vi, "_query_cisa_kev", fake_query_cisa_kev)

        async def go():
            await _seed_honeypot_event(db, source_ip="9.9.9.9", risk_level="CRITICAL")
            uid = await _seed_user(db)
            mid = await _seed_monitor(db, uid)
            await _seed_alert(db, mid, source="paste", detail={"url": "https://pastebin.com/raw/1"})
            async with db() as db_:
                return await sharing.collect_local_iocs(db_)
        iocs = _run(go())
        assert len(iocs) == 3
        modules_present = {i["source_module"] for i in iocs}
        assert modules_present == {"honeypot", "darkweb", "vulnerability_intel"}
        assert all("id" in i and len(i["id"]) == 12 for i in iocs)


# ── 3. Export — STIX bundle / CSV ──────────────────────────────────────────

class TestBuildStixBundle:
    def test_builds_valid_indicator_objects(self):
        iocs = [
            {"id": "abc123", "type": "ip", "value": "1.2.3.4", "source_module": "honeypot"},
            {"id": "def456", "type": "cve", "value": "CVE-2021-44228", "source_module": "vulnerability_intel"},
        ]
        bundle = sharing.build_stix_bundle(iocs)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 2
        assert bundle["objects"][0]["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
        assert bundle["objects"][1]["pattern"] == "[vulnerability:name = 'CVE-2021-44228']"
        assert all(o["type"] == "indicator" for o in bundle["objects"])

    def test_skips_unsupported_types(self):
        bundle = sharing.build_stix_bundle([{"id": "x", "type": "weird", "value": "v"}])
        assert bundle["objects"] == []

    def test_empty_input_produces_empty_bundle(self):
        bundle = sharing.build_stix_bundle([])
        assert bundle["objects"] == []
        assert bundle["type"] == "bundle"


class TestBuildCsv:
    def test_includes_header_and_rows(self):
        csv_text = sharing.build_csv([
            {"type": "ip", "value": "1.2.3.4", "source_module": "honeypot", "severity": "HIGH", "last_seen": "2026-01-01"},
        ])
        lines = csv_text.strip().splitlines()
        assert lines[0] == "type,value,source_module,severity,last_seen"
        assert "1.2.3.4" in lines[1]

    def test_empty_iocs_still_has_header(self):
        csv_text = sharing.build_csv([])
        assert csv_text.strip() == "type,value,source_module,severity,last_seen"


# ── 4. share_ioc_to_otx — OTX pulse creation, mocked HTTP ──────────────────

class _FakeResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json_data = json_data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._json_data


class TestShareIocToOtx:
    def test_success_returns_pulse_id_and_url(self, monkeypatch):
        monkeypatch.setattr(sharing.requests, "post",
                             lambda *a, **kw: _FakeResponse(200, {"id": "pulse123"}))
        result = sharing.share_ioc_to_otx("fake-key", "ip", "1.2.3.4")
        assert result["success"] is True
        assert result["pulse_id"] == "pulse123"
        assert "pulse123" in result["pulse_url"]

    def test_http_error_returns_failure_not_raise(self, monkeypatch):
        monkeypatch.setattr(sharing.requests, "post", lambda *a, **kw: _FakeResponse(403))
        result = sharing.share_ioc_to_otx("fake-key", "ip", "1.2.3.4")
        assert result["success"] is False
        assert "error" in result

    def test_connection_error_returns_failure_not_raise(self, monkeypatch):
        import requests

        def boom(*a, **kw):
            raise requests.exceptions.ConnectionError("no network")
        monkeypatch.setattr(sharing.requests, "post", boom)
        result = sharing.share_ioc_to_otx("fake-key", "domain", "evil.example")
        assert result["success"] is False

    def test_unsupported_ioc_type_rejected_before_network_call(self, monkeypatch):
        called = []
        monkeypatch.setattr(sharing.requests, "post", lambda *a, **kw: called.append(1))
        result = sharing.share_ioc_to_otx("fake-key", "email", "x@example.com")
        assert result["success"] is False
        assert called == []  # never even attempted the HTTP call


# ── 5. share_ioc — the opt-in gate + validation + OTX call ────────────────

class TestShareIoc:
    def test_disabled_by_default_never_calls_network(self, monkeypatch):
        called = []
        monkeypatch.setattr(sharing, "share_ioc_to_otx", lambda *a, **kw: called.append(1))
        result = _run(sharing.share_ioc(ioc_type="ip", value="1.2.3.4", enabled=False, api_key="key"))
        assert result["status"] == "disabled"
        assert called == []

    def test_invalid_ioc_rejected_even_when_enabled(self, monkeypatch):
        result = _run(sharing.share_ioc(ioc_type="ip", value="not-an-ip", enabled=True, api_key="key"))
        assert result["status"] == "invalid"

    def test_missing_api_key_fails_gracefully(self):
        result = _run(sharing.share_ioc(ioc_type="ip", value="1.2.3.4", enabled=True, api_key=""))
        assert result["status"] == "failed"

    def test_success_path(self, monkeypatch):
        monkeypatch.setattr(sharing, "share_ioc_to_otx",
                             lambda *a, **kw: {"success": True, "pulse_id": "p1", "pulse_url": "https://x/p1"})
        result = _run(sharing.share_ioc(ioc_type="ip", value="1.2.3.4", enabled=True, api_key="key"))
        assert result["status"] == "success"
        assert result["pulse_id"] == "p1"

    def test_otx_failure_surfaces_as_failed_status(self, monkeypatch):
        monkeypatch.setattr(sharing, "share_ioc_to_otx",
                             lambda *a, **kw: {"success": False, "error": "rate limited"})
        result = _run(sharing.share_ioc(ioc_type="ip", value="1.2.3.4", enabled=True, api_key="key"))
        assert result["status"] == "failed"
        assert "rate limited" in result["message_en"]

    def test_rejects_email_even_with_sharing_enabled(self, monkeypatch):
        called = []
        monkeypatch.setattr(sharing, "share_ioc_to_otx", lambda *a, **kw: called.append(1))
        result = _run(sharing.share_ioc(ioc_type="domain", value="victim@example.com", enabled=True, api_key="key"))
        assert result["status"] == "invalid"
        assert called == []

    def test_arabic_message_present_in_every_status(self, monkeypatch):
        monkeypatch.setattr(sharing, "share_ioc_to_otx", lambda *a, **kw: {"success": True, "pulse_id": "p"})
        for kwargs in [
            dict(ioc_type="ip", value="1.2.3.4", enabled=False, api_key="k"),
            dict(ioc_type="ip", value="bad", enabled=True, api_key="k"),
            dict(ioc_type="ip", value="1.2.3.4", enabled=True, api_key=""),
            dict(ioc_type="ip", value="1.2.3.4", enabled=True, api_key="k"),
        ]:
            result = _run(sharing.share_ioc(**kwargs))
            assert result.get("message_ar")


# ── 6. Router persistence helpers — record_share / already_shared_values ──

class TestRecordShare:
    def test_persists_row_with_result_detail(self, db):
        async def go():
            uid = await _seed_user(db)
            async with db() as db_:
                row = await ts_router.record_share(
                    db_, user_id=uid, ioc_type="ip", value="1.2.3.4",
                    source_module="honeypot", severity="HIGH", tlp="AMBER",
                    result={"status": "success", "pulse_id": "p1"},
                )
                return row.id
        row_id = _run(go())
        assert row_id is not None

        async def fetch():
            async with db() as db_:
                return await db_.get(ThreatShare, row_id)
        row = _run(fetch())
        assert row.status == "success"
        assert row.ioc_value == "1.2.3.4"
        assert row.detail["pulse_id"] == "p1"

    def test_persists_even_when_user_id_none(self, db):
        async def go():
            async with db() as db_:
                row = await ts_router.record_share(
                    db_, user_id=None, ioc_type="cve", value="CVE-2021-44228",
                    source_module="vulnerability_intel", severity="HIGH", tlp="AMBER",
                    result={"status": "disabled"},
                )
                return row.id
        assert _run(go()) is not None


class TestAlreadySharedValues:
    def test_only_counts_successful_shares(self, db):
        async def go():
            uid = await _seed_user(db)
            async with db() as db_:
                await ts_router.record_share(db_, user_id=uid, ioc_type="ip", value="1.1.1.1",
                                              source_module="honeypot", severity="HIGH", tlp="AMBER",
                                              result={"status": "success"})
                await ts_router.record_share(db_, user_id=uid, ioc_type="ip", value="2.2.2.2",
                                              source_module="honeypot", severity="HIGH", tlp="AMBER",
                                              result={"status": "failed"})
            async with db() as db_:
                return await ts_router.already_shared_values(db_)
        values = _run(go())
        assert values == {"1.1.1.1"}


class TestShareToDict:
    def test_serializes_all_fields(self, db):
        async def go():
            uid = await _seed_user(db)
            async with db() as db_:
                return await ts_router.record_share(
                    db_, user_id=uid, ioc_type="domain", value="evil.example",
                    source_module="manual", severity="MEDIUM", tlp="GREEN",
                    result={"status": "success"},
                )
        row = _run(go())
        d = ts_router._share_to_dict(row)
        assert d["ioc_type"] == "domain"
        assert d["ioc_value"] == "evil.example"
        assert d["destination"] == "alienvault_otx"
        assert d["created_at"] is not None


# ── 7. License feature registration ────────────────────────────────────────

class TestLicenseFeatureRegistered:
    def test_threat_sharing_in_pro_and_enterprise_tiers(self):
        from web.license import TIER_FEATURES, FEATURE_LABELS
        assert "threat_sharing" in TIER_FEATURES["pro"]
        assert "threat_sharing" in FEATURE_LABELS
