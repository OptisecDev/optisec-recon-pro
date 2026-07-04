"""Tests for modules.ioc.ioc_engine — IOCEngine (check_ioc/enrich_ioc/
extract_iocs_from_finding) and IOCRepository. Phase 2: IOCRepository is now
backed by a real database (in-memory SQLite via an async engine, same
fixture convention as tests/test_honeypot.py / tests/test_darkweb_scheduler.py
— no mocking of the DB layer itself), while every external threat-intel
source client (VirusTotal/AbuseIPDB/OTX) stays an injected fake callable /
pre-fetched dict — nothing here reaches a real network.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base
from web.models import Ioc  # noqa: F401 — import registers all models on Base.metadata
from modules.ioc.ioc_engine import (
    IOC_TYPES,
    IOCEngine,
    IOCRepository,
    IOCCheckResult,
)


def _run(coro):
    return asyncio.run(coro)


# ── Isolated in-memory DB fixture (same pattern as tests/test_honeypot.py) ──

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


# ---------------------------------------------------------------------------
# IOCRepository (real DB, in-memory SQLite)
# ---------------------------------------------------------------------------

class TestIOCRepository:
    def test_get_by_value_missing_returns_none(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                return await repo.get_by_value("ip", "1.2.3.4")
        assert _run(go()) is None

    def test_create_persists_new_record_with_defaults(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                row = await repo.create("ip", "1.2.3.4", source="manual", confidence_score=42.0)
                await db.commit()
                return row.id
        row_id = _run(go())

        async def fetch():
            async with db_factory() as db:
                repo = IOCRepository(db)
                return await repo.get_by_value("ip", "1.2.3.4")
        record = _run(fetch())

        assert record is not None
        assert record.id == row_id
        assert record.ioc_type == "ip"
        assert record.ioc_value == "1.2.3.4"
        assert record.source == "manual"
        assert record.confidence_score == 42.0
        assert record.is_active is True
        assert record.tags == []
        assert record.related_finding_id is None
        assert record.first_seen == record.last_seen

    def test_upsert_creates_new_when_missing(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                row = await repo.upsert("domain", "evil.com", source="manual", confidence_score=10.0)
                await db.commit()
                return row.confidence_score
        assert _run(go()) == 10.0

    def test_upsert_existing_updates_last_seen_but_keeps_first_seen_and_row_identity(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                first = await repo.upsert("domain", "evil.com", source="manual", confidence_score=10.0)
                await db.commit()
                first_id, first_seen = first.id, first.first_seen

                second = await repo.upsert("domain", "evil.com", confidence_score=90.0)
                await db.commit()
                return first_id, first_seen, second
        first_id, first_seen, second = _run(go())

        assert second.id == first_id  # same row, updated in place — not a duplicate
        assert second.confidence_score == 90.0
        assert second.first_seen == first_seen
        assert second.last_seen >= first_seen

    def test_upsert_does_not_create_duplicate_rows(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.upsert("ip", "1.2.3.4", source="manual")
                await repo.upsert("ip", "1.2.3.4", confidence_score=55.0)
                await db.commit()
                return await repo.list_active(ioc_type="ip")
        rows = _run(go())
        assert len(rows) == 1
        assert rows[0].confidence_score == 55.0

    def test_list_active_filters_inactive_and_by_type(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "1.1.1.1", source="manual")
                await repo.create("domain", "evil.com", source="manual")
                await repo.create("ip", "2.2.2.2", source="manual", is_active=False)
                await db.commit()

                all_active = await repo.list_active()
                ip_only = await repo.list_active(ioc_type="ip")
                return all_active, ip_only
        all_active, ip_only = _run(go())

        assert {r.ioc_value for r in all_active} == {"1.1.1.1", "evil.com"}
        assert {r.ioc_value for r in ip_only} == {"1.1.1.1"}

    def test_list_active_is_active_none_returns_all_regardless_of_status(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "1.1.1.1", source="manual", is_active=True)
                await repo.create("ip", "2.2.2.2", source="manual", is_active=False)
                await db.commit()
                return await repo.list_active(is_active=None)
        rows = _run(go())
        assert {r.ioc_value for r in rows} == {"1.1.1.1", "2.2.2.2"}

    def test_list_active_respects_limit_and_offset(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                for i in range(5):
                    await repo.create("ip", f"1.1.1.{i}", source="manual")
                await db.commit()
                return await repo.list_active(limit=2, offset=1)
        rows = _run(go())
        assert len(rows) == 2

    def test_create_persists_related_finding_id_and_tags(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                row = await repo.create(
                    "domain", "evil-phish.com", source="scan_finding",
                    related_finding_id=42, tags=["vuln_type:Open Redirect"],
                )
                await db.commit()
                return row
        row = _run(go())
        assert row.related_finding_id == 42
        assert row.tags == ["vuln_type:Open Redirect"]


# ---------------------------------------------------------------------------
# IOCEngine.check_ioc — pure, no DB, unchanged from Phase 1
# ---------------------------------------------------------------------------

class TestCheckIoc:
    def _engine(self, **clients):
        return IOCEngine(source_clients=clients)

    def test_rejects_unsupported_type(self):
        engine = self._engine()
        with pytest.raises(ValueError):
            engine.check_ioc("1.2.3.4", "cidr")

    def test_rejects_empty_value(self):
        engine = self._engine()
        with pytest.raises(ValueError):
            engine.check_ioc("   ", "ip")

    def test_ip_uses_abuseipdb_client(self):
        calls = []

        def fake_abuseipdb(ip):
            calls.append(ip)
            return {"verdict": "MALICIOUS", "score": 80}

        engine = self._engine(abuseipdb_ip=fake_abuseipdb)
        result = engine.check_ioc("203.0.113.5", "ip")

        assert calls == ["203.0.113.5"]
        assert isinstance(result, IOCCheckResult)
        assert result.source == "abuseipdb"
        assert result.verdict == "MALICIOUS"
        assert result.score == 80.0

    def test_domain_uses_virustotal_client(self):
        def fake_vt_domain(domain):
            assert domain == "evil.com"
            return {"verdict": "CRITICAL", "score": 95}

        engine = self._engine(virustotal_domain=fake_vt_domain)
        result = engine.check_ioc("evil.com", "domain")

        assert result.source == "virustotal"
        assert result.verdict == "CRITICAL"
        assert result.score == 95.0

    @pytest.mark.parametrize("ioc_type,value", [
        ("hash_md5", "d41d8cd98f00b204e9800998ecf8427e"),
        ("hash_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"),
    ])
    def test_hash_uses_virustotal_hash_client(self, ioc_type, value):
        def fake_vt_hash(h):
            assert h == value
            return {"verdict": "MALICIOUS", "score": 70}

        engine = self._engine(virustotal_hash=fake_vt_hash)
        result = engine.check_ioc(value, ioc_type)

        assert result.source == "virustotal"
        assert result.verdict == "MALICIOUS"
        assert result.score == 70.0

    def test_url_extracts_domain_before_calling_virustotal(self):
        def fake_vt_domain(domain):
            assert domain == "evil.com"
            return {"verdict": "MALICIOUS", "score": 60}

        engine = self._engine(virustotal_domain=fake_vt_domain)
        result = engine.check_ioc("https://evil.com:8443/phish?x=1", "url")

        assert result.source == "virustotal"
        assert result.score == 60.0

    def test_email_never_calls_any_client_and_is_unknown(self):
        called = {"flag": False}

        def poison(*_a, **_k):
            called["flag"] = True
            raise AssertionError("should never be called for email")

        engine = self._engine(virustotal_domain=poison, abuseipdb_ip=poison, virustotal_hash=poison)
        result = engine.check_ioc("victim@example.com", "email")

        assert called["flag"] is False
        assert result.source == "manual"
        assert result.verdict == "UNKNOWN"
        assert result.score == 0.0

    def test_client_exception_is_swallowed_and_returns_unknown(self):
        def boom(_value):
            raise RuntimeError("network exploded")

        engine = self._engine(abuseipdb_ip=boom)
        result = engine.check_ioc("1.2.3.4", "ip")

        assert result.verdict == "UNKNOWN"
        assert result.score == 0.0
        assert result.raw == {}

    def test_missing_client_returns_unknown_without_raising(self):
        engine = IOCEngine(source_clients={"abuseipdb_ip": None})
        result = engine.check_ioc("1.2.3.4", "ip")
        assert result.verdict == "UNKNOWN"


# ---------------------------------------------------------------------------
# IOCEngine.enrich_ioc — now async (persists via a real DB-backed repository)
# ---------------------------------------------------------------------------

class TestEnrichIoc:
    def test_single_source_confidence_equals_that_source_score_without_repository(self):
        # No repository injected -> enrich_ioc must still work (no DB touch),
        # it just skips persistence.
        engine = IOCEngine(source_clients={
            "abuseipdb_ip": lambda ip: {"verdict": "MALICIOUS", "score": 80},
        })
        record = _run(engine.enrich_ioc("1.2.3.4", "ip"))

        assert record["ioc_value"] == "1.2.3.4"
        assert record["source"] == "abuseipdb"
        assert record["confidence_score"] == 80.0
        assert record["sources_consulted"] == ["abuseipdb"]

    def test_blends_additional_sources_by_weight(self):
        engine = IOCEngine(source_clients={
            "virustotal_domain": lambda d: {"verdict": "MALICIOUS", "score": 100},
        })
        # virustotal weight 1.0, otx weight 0.85 -> weighted avg, not plain mean
        record = _run(engine.enrich_ioc(
            "evil.com", "domain",
            additional_sources={"otx": {"score": 50, "malware": "Emotet", "adversary": "APT28"}},
        ))

        expected = round((100 * 1.0 + 50 * 0.85) / (1.0 + 0.85), 2)
        assert record["confidence_score"] == expected
        assert "otx" in record["sources_consulted"]
        assert "malware_family:Emotet" in record["tags"]
        assert "campaign:APT28" in record["tags"]

    def test_ignores_falsy_additional_source_entries(self):
        engine = IOCEngine(source_clients={
            "abuseipdb_ip": lambda ip: {"verdict": "CLEAN", "score": 5},
        })
        record = _run(engine.enrich_ioc(
            "1.2.3.4", "ip", additional_sources={"otx": {}, "leakcheck": None},
        ))
        assert record["sources_consulted"] == ["abuseipdb"]

    def test_persists_merged_record_into_real_repository(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine(
                    repository=repo,
                    source_clients={"abuseipdb_ip": lambda ip: {"verdict": "MALICIOUS", "score": 90}},
                )
                await engine.enrich_ioc("1.2.3.4", "ip")
                await db.commit()
                return await repo.get_by_value("ip", "1.2.3.4")
        stored = _run(go())

        assert stored is not None
        assert stored.confidence_score == 90.0
        assert stored.is_active is True

    def test_enrich_twice_updates_existing_repository_row_not_duplicate(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine(repository=repo, source_clients={
                    "abuseipdb_ip": lambda ip: {"verdict": "SUSPICIOUS", "score": 30},
                })
                await engine.enrich_ioc("1.2.3.4", "ip")
                await engine.enrich_ioc("1.2.3.4", "ip")
                await db.commit()
                return await repo.list_active(ioc_type="ip")
        rows = _run(go())
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# IOCEngine.extract_iocs_from_finding — pure, no DB, unchanged from Phase 1
# ---------------------------------------------------------------------------

class TestExtractIocsFromFinding:
    def _engine(self):
        return IOCEngine()

    def test_extracts_external_redirect_url_domain_and_url(self):
        finding = {
            "id": 42,
            "vuln_type": "Open Redirect",
            "url": "https://myapp.example/login?next=x",
            "evidence": "Redirect to: https://evil-phish.com/steal (status 302)",
        }
        candidates = self._engine().extract_iocs_from_finding(finding)
        by_type = {(c["ioc_type"], c["ioc_value"]) for c in candidates}

        assert ("domain", "evil-phish.com") in by_type
        assert ("url", "https://evil-phish.com/steal") in by_type
        for c in candidates:
            assert c["source"] == "scan_finding"
            assert c["related_finding_id"] == 42
            assert c["tags"] == ["vuln_type:Open Redirect"]

    def test_ignores_own_target_host(self):
        finding = {
            "id": 1,
            "url": "https://myapp.example/login?next=x",
            "evidence": "Redirect to: https://myapp.example/dashboard (status 302)",
        }
        candidates = self._engine().extract_iocs_from_finding(finding)
        assert candidates == []

    def test_ignores_private_and_loopback_ips(self):
        finding = {
            "id": 2,
            "url": "https://myapp.example/fetch?url=x",
            "evidence": "SSRF probe reached internal host 127.0.0.1 and 10.0.0.5 and 169.254.169.254",
        }
        candidates = self._engine().extract_iocs_from_finding(finding)
        assert candidates == []

    def test_extracts_external_ip_from_evidence(self):
        finding = {
            "id": 3,
            "vuln_type": "SSRF",
            "url": "https://myapp.example/fetch?url=x",
            "evidence": "Outbound connection observed to 8.8.8.8 before timeout",
        }
        candidates = self._engine().extract_iocs_from_finding(finding)
        values = {(c["ioc_type"], c["ioc_value"]) for c in candidates}
        assert ("ip", "8.8.8.8") in values

    def test_does_not_mine_payload_field(self):
        finding = {
            "id": 4,
            "vuln_type": "SSRF",
            "url": "https://myapp.example/fetch?url=x",
            "payload": "http://169.254.169.254/latest/meta-data/",
            "evidence": "root:x:",
        }
        candidates = self._engine().extract_iocs_from_finding(finding)
        assert candidates == []

    def test_empty_evidence_returns_empty_list(self):
        finding = {"id": 5, "url": "https://myapp.example/", "evidence": ""}
        assert self._engine().extract_iocs_from_finding(finding) == []

    def test_deduplicates_repeated_indicator_in_evidence(self):
        finding = {
            "id": 6,
            "url": "https://myapp.example/",
            "evidence": "Seen evil.io twice: https://evil.io/a and https://evil.io/a",
        }
        candidates = self._engine().extract_iocs_from_finding(finding)
        urls = [c for c in candidates if c["ioc_type"] == "url"]
        assert len(urls) == 1


# ---------------------------------------------------------------------------
# End-to-end: extract_iocs_from_finding() candidates persisted via a real repo
# ---------------------------------------------------------------------------

class TestExtractThenPersistIntegration:
    def test_candidates_from_finding_persist_with_related_finding_id(self, db_factory):
        finding = {
            "id": 99,
            "vuln_type": "SSRF",
            "url": "https://myapp.example/fetch?url=x",
            "evidence": "Outbound connection observed to 8.8.8.8 before timeout",
        }

        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine()
                for candidate in engine.extract_iocs_from_finding(finding):
                    await repo.upsert(
                        candidate["ioc_type"], candidate["ioc_value"],
                        source=candidate["source"],
                        related_finding_id=candidate["related_finding_id"],
                        tags=candidate["tags"],
                    )
                await db.commit()
                return await repo.get_by_value("ip", "8.8.8.8")
        stored = _run(go())

        assert stored is not None
        assert stored.source == "scan_finding"
        assert stored.related_finding_id == 99
        assert stored.tags == ["vuln_type:SSRF"]


def test_ioc_types_are_the_six_documented_types():
    assert IOC_TYPES == {"hash_md5", "hash_sha256", "ip", "domain", "url", "email"}
