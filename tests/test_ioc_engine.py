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

    def test_list_active_filters_by_source(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("url", "http://evil.com/a", source="urlhaus")
                await repo.create("url", "http://evil.com/b", source="manual")
                await db.commit()
                return await repo.list_active(source="urlhaus")
        rows = _run(go())
        assert {r.ioc_value for r in rows} == {"http://evil.com/a"}

    def test_list_active_combines_source_with_ioc_type(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("url", "http://evil.com/a", source="urlhaus")
                await repo.create("ip", "8.8.8.8", source="urlhaus")
                await db.commit()
                return await repo.list_active(ioc_type="url", source="urlhaus")
        rows = _run(go())
        assert {r.ioc_value for r in rows} == {"http://evil.com/a"}

    def test_list_active_source_none_does_not_filter(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("url", "http://evil.com/a", source="urlhaus")
                await repo.create("url", "http://evil.com/b", source="manual")
                await db.commit()
                return await repo.list_active()
        rows = _run(go())
        assert {r.ioc_value for r in rows} == {"http://evil.com/a", "http://evil.com/b"}

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

    def test_search_matches_substring_case_insensitive(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("domain", "evil-phish.com", source="manual")
                await repo.create("domain", "safe.com", source="manual")
                await db.commit()
                return await repo.search("EVIL-PHISH")
        rows = _run(go())
        assert {r.ioc_value for r in rows} == {"evil-phish.com"}

    def test_search_filters_by_ioc_type(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("domain", "evil.com", source="manual")
                await repo.create("url", "http://evil.com/x", source="manual")
                await db.commit()
                return await repo.search("evil", ioc_type="domain")
        rows = _run(go())
        assert len(rows) == 1
        assert rows[0].ioc_type == "domain"

    def test_search_excludes_inactive_by_default(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "1.2.3.4", source="manual", is_active=False)
                await db.commit()
                return await repo.search("1.2.3.4")
        assert _run(go()) == []

    def test_search_no_match_returns_empty_list(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "1.2.3.4", source="manual")
                await db.commit()
                return await repo.search("nope")
        assert _run(go()) == []

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
# IOCEngine.sync_from_otx — fetch is injected, upsert via a real repository
# ---------------------------------------------------------------------------

class TestSyncFromOtx:
    def _pulse(self, ioc_type="domain", value="evil.com", **extra):
        item = {"type": ioc_type, "value": value, "threat_score": 80}
        item.update(extra)
        return item

    def test_no_client_configured_returns_zeroed_summary_with_error(self):
        engine = IOCEngine(source_clients={"otx_pulses": None})
        summary = _run(engine.sync_from_otx())
        assert summary == {"fetched": 0, "stored": 0, "skipped": 0, "error": "otx_pulses client not configured"}

    def test_fetch_failure_is_swallowed_and_reported(self):
        def boom(limit):
            raise RuntimeError("OTX API unreachable")

        engine = IOCEngine(source_clients={"otx_pulses": boom})
        summary = _run(engine.sync_from_otx())
        assert summary == {"fetched": 0, "stored": 0, "skipped": 0, "error": "fetch_failed"}

    def test_unsupported_indicator_types_are_skipped_not_stored(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine(repository=repo, source_clients={
                    "otx_pulses": lambda limit: [
                        self._pulse(ioc_type="cve", value="CVE-2024-1234"),
                        self._pulse(ioc_type="domain", value="evil.com"),
                    ],
                })
                summary = await engine.sync_from_otx()
                await db.commit()
                return summary, await repo.list_active(ioc_type="domain")
        summary, rows = _run(go())
        assert summary == {"fetched": 2, "stored": 1, "skipped": 1}
        assert {r.ioc_value for r in rows} == {"evil.com"}

    def test_unsupported_indicator_types_never_reach_the_iocs_table_at_all(self, db_factory):
        """Stronger than test_unsupported_indicator_types_are_skipped_not_stored:
        that test only checked the ioc_type="domain" filter's result, which
        can't catch a bug that persisted a CVE/CIDR/Mutex row under its own
        (unsupported) ioc_type — web.models.Ioc.ioc_type has no DB-level
        enum constraint, so nothing but this engine's own IOC_TYPES check
        stops that. Query across every type/active-state and assert the
        unsupported OTX indicators are absent outright, not merely
        unreachable through one filter."""
        unsupported = [
            self._pulse(ioc_type="cve", value="CVE-2024-1234"),
            self._pulse(ioc_type="cidr", value="10.0.0.0/8"),
            self._pulse(ioc_type="mutex", value="Global\\SomeMutex"),
            self._pulse(ioc_type="filepath", value="/tmp/evil.bin"),
            self._pulse(ioc_type="yara", value="rule_evil_1"),
        ]
        supported = [self._pulse(ioc_type="domain", value="evil.com")]

        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine(repository=repo, source_clients={
                    "otx_pulses": lambda limit: unsupported + supported,
                })
                summary = await engine.sync_from_otx()
                await db.commit()
                return summary, await repo.list_active(ioc_type=None, is_active=None)
        summary, all_rows = _run(go())

        assert summary == {"fetched": 6, "stored": 1, "skipped": 5}
        assert len(all_rows) == 1
        assert all_rows[0].ioc_value == "evil.com"
        assert all_rows[0].ioc_type == "domain"

        stored_values = {r.ioc_value for r in all_rows}
        stored_types = {r.ioc_type for r in all_rows}
        for item in unsupported:
            assert item["value"] not in stored_values
            assert item["type"] not in stored_types

    def test_stores_indicators_with_otx_source_and_tags(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine(repository=repo, source_clients={
                    "otx_pulses": lambda limit: [
                        self._pulse(pulse_name="Emotet Campaign", adversary="APT28"),
                    ],
                })
                await engine.sync_from_otx()
                await db.commit()
                return await repo.get_by_value("domain", "evil.com")
        row = _run(go())
        assert row.source == "otx"
        assert row.confidence_score == 80.0
        assert "pulse:Emotet Campaign" in row.tags
        assert "campaign:APT28" in row.tags

    def test_passes_limit_through_to_the_client(self):
        calls = []

        def fake_client(limit):
            calls.append(limit)
            return []

        engine = IOCEngine(source_clients={"otx_pulses": fake_client})
        _run(engine.sync_from_otx(limit=25))
        assert calls == [25]

    def test_missing_value_is_skipped(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine(repository=repo, source_clients={
                    "otx_pulses": lambda limit: [self._pulse(value="")],
                })
                return await engine.sync_from_otx()
        summary = _run(go())
        assert summary == {"fetched": 1, "stored": 0, "skipped": 1}

    def test_no_repository_counts_fetched_but_stores_nothing(self):
        engine = IOCEngine(source_clients={
            "otx_pulses": lambda limit: [self._pulse()],
        })
        summary = _run(engine.sync_from_otx())
        assert summary == {"fetched": 1, "stored": 0, "skipped": 0}


# ---------------------------------------------------------------------------
# IOCEngine.sync_from_urlhaus — fetch is injected, upsert via a real repository
# ---------------------------------------------------------------------------

class TestSyncFromUrlhaus:
    def _entry(self, ioc_type="url", value="http://evil.com/x", **extra):
        item = {"type": ioc_type, "value": value, "threat_score": 90}
        item.update(extra)
        return item

    def test_no_client_configured_returns_zeroed_summary_with_error(self):
        engine = IOCEngine(source_clients={"urlhaus_recent": None})
        summary = _run(engine.sync_from_urlhaus())
        assert summary == {"fetched": 0, "stored": 0, "skipped": 0, "error": "urlhaus_recent client not configured"}

    def test_fetch_failure_is_swallowed_and_reported(self):
        def boom(limit):
            raise RuntimeError("URLhaus API unreachable")

        engine = IOCEngine(source_clients={"urlhaus_recent": boom})
        summary = _run(engine.sync_from_urlhaus())
        assert summary == {"fetched": 0, "stored": 0, "skipped": 0, "error": "fetch_failed"}

    def test_unsupported_entry_types_are_skipped_not_stored(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine(repository=repo, source_clients={
                    "urlhaus_recent": lambda limit: [
                        self._entry(ioc_type="cidr", value="10.0.0.0/8"),
                        self._entry(ioc_type="url", value="http://evil.com/x"),
                    ],
                })
                summary = await engine.sync_from_urlhaus()
                await db.commit()
                return summary, await repo.list_active(ioc_type="url")
        summary, rows = _run(go())
        assert summary == {"fetched": 2, "stored": 1, "skipped": 1}
        assert {r.ioc_value for r in rows} == {"http://evil.com/x"}

    def test_stores_indicators_with_urlhaus_source_and_tags(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine(repository=repo, source_clients={
                    "urlhaus_recent": lambda limit: [self._entry(tags=["elf", "mirai"])],
                })
                await engine.sync_from_urlhaus()
                await db.commit()
                return await repo.get_by_value("url", "http://evil.com/x")
        row = _run(go())
        assert row.source == "urlhaus"
        assert row.confidence_score == 90.0
        assert "malware_family:elf" in row.tags
        assert "malware_family:mirai" in row.tags

    def test_passes_limit_through_to_the_client(self):
        calls = []

        def fake_client(limit):
            calls.append(limit)
            return []

        engine = IOCEngine(source_clients={"urlhaus_recent": fake_client})
        _run(engine.sync_from_urlhaus(limit=25))
        assert calls == [25]

    def test_missing_value_is_skipped(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine(repository=repo, source_clients={
                    "urlhaus_recent": lambda limit: [self._entry(value="")],
                })
                return await engine.sync_from_urlhaus()
        summary = _run(go())
        assert summary == {"fetched": 1, "stored": 0, "skipped": 1}

    def test_no_repository_counts_fetched_but_stores_nothing(self):
        engine = IOCEngine(source_clients={
            "urlhaus_recent": lambda limit: [self._entry()],
        })
        summary = _run(engine.sync_from_urlhaus())
        assert summary == {"fetched": 1, "stored": 0, "skipped": 0}


# ---------------------------------------------------------------------------
# IOCEngine.match_scan_results — correlate findings against the local store
# ---------------------------------------------------------------------------

class TestMatchScanResults:
    def test_no_repository_returns_empty_list(self):
        engine = IOCEngine()
        findings = [{"id": 1, "url": "https://myapp.example/", "evidence": "8.8.8.8"}]
        assert _run(engine.match_scan_results(findings)) == []

    def test_matches_known_ioc_from_finding_evidence(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "8.8.8.8", source="otx", confidence_score=90.0, tags=["campaign:APT28"])
                await db.commit()

                engine = IOCEngine(repository=repo)
                findings = [{
                    "id": 5, "vuln_type": "SSRF",
                    "url": "https://myapp.example/fetch?url=x",
                    "evidence": "Outbound connection observed to 8.8.8.8 before timeout",
                }]
                return await engine.match_scan_results(findings)
        matches = _run(go())
        assert len(matches) == 1
        assert matches[0]["finding_id"] == 5
        assert matches[0]["vuln_type"] == "SSRF"
        assert matches[0]["ioc_value"] == "8.8.8.8"
        assert matches[0]["ioc_source"] == "otx"
        assert matches[0]["confidence_score"] == 90.0
        assert matches[0]["tags"] == ["campaign:APT28"]

    def test_unknown_infrastructure_produces_no_matches(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                engine = IOCEngine(repository=repo)
                findings = [{
                    "id": 1, "url": "https://myapp.example/fetch?url=x",
                    "evidence": "Outbound connection observed to 8.8.8.8 before timeout",
                }]
                return await engine.match_scan_results(findings)
        assert _run(go()) == []

    def test_inactive_ioc_is_not_matched(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "8.8.8.8", source="otx", is_active=False)
                await db.commit()

                engine = IOCEngine(repository=repo)
                findings = [{
                    "id": 1, "url": "https://myapp.example/fetch?url=x",
                    "evidence": "Outbound connection observed to 8.8.8.8 before timeout",
                }]
                return await engine.match_scan_results(findings)
        assert _run(go()) == []

    def test_multiple_findings_each_matched_independently(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "8.8.8.8", source="otx")
                await repo.create("domain", "evil-phish.com", source="otx")
                await db.commit()

                engine = IOCEngine(repository=repo)
                findings = [
                    {"id": 1, "vuln_type": "SSRF", "url": "https://myapp.example/a",
                     "evidence": "hit 8.8.8.8"},
                    {"id": 2, "vuln_type": "Open Redirect", "url": "https://myapp.example/b",
                     "evidence": "Redirect to: https://evil-phish.com/x"},
                ]
                return await engine.match_scan_results(findings)
        matches = _run(go())
        assert {m["finding_id"] for m in matches} == {1, 2}


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
