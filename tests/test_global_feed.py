"""Tests for modules/threat_intel/global_feed.py's real-URLhaus integration
(Phase 3 follow-up): _SAMPLE_IOCS no longer hardcodes fake URLHAUS rows,
fetch_real_urlhaus_iocs() reads them from the local Ioc table instead, and
get_live_ioc_feed() merges the two without disturbing the still-fabricated
ABUSE-CH/CISA-KEV/etc. sample rows.

Mirrors tests/test_ioc_engine.py's DB fixture convention: real in-memory
SQLite via IOCRepository, no mocking of the DB layer itself.
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
from modules.threat_intel import global_feed


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


def _fake_user() -> User:
    return User(id=1, username="analyst", email="a@example.com", password_hash="x", role="analyst")


# ---------------------------------------------------------------------------
# _SAMPLE_IOCS / FEED_SOURCES — fake URLHAUS rows gone, everything else stays
# ---------------------------------------------------------------------------

class TestSampleDataNoLongerFakesUrlhaus:
    def test_no_sample_ioc_claims_to_be_from_urlhaus(self):
        assert all(ioc.get("source") != "URLHAUS" for ioc in global_feed._SAMPLE_IOCS)

    def test_abuse_ch_and_cisa_kev_sample_rows_are_untouched(self):
        sources = {ioc["source"] for ioc in global_feed._SAMPLE_IOCS}
        assert "ABUSE-CH" in sources
        assert "CISA-KEV" in sources

    def test_urlhaus_still_listed_as_a_feed_source(self):
        """FEED_SOURCES is descriptive metadata (id/name/reliability), not a
        fabricated indicator — it must stay so real URLhaus rows can still
        be scored via _aggregate_threat_score()'s reliability lookup."""
        ids = {s["id"] for s in global_feed.FEED_SOURCES}
        assert "URLHAUS" in ids


# ---------------------------------------------------------------------------
# _malware_from_tags
# ---------------------------------------------------------------------------

class TestMalwareFromTags:
    def test_extracts_malware_family_tag(self):
        assert global_feed._malware_from_tags(["malware_family:Mirai", "elf"]) == "Mirai"

    def test_no_matching_tag_returns_unknown(self):
        assert global_feed._malware_from_tags(["elf", "botnet"]) == "Unknown"

    def test_none_returns_unknown(self):
        assert global_feed._malware_from_tags(None) == "Unknown"

    def test_empty_list_returns_unknown(self):
        assert global_feed._malware_from_tags([]) == "Unknown"


# ---------------------------------------------------------------------------
# fetch_real_urlhaus_iocs — real DB read via IOCRepository
# ---------------------------------------------------------------------------

class TestFetchRealUrlhausIocs:
    def test_empty_when_nothing_synced(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await global_feed.fetch_real_urlhaus_iocs(db)
        assert _run(go()) == []

    def test_returns_urlhaus_rows_in_sample_ioc_shape(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create(
                    "url", "http://evil.com/payload.exe", source="urlhaus",
                    confidence_score=91.0, tags=["malware_family:Mirai"],
                )
                await db.commit()
                return await global_feed.fetch_real_urlhaus_iocs(db)
        rows = _run(go())
        assert rows == [{
            "type": "url",
            "value": "http://evil.com/payload.exe",
            "malware": "Mirai",
            "confidence": 91,
            "source": "URLHAUS",
        }]

    def test_ignores_non_urlhaus_url_rows(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("url", "http://safe.example/manual", source="manual")
                await repo.create("url", "http://evil.com/x", source="urlhaus", confidence_score=80.0)
                await db.commit()
                return await global_feed.fetch_real_urlhaus_iocs(db)
        rows = _run(go())
        assert len(rows) == 1
        assert rows[0]["value"] == "http://evil.com/x"

    def test_ignores_inactive_rows(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("url", "http://evil.com/x", source="urlhaus", is_active=False)
                await db.commit()
                return await global_feed.fetch_real_urlhaus_iocs(db)
        assert _run(go()) == []

    def test_respects_limit(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                for i in range(5):
                    await repo.create("url", f"http://evil.com/{i}", source="urlhaus")
                await db.commit()
                return await global_feed.fetch_real_urlhaus_iocs(db, limit=2)
        rows = _run(go())
        assert len(rows) == 2

    def test_missing_malware_family_tag_falls_back_to_unknown(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("url", "http://evil.com/x", source="urlhaus", tags=["elf"])
                await db.commit()
                return await global_feed.fetch_real_urlhaus_iocs(db)
        rows = _run(go())
        assert rows[0]["malware"] == "Unknown"


# ---------------------------------------------------------------------------
# get_live_ioc_feed — merges real urlhaus_iocs alongside _SAMPLE_IOCS
# ---------------------------------------------------------------------------

class TestGetLiveIocFeed:
    def test_default_call_has_no_urlhaus_rows(self):
        feed = global_feed.get_live_ioc_feed(limit=100)
        assert all(ioc["source"] != "URLHAUS" for ioc in feed["iocs"])

    def test_default_call_still_has_fake_abuse_ch_and_cisa_kev_rows(self):
        feed = global_feed.get_live_ioc_feed(limit=100)
        sources = {ioc["source"] for ioc in feed["iocs"]}
        assert "ABUSE-CH" in sources
        assert "CISA-KEV" in sources

    def test_urlhaus_iocs_are_merged_into_the_feed(self):
        real_row = {"type": "url", "value": "http://evil.com/x", "malware": "Mirai",
                    "confidence": 91, "source": "URLHAUS"}
        feed = global_feed.get_live_ioc_feed(limit=100, urlhaus_iocs=[real_row])

        urlhaus_entries = [ioc for ioc in feed["iocs"] if ioc["source"] == "URLHAUS"]
        assert len(urlhaus_entries) == 1
        assert urlhaus_entries[0]["value"] == "http://evil.com/x"
        # still fully scored/tagged like every other entry, same enrichment path
        assert "threat_score" in urlhaus_entries[0]
        assert "tags" in urlhaus_entries[0]

    def test_urlhaus_iocs_counted_in_by_source_stats(self):
        real_row = {"type": "url", "value": "http://evil.com/x", "malware": "Mirai",
                    "confidence": 91, "source": "URLHAUS"}
        feed = global_feed.get_live_ioc_feed(limit=100, urlhaus_iocs=[real_row])
        assert feed["stats"]["by_source"].get("URLHAUS") == 1

    def test_none_urlhaus_iocs_behaves_like_omitted(self):
        with_none = global_feed.get_live_ioc_feed(limit=100, urlhaus_iocs=None)
        omitted = global_feed.get_live_ioc_feed(limit=100)
        assert len(with_none["iocs"]) == len(omitted["iocs"])


# ---------------------------------------------------------------------------
# Router integration — live_feed / get_threat_feed now read real URLhaus IOCs
# ---------------------------------------------------------------------------

class TestRouterMergesRealUrlhausData:
    def test_live_feed_includes_real_urlhaus_row(self, db_factory, monkeypatch):
        import config
        import web.routers.threat_feed as threat_feed_router
        monkeypatch.setattr(threat_feed_router, "OTX_API_KEY", "")  # keep OTX out of the way

        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("url", "http://evil.com/x", source="urlhaus", confidence_score=90.0)
                await db.commit()
                return await threat_feed_router.live_feed(limit=50, user=_fake_user(), db=db)
        feed = _run(go())
        urlhaus_entries = [ioc for ioc in feed["iocs"] if ioc.get("source") == "URLHAUS"]
        assert len(urlhaus_entries) == 1
        assert urlhaus_entries[0]["value"] == "http://evil.com/x"

    def test_threat_sharing_get_threat_feed_includes_real_urlhaus_row(self, db_factory, monkeypatch):
        import web.routers.threat_sharing as ts_router
        monkeypatch.setattr(ts_router, "OTX_API_KEY", "")  # keep OTX out of the way

        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("url", "http://evil.com/y", source="urlhaus", confidence_score=85.0)
                await db.commit()
                resp = await ts_router.get_threat_feed(limit=50, user=_fake_user(), db=db)
                import json
                return json.loads(resp.body)
        feed = _run(go())
        urlhaus_entries = [ioc for ioc in feed["iocs"] if ioc.get("source") == "URLHAUS"]
        assert len(urlhaus_entries) == 1
        assert urlhaus_entries[0]["value"] == "http://evil.com/y"

    def test_live_feed_has_no_urlhaus_rows_when_none_synced(self, db_factory, monkeypatch):
        import web.routers.threat_feed as threat_feed_router
        monkeypatch.setattr(threat_feed_router, "OTX_API_KEY", "")

        async def go():
            async with db_factory() as db:
                return await threat_feed_router.live_feed(limit=50, user=_fake_user(), db=db)
        feed = _run(go())
        assert all(ioc.get("source") != "URLHAUS" for ioc in feed["iocs"])
