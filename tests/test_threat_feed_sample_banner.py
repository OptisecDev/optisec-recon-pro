"""
PRIORITY 1 item 4 of the live-walkthrough audit (BATCH 2):

web/templates/threat_feed.html's header used to present "GLOBAL THREAT
LEVEL: CRITICAL", an "active IOCs tracked across N intelligence sources"
line, an "Attacks/Hour" stat, and a "Live IOC Stream" heading unconditionally
-- all computed over data that, in the live walkthrough, was 100% fabricated
sample/demo content (neither AlienVault OTX nor abuse.ch URLhaus was
returning live rows). Nothing on the page disclosed that.

This file covers:
1. web/routers/threat_feed.py's _build_feed() now computes an `is_live` flag
   that is False when every IOC shown is sample/demo data, and True as soon
   as at least one real (OTX or synced-URLhaus) indicator is present.
2. web/templates/threat_feed.html renders a bilingual sample-data banner and
   qualifies the headline numbers when `is_live` is False (static-source
   check, same pattern as tests/test_redteam_simulated_labeling.py -- no JS
   test runner in this repo for the parts that are pure Jinja).
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
import web.routers.threat_feed as threat_feed_router


@pytest.fixture(autouse=True)
def _isolate_global_feed_data_file(tmp_path, monkeypatch):
    """global_feed.DATA_FILE is a real on-disk file shared across the whole
    app (data/global_threat_feed.json) — isolate it so leftover shared_iocs
    from other tests/runs can't make the feed look "live" here. Same
    convention as tests/test_global_feed_sample_tagging.py."""
    monkeypatch.setattr(global_feed, "DATA_FILE", tmp_path / "global_threat_feed.json")


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
    return User(id=1, username="analyst", email="a@example.com", password_hash="x",
                role="analyst", subscription_tier="enterprise")


TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web", "templates", "threat_feed.html",
)


def _read_template() -> str:
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        return f.read()


class TestBuildFeedIsLiveFlag:
    def test_is_live_false_when_everything_is_sample(self, db_factory, monkeypatch):
        monkeypatch.setattr(threat_feed_router, "OTX_API_KEY", "")
        async def go():
            async with db_factory() as db:
                return await threat_feed_router.live_feed(limit=50, user=_fake_user(), db=db)
        feed = _run(go())
        assert feed["iocs"], "expected the fabricated sample pool to fill the feed"
        assert all(ioc.get("is_sample") for ioc in feed["iocs"])
        assert feed["is_live"] is False

    def test_is_live_true_when_a_real_urlhaus_row_is_synced(self, db_factory, monkeypatch):
        monkeypatch.setattr(threat_feed_router, "OTX_API_KEY", "")
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("url", "http://real-malware.example/x", source="urlhaus", confidence_score=90.0)
                await db.commit()
                return await threat_feed_router.live_feed(limit=50, user=_fake_user(), db=db)
        feed = _run(go())
        assert any(ioc.get("source") == "URLHAUS" for ioc in feed["iocs"])
        assert feed["is_live"] is True

    def test_is_live_true_when_otx_returns_real_pulses(self, db_factory, monkeypatch):
        monkeypatch.setattr(threat_feed_router, "OTX_API_KEY", "fake-key")

        # fetch_otx_pulses is called via asyncio.to_thread(), so it must stay
        # a plain sync callable (not a coroutine function).
        def _sync_fetch_pulses(api_key, limit):
            return [{"type": "domain", "value": "real-otx-pulse.example", "malware": "X",
                      "confidence": 80, "source": "ALIENVAULT-OTX", "threat_score": 75}]
        monkeypatch.setattr("modules.threat_intel.otx_feed.fetch_otx_pulses", _sync_fetch_pulses)

        async def go():
            async with db_factory() as db:
                return await threat_feed_router.live_feed(limit=50, user=_fake_user(), db=db)
        feed = _run(go())
        assert feed["is_live"] is True
        assert any(ioc.get("value") == "real-otx-pulse.example" for ioc in feed["iocs"])


class TestSampleDataBannerInTemplate:
    def test_top_of_page_banner_is_conditional_on_is_live(self):
        src = _read_template()
        assert "feed.is_live" in src
        assert "Sample / Demo Data" in src
        assert any("؀" <= ch <= "ۿ" for ch in src)

    def test_global_threat_level_gets_sample_qualifier_when_not_live(self):
        src = _read_template()
        assert "SAMPLE DATA" in src

    def test_attacks_per_hour_always_carries_a_sample_disclaimer(self):
        # Unlike the IOC feed (which can be live via OTX/URLhaus), the threat
        # map's attacks_per_hour is ALWAYS jittered demo data (see
        # modules/threat_intel/global_feed.py's get_threat_map() /
        # MAP_JITTER_NOTE_EN) — so this disclaimer must be unconditional,
        # not gated behind feed.is_live.
        src = _read_template()
        assert "Attacks/Hour (sample)" in src
        assert "jittered demo figure" in src

    def test_live_ioc_stream_heading_is_conditional(self):
        src = _read_template()
        assert "'Live IOC Stream' if feed.is_live else" in src.replace('"', "'")

    def test_refresh_feed_js_updates_heading_from_is_live(self):
        fn = _read_template().split("async function refreshFeed()")[1].split("\nasync function")[0]
        assert "data.is_live" in fn
        assert "feed-stream-heading" in fn
