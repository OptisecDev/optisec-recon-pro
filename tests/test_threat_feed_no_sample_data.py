"""The threat feed and IOC correlations hold real indicators only.

modules/threat_intel/global_feed.py used to ship _SAMPLE_IOCS (~18 hardcoded
indicators labelled as Mandiant / CISA KEV / Spamhaus / etc.) and enriched
every IOC with a random TLP and random first/last-seen dates. Both are gone:

- With no live source (AlienVault OTX, abuse.ch URLhaus) returning data,
  the feed and /correlations are an honest empty state: is_live=False,
  iocs=[], plus a note telling the operator what to configure.
- Real indicators pass through as-is. tlp/first_seen/last_seen come from
  the source (OTX, a submitter's chosen TLP) or are left None.
- Feed Sources status is computed per request from what each source
  actually returned — OTX is never labelled sample/demo while connected,
  and catalogued sources with no integration say so.

Replaces tests/test_global_feed_sample_tagging.py,
tests/test_global_feed_estimated_tagging.py and
tests/test_ioc_correlation_sample_tagging.py, which asserted the sample /
estimated data itself. Their still-applicable guards (real OTX IOCs pass
through untouched, submit_ioc() keeps the user's TLP, no tagging leaks
into otx_feed.py / urlhaus_feed.py) are carried over below.
"""
import inspect
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.ioc_correlation as ic
import modules.threat_intel.global_feed as gf
from web.routers.threat_feed import _build_feed

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

URLHAUS_IOC = {
    "type": "url",
    "value": "http://real-urlhaus-example.test/payload.exe",
    "malware": "TestMalware",
    "confidence": 77,
    "source": "URLHAUS",
}

OTX_IOC = {
    "id": "abc123", "type": "ip", "value": "198.51.100.7", "malware": "RealPulseMalware",
    "confidence": 80, "source": "ALIENVAULT-OTX", "tlp": "GREEN",
    "first_seen": "2026-01-01T00:00:00", "last_seen": "2026-01-02T00:00:00",
    "tags": ["real-otx-tag"], "threat_score": 82,
}

FABRICATION_KEYS = ("is_sample", "sample_note", "sample_note_ar", "tlp_source", "date_source")


@pytest.fixture(autouse=True)
def _isolate_data_files(tmp_path, monkeypatch):
    monkeypatch.setattr(gf, "DATA_FILE", tmp_path / "global_threat_feed.json")
    monkeypatch.setattr(ic, "DATA_FILE", tmp_path / "ioc_correlations.json")


def _read(path: str) -> str:
    with open(os.path.join(REPO, path), encoding="utf-8") as f:
        return f.read()


# ── global_feed: no sample pool, no invented fields ──────────────────────────

class TestNoSamplePool:
    def test_sample_and_estimation_helpers_are_gone(self):
        for name in ("_SAMPLE_IOCS", "SAMPLE_DATA_NOTE_EN", "SAMPLE_DATA_NOTE_AR",
                     "IOC_ESTIMATED_NOTE_EN", "IOC_ESTIMATED_NOTE_AR", "_fake_date"):
            assert not hasattr(gf, name), name
        src = inspect.getsource(gf)
        assert "import random" not in src
        assert "random." not in src

    def test_nothing_imports_sample_iocs(self):
        for path in ("modules/ioc_correlation.py", "web/routers/threat_feed.py",
                     "web/routers/threat_sharing.py", "web/routers/correlations.py", "web/app.py"):
            assert "_SAMPLE_IOCS" not in _read(path), path

    def test_feed_stats_has_no_sample_count(self):
        assert "sample_ioc_count" not in gf.get_feed_stats()


class TestEmptyStateWithoutLiveSource:
    def test_feed_is_empty_and_not_live(self):
        feed = gf.get_live_ioc_feed(limit=50)
        assert feed["iocs"] == []
        assert feed["total"] == 0
        assert feed["is_live"] is False
        assert feed["note"] == gf.NO_LIVE_SOURCE_NOTE_EN
        assert feed["note_ar"] == gf.NO_LIVE_SOURCE_NOTE_AR
        assert "OTX" in feed["note"] and "URLhaus" in feed["note"]
        assert feed["global_threat_level"] is None

    def test_community_submissions_alone_do_not_make_the_feed_live(self):
        gf.submit_ioc("ip", "203.0.113.9", "TestMalware", 80, tlp="GREEN")
        feed = gf.get_live_ioc_feed(limit=50)
        assert feed["iocs"] == []
        assert feed["is_live"] is False

    def test_build_feed_empty_state(self):
        feed = _build_feed([], gf.get_live_ioc_feed(limit=50), otx_configured=False)
        assert feed["iocs"] == []
        assert feed["is_live"] is False
        assert feed["otx_live"] is False
        assert feed["note"] == gf.NO_LIVE_SOURCE_NOTE_EN
        assert feed["global_threat_level"] is None


class TestRealDataPassesThrough:
    def test_urlhaus_ioc_has_no_invented_tlp_or_dates(self):
        feed = gf.get_live_ioc_feed(limit=50, urlhaus_iocs=[URLHAUS_IOC])
        assert feed["is_live"] is True
        assert feed["note"] is None
        scored = next(i for i in feed["iocs"] if i["value"] == URLHAUS_IOC["value"])
        for key in ("type", "value", "malware", "confidence", "source"):
            assert scored[key] == URLHAUS_IOC[key]
        assert scored["tlp"] is None
        assert scored["first_seen"] is None
        assert scored["last_seen"] is None
        for key in FABRICATION_KEYS:
            assert key not in scored

    def test_submission_alongside_live_data_keeps_the_users_tlp(self):
        gf.submit_ioc("ip", "203.0.113.9", "TestMalware", 80, tlp="GREEN")
        feed = gf.get_live_ioc_feed(limit=50, urlhaus_iocs=[URLHAUS_IOC])
        scored = next(i for i in feed["iocs"] if i["value"] == "203.0.113.9")
        assert scored["tlp"] == "GREEN"
        assert scored["source"] == "OPTISEC-GLOBAL"

    def test_submit_ioc_result_is_not_tagged(self):
        result = gf.submit_ioc("ip", "203.0.113.5", "TestMalware", 80, tlp="GREEN")
        assert result["tlp"] == "GREEN"
        for key in FABRICATION_KEYS:
            assert key not in result

    def test_build_feed_passes_real_otx_iocs_through_unchanged(self):
        otx_iocs = [dict(OTX_IOC)]
        feed = _build_feed(otx_iocs, fallback_feed={"iocs": []}, otx_configured=True)
        assert feed["otx_live"] is True
        assert feed["is_live"] is True
        assert feed["iocs"] == [OTX_IOC]

    def test_otx_and_urlhaus_modules_carry_no_tagging(self):
        import modules.threat_intel.otx_feed as otx
        import modules.threat_intel.urlhaus_feed as urlhaus
        for mod in (otx, urlhaus):
            src = inspect.getsource(mod)
            for key in ("is_sample", "tlp_source", "date_source", "IOC_SAMPLE_NOTE"):
                assert key not in src
        assert "estimated" not in inspect.getsource(otx).lower()


# ── Feed Sources tab: status computed from the actual connection ─────────────

def _status(feed: dict, source_id: str) -> dict:
    return next(s for s in feed["feed_sources"] if s["id"] == source_id)


class TestFeedSourceStatus:
    def test_no_source_is_labelled_sample(self):
        for src in gf.FEED_SOURCES:
            assert "is_sample" not in src
            assert src["integration"] in ("live", "community", "none")

    def test_otx_connected_when_it_returned_indicators(self):
        feed = _build_feed([dict(OTX_IOC)], fallback_feed={"iocs": []}, otx_configured=True)
        otx = _status(feed, "ALIENVAULT-OTX")
        assert otx["status"] == "connected"
        assert otx["ioc_count"] == 1

    def test_otx_configured_but_nothing_returned(self):
        feed = _build_feed([], fallback_feed={"iocs": []}, otx_configured=True)
        assert _status(feed, "ALIENVAULT-OTX")["status"] == "configured_no_data"

    def test_otx_not_configured(self):
        feed = _build_feed([], fallback_feed={"iocs": []}, otx_configured=False)
        assert _status(feed, "ALIENVAULT-OTX")["status"] == "not_configured"

    def test_urlhaus_status_counts_synced_rows_even_when_otx_takes_precedence(self):
        fallback = gf.get_live_ioc_feed(limit=50, urlhaus_iocs=[URLHAUS_IOC])
        feed = _build_feed([dict(OTX_IOC)], fallback_feed=fallback, otx_configured=True)
        urlhaus = _status(feed, "URLHAUS")
        assert urlhaus["status"] == "connected"
        assert urlhaus["ioc_count"] == 1

    def test_urlhaus_not_configured_when_nothing_synced(self):
        feed = _build_feed([], gf.get_live_ioc_feed(limit=50), otx_configured=False)
        assert _status(feed, "URLHAUS")["status"] == "not_configured"

    def test_catalogue_only_vendors_are_not_integrated(self):
        feed = _build_feed([], fallback_feed={"iocs": []})
        for vendor in ("MANDIANT", "CISA-KEV", "SPAMHAUS", "MISP-COMMUNITY",
                       "ABUSE-CH", "FEODO-TRACKER", "CIRCL-LU"):
            assert _status(feed, vendor)["status"] == "not_integrated"


class TestThreatFeedTemplate:
    def test_no_sample_or_estimated_markup_left(self):
        src = _read("web/templates/threat_feed.html")
        for text in ("Sample / Demo", "SAMPLE DATA", "is_sample", "sample_note",
                     "tlp_source", "date_source", "estimated locally"):
            assert text not in src, text

    def test_feed_sources_tab_renders_computed_status(self):
        src = _read("web/templates/threat_feed.html")
        sources_tab = src.split('<div id="tab-sources"')[1].split("<!-- SUBMIT IOC TAB -->")[0]
        assert "src.status" in sources_tab
        assert "Connected (" in sources_tab
        assert "Not integrated" in sources_tab

    def test_empty_state_note_is_rendered(self):
        src = _read("web/templates/threat_feed.html")
        assert "{% if not feed.is_live %}" in src
        assert "feed.note" in src
        fn = src.split("async function refreshFeed()")[1].split("\nasync function")[0]
        assert "data.note" in fn


# ── /correlations: same honest empty state ───────────────────────────────────

class TestCorrelationsEmptyState:
    def test_collect_iocs_is_empty_without_otx(self, monkeypatch):
        monkeypatch.setattr(ic, "OTX_API_KEY", "")
        assert ic.collect_iocs() == []

    def test_run_correlation_without_live_source(self, monkeypatch):
        monkeypatch.setattr(ic, "OTX_API_KEY", "")
        result = ic.run_correlation(save=False)
        assert result["is_live"] is False
        assert result["total_iocs"] == 0
        assert result["clusters"] == []
        assert result["note"] == ic.NO_LIVE_SOURCE_NOTE_EN
        assert "OTX" in result["note"]
        assert result["note_ar"] == ic.NO_LIVE_SOURCE_NOTE_AR

    def test_collect_iocs_returns_only_real_otx_iocs_untagged(self, monkeypatch):
        fake_otx_ioc = {"id": "otxabc123", "type": "ip", "value": "198.51.100.42",
                        "malware": "RealOtxMalware", "confidence": 84, "adversary": "APT28",
                        "tags": ["real-otx-tag"], "threat_score": 88, "pulse_name": "Real Pulse"}
        monkeypatch.setattr(ic, "OTX_API_KEY", "fake-key-for-test")
        monkeypatch.setattr(ic, "_load_otx_iocs", lambda: [fake_otx_ioc])

        iocs = ic.collect_iocs()
        assert len(iocs) == 1
        assert iocs[0]["value"] == "198.51.100.42"
        assert iocs[0]["source"] == "ALIENVAULT-OTX"
        for key in ("is_sample", "note", "note_ar"):
            assert key not in iocs[0]

        result = ic.run_correlation(save=False)
        assert result["is_live"] is True
        assert result["note"] is None
        assert result["total_iocs"] == 1

    def test_legacy_cache_without_is_live_is_ignored(self):
        ic.DATA_FILE.write_text(json.dumps({"total_iocs": 18, "clusters": [{"name": "Emotet"}]}))
        assert ic.load_cached() is None

    def test_current_cache_is_served(self, monkeypatch):
        monkeypatch.setattr(ic, "OTX_API_KEY", "")
        ic.run_correlation(save=True)
        cached = ic.load_cached()
        assert cached is not None and cached["is_live"] is False

    def test_correlations_template_has_no_sample_markup(self):
        src = _read("web/templates/correlations.html")
        assert "is_sample" not in src
        assert "data.note" in src


# ── Rendered page ────────────────────────────────────────────────────────────

def _render_threat_feed_page(monkeypatch, seed_urlhaus: bool) -> str:
    import asyncio
    from fastapi.testclient import TestClient
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from sqlalchemy.pool import StaticPool

    import web.app as app_module
    import web.routers.threat_feed as threat_feed_router
    from modules.ioc.ioc_engine import IOCRepository
    from web.auth import create_access_token, hash_password
    from web.database import Base, get_db
    from web.models import User, Ioc  # noqa: F401 — registers the table

    monkeypatch.setattr(threat_feed_router, "OTX_API_KEY", "")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
                                 connect_args={"check_same_thread": False})
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with session_factory() as db:
            user = User(username="tf_page", email="tf_page@example.com",
                        password_hash=hash_password("Passw0rd!1"), role="analyst",
                        subscription_tier="enterprise", is_active=True)
            db.add(user)
            if seed_urlhaus:
                await IOCRepository(db).create("url", "http://real-malware.example/x",
                                               source="urlhaus", confidence_score=90.0)
            await db.commit()
            await db.refresh(user)
            return user.id

    user_id = asyncio.run(setup())

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db
    try:
        resp = TestClient(app_module.app).get(
            "/threat-feed", cookies={"access_token": create_access_token(user_id, "analyst")})
        assert resp.status_code == 200, resp.text[:500]
        return resp.text
    finally:
        app_module.app.dependency_overrides.pop(get_db, None)
        asyncio.run(engine.dispose())


class TestRenderedThreatFeedPage:
    def test_empty_state_page(self, monkeypatch):
        html = _render_threat_feed_page(monkeypatch, seed_urlhaus=False)
        assert "No live threat source connected" in html
        assert "GLOBAL THREAT LEVEL" not in html
        assert "Sample / Demo" not in html

    def test_live_urlhaus_page(self, monkeypatch):
        html = _render_threat_feed_page(monkeypatch, seed_urlhaus=True)
        assert "http://real-malware.example/x" in html
        assert "GLOBAL THREAT LEVEL" in html
        assert "No live threat source connected" not in html
        assert "TLP:" not in html.split('id="ioc-feed-list"')[1].split("</div>\n  </div>\n</div>")[0]
        assert "Connected (1)" in html
