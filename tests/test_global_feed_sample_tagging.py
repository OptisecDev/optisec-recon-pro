"""
Tests for the is_sample honesty labeling on modules/threat_intel/global_feed.py
(Public-Claims Audit follow-up).

FEED_SOURCES lists ten "intelligence feed sources" (Mandiant, CISA KEV,
Spamhaus, MISP, etc.) but only URLhaus is backed by a real sync job
(fetch_real_urlhaus_iocs(), from modules/ioc/scheduler.py's periodic
URLhaus sync) -- every other source is just a label attached to the
hardcoded _SAMPLE_IOCS list. Every source in the catalog, and every IOC
returned by get_live_ioc_feed(), must carry an is_sample flag that reflects
this so the UI can render a "Sample / Demo data" badge instead of implying
a live vendor integration.

Mirrors tests/test_global_feed_estimated_tagging.py's isolation pattern
(monkeypatched DATA_FILE, no real filesystem state).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.threat_intel.global_feed as gf
from web.routers.threat_feed import _build_feed


def _isolate_data_file(monkeypatch, tmp_path):
    monkeypatch.setattr(gf, "DATA_FILE", tmp_path / "global_threat_feed.json")


TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web", "templates", "threat_feed.html",
)


def _read_template() -> str:
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        return f.read()


# ── FEED_SOURCES catalog: only URLhaus is live ────────────────────────────────

def test_only_urlhaus_source_is_not_sample():
    non_sample = [s["id"] for s in gf.FEED_SOURCES if not s["is_sample"]]
    assert non_sample == ["URLHAUS"]


def test_every_named_vendor_source_is_marked_sample():
    named_vendors = {"MANDIANT", "CISA-KEV", "SPAMHAUS", "MISP-COMMUNITY", "ABUSE-CH", "FEODO-TRACKER", "CIRCL-LU"}
    by_id = {s["id"]: s for s in gf.FEED_SOURCES}
    for vendor_id in named_vendors:
        assert by_id[vendor_id]["is_sample"] is True, f"{vendor_id} must be marked is_sample=True"


# ── get_live_ioc_feed(): per-IOC is_sample provenance ─────────────────────────

def test_sample_iocs_are_tagged_is_sample_true(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    feed = gf.get_live_ioc_feed(limit=len(gf._SAMPLE_IOCS))
    by_value = {i["value"]: i for i in feed["iocs"]}
    for original in gf._SAMPLE_IOCS:
        scored = by_value[original["value"]]
        assert scored["is_sample"] is True
        assert isinstance(scored.get("sample_note"), str) and scored["sample_note"]
        assert isinstance(scored.get("sample_note_ar"), str) and scored["sample_note_ar"]


def test_real_urlhaus_iocs_are_tagged_is_sample_false(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    urlhaus_ioc = {
        "type": "url",
        "value": "http://real-urlhaus-example.test/payload.exe",
        "malware": "TestMalware",
        "confidence": 77,
        "source": "URLHAUS",
    }
    feed = gf.get_live_ioc_feed(limit=50, urlhaus_iocs=[urlhaus_ioc])
    scored = next(i for i in feed["iocs"] if i["value"] == urlhaus_ioc["value"])
    assert scored["is_sample"] is False
    assert scored.get("sample_note") is None
    assert scored.get("sample_note_ar") is None


def test_submitted_ioc_is_tagged_is_sample_false(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    result = gf.submit_ioc("ip", "203.0.113.9", "TestMalware", 80, tlp="GREEN")
    assert result["is_sample"] is False

    feed = gf.get_live_ioc_feed(limit=50)
    scored = next(i for i in feed["iocs"] if i["value"] == "203.0.113.9")
    assert scored["is_sample"] is False


# ── web.routers.threat_feed._build_feed() must not strip is_sample ───────────

def test_build_feed_preserves_is_sample_on_fallback_iocs(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    fallback = gf.get_live_ioc_feed(limit=5)
    feed = _build_feed([], fallback_feed=fallback)
    assert feed["iocs"], "expected fallback IOCs to be present"
    assert any(i.get("is_sample") is True for i in feed["iocs"])


def test_build_feed_real_otx_iocs_are_not_marked_sample():
    otx_iocs = [{
        "id": "abc123", "type": "ip", "value": "198.51.100.9", "malware": "RealPulseMalware",
        "confidence": 80, "source": "ALIENVAULT-OTX", "tlp": "GREEN",
        "first_seen": "2026-01-01T00:00:00", "last_seen": "2026-01-02T00:00:00",
        "tags": [], "threat_score": 82,
    }]
    feed = _build_feed(otx_iocs, fallback_feed={"iocs": [], "feed_sources": []})
    for ioc in feed["iocs"]:
        assert not ioc.get("is_sample")


# ── UI must render a visible badge, not just carry the API field ─────────────

def test_template_renders_sample_badge_for_jinja_ioc_rows():
    src = _read_template()
    ioc_loop = src.split("{% for ioc in feed.iocs %}")[1].split("{% endfor %}")[0]
    assert "ioc.is_sample" in ioc_loop
    assert "Sample / Demo data" in ioc_loop


def test_template_renders_sample_badge_in_js_refresh_feed():
    src = _read_template()
    fn = src.split("async function refreshFeed()")[1].split("async function")[0]
    assert "ioc.is_sample" in fn
    assert "Sample / Demo data" in fn


def test_template_renders_live_or_sample_badge_for_feed_sources_tab():
    src = _read_template()
    sources_tab = src.split('<div id="tab-sources"')[1].split("<!-- SUBMIT IOC TAB -->")[0]
    assert "src.is_sample" in sources_tab
    assert "Sample / Demo data" in sources_tab
    # A non-sample source only shows "Live" when it actually has indicators
    # in the current feed right now (live_count > 0) — a static "Live"
    # badge regardless of whether anything ever synced would itself be a
    # false claim (see the URLhaus-invalid-key case this guards against).
    assert "live_count" in sources_tab
    assert re.search(r">Live \(", sources_tab)
    assert "0 synced — check connection" in sources_tab
