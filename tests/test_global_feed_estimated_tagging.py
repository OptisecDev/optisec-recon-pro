"""
Tests for the estimated-field tagging on modules/threat_intel/global_feed.py.

get_live_ioc_feed() enriches every real IOC (from _SAMPLE_IOCS, a caller-
supplied urlhaus_iocs list from fetch_real_urlhaus_iocs(), or a previously
submit_ioc()'d entry) with a TLP classification (random.choice) and
first_seen/last_seen dates (random day offsets) that are NOT part of the
original indicator. get_threat_map() jitters attacks_per_hour and fabricates
active_campaigns per point on every call for a "live" visual effect.

Every such fabricated value must be tagged (tlp_source/date_source per IOC,
map_jitter at the threat-map root) plus a bilingual note/note_ar, following
the same convention as tests/test_darkweb_simulated_tagging.py and
modules/quantum/encryption.py's mode="simulated".

Real fields that pass straight through from the original IOC/source data
(type, value, malware, confidence, source for IOCs; lat/lon/country/code/
threat_level for map points) must remain byte-for-byte unmodified and must
never themselves carry an estimated/jitter tag.

OTX-sourced IOCs (modules/threat_intel/otx_feed.py's fetch_otx_pulses())
carry real tlp/first_seen/last_seen straight from the OTX API and never flow
through get_live_ioc_feed(), so web.routers.threat_feed._build_feed() must
never add these tags to them.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.threat_intel.global_feed as gf
from web.routers.threat_feed import _build_feed


def _isolate_data_file(monkeypatch, tmp_path):
    monkeypatch.setattr(gf, "DATA_FILE", tmp_path / "global_threat_feed.json")


def _assert_ioc_estimated_tag(ioc: dict):
    assert ioc["tlp_source"] == "estimated"
    assert ioc["date_source"] == "estimated"
    assert isinstance(ioc.get("note"), str) and ioc["note"]
    assert isinstance(ioc.get("note_ar"), str) and ioc["note_ar"]
    assert "estimat" in ioc["note"].lower()
    assert any(ch in ioc["note_ar"] for ch in ("تقدير", "عشوائ"))


# ── get_live_ioc_feed(): fabricated tlp/dates must be tagged ─────────────────

def test_live_feed_iocs_are_tagged_estimated(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    feed = gf.get_live_ioc_feed(limit=10)
    assert feed["iocs"], "expected at least one scored IOC"
    for ioc in feed["iocs"]:
        _assert_ioc_estimated_tag(ioc)
        assert ioc["tlp"] in ("WHITE", "GREEN", "AMBER", "RED")


def test_live_feed_preserves_real_sample_ioc_fields_untouched(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    feed = gf.get_live_ioc_feed(limit=len(gf._SAMPLE_IOCS))
    by_value = {i["value"]: i for i in feed["iocs"]}

    for original in gf._SAMPLE_IOCS:
        scored = by_value[original["value"]]
        assert scored["type"] == original["type"]
        assert scored["malware"] == original["malware"]
        assert scored["confidence"] == original["confidence"]
        assert scored["source"] == original["source"]
        # The real fields themselves must never carry the estimated tag.
        assert "tlp_source" not in original
        assert "date_source" not in original


def test_live_feed_tags_caller_supplied_urlhaus_iocs_too(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    urlhaus_ioc = {
        "type": "url",
        "value": "http://malicious-urlhaus-example.test/payload.exe",
        "malware": "TestMalware",
        "confidence": 77,
        "source": "URLHAUS",
    }
    feed = gf.get_live_ioc_feed(limit=50, urlhaus_iocs=[urlhaus_ioc])
    scored = next(i for i in feed["iocs"] if i["value"] == urlhaus_ioc["value"])
    _assert_ioc_estimated_tag(scored)
    assert scored["type"] == "url"
    assert scored["malware"] == "TestMalware"
    assert scored["confidence"] == 77
    assert scored["source"] == "URLHAUS"


def test_submit_ioc_result_is_not_retroactively_tagged(monkeypatch, tmp_path):
    """submit_ioc() sets tlp from the caller's own input, not random.choice —
    it must not carry the get_live_ioc_feed() estimated tags."""
    _isolate_data_file(monkeypatch, tmp_path)
    result = gf.submit_ioc("ip", "203.0.113.5", "TestMalware", 80, tlp="GREEN")
    assert result["tlp"] == "GREEN"
    assert "tlp_source" not in result
    assert "date_source" not in result


# ── get_threat_map(): jitter must be tagged at the root ──────────────────────

def test_threat_map_is_tagged_jitter_at_root():
    result = gf.get_threat_map()
    assert result["map_jitter"] is True
    assert isinstance(result.get("note"), str) and result["note"]
    assert isinstance(result.get("note_ar"), str) and result["note_ar"]
    assert "jitter" in result["note"].lower()
    assert any(ch in result["note_ar"] for ch in ("تقدير", "عشوائ", "مُهتز", "مهتز"))


def test_threat_map_points_preserve_real_baseline_fields():
    result = gf.get_threat_map()
    baseline_by_code = {p["code"]: p for p in gf.THREAT_MAP_POINTS}

    for point in result["points"]:
        baseline = baseline_by_code[point["code"]]
        assert point["country"] == baseline["country"]
        assert point["lat"] == baseline["lat"]
        assert point["lon"] == baseline["lon"]
        assert point["threat_level"] == baseline["threat_level"]
        # Points themselves are not individually tagged — only the response root.
        assert "map_jitter" not in point
        assert "note" not in point
        # attacks_per_hour is baseline +/- 50, clamped at 0.
        assert point["attacks_per_hour"] >= 0
        assert abs(point["attacks_per_hour"] - baseline["attacks_per_hour"]) <= 50
        assert 0 <= point["active_campaigns"] <= 5


# ── Real, live-queried OTX surface must stay completely untouched ────────────

def test_build_feed_never_tags_real_otx_iocs():
    otx_iocs = [
        {
            "id": "abc123",
            "type": "ip",
            "value": "198.51.100.7",
            "malware": "RealPulseMalware",
            "confidence": 80,
            "source": "ALIENVAULT-OTX",
            "tlp": "GREEN",
            "first_seen": "2026-01-01T00:00:00",
            "last_seen": "2026-01-02T00:00:00",
            "tags": ["real-otx-tag"],
            "threat_score": 82,
        }
    ]
    feed = _build_feed(otx_iocs, fallback_feed={"iocs": [], "feed_sources": []})
    assert feed["otx_live"] is True
    assert feed["iocs"] == otx_iocs
    for ioc in feed["iocs"]:
        assert "tlp_source" not in ioc
        assert "date_source" not in ioc


def test_build_feed_falls_back_to_tagged_estimated_iocs_without_otx(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    fallback = gf.get_live_ioc_feed(limit=5)
    feed = _build_feed([], fallback_feed=fallback)
    assert feed["otx_live"] is False
    assert feed["iocs"], "expected fallback IOCs to be present"
    for ioc in feed["iocs"]:
        _assert_ioc_estimated_tag(ioc)


def test_real_otx_feed_module_source_has_no_estimated_tag():
    """Guards against the estimated tag ever leaking into the real,
    live-queried OTX surface."""
    import inspect
    import modules.threat_intel.otx_feed as otx

    source = inspect.getsource(otx)
    assert "tlp_source" not in source
    assert "date_source" not in source
    assert "estimated" not in source.lower()
