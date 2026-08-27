"""
Tests for the sample-IOC tagging on modules/ioc_correlation.py.

collect_iocs() merges modules.threat_intel.global_feed._SAMPLE_IOCS (~18
hardcoded/fabricated sample IOCs, not sourced from a live feed) with real
IOCs from AlienVault OTX (_load_otx_iocs(), only when OTX_API_KEY is set).

Every sample IOC must be tagged is_sample=True plus a bilingual note/note_ar,
following the same convention as tests/test_global_feed_estimated_tagging.py
and tests/test_darkweb_simulated_tagging.py. Real OTX-sourced IOCs must never
carry the tag, and the correlation math (weighted threat-ranking formula,
malware-family/adversary/subnet clustering, relationship linking, pattern
detection) must be completely unaffected by the tag's presence.
"""
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.ioc_correlation as ic
from modules.threat_intel.global_feed import _SAMPLE_IOCS


def _assert_sample_tag(ioc: dict):
    assert ioc["is_sample"] is True
    assert isinstance(ioc.get("note"), str) and ioc["note"]
    assert isinstance(ioc.get("note_ar"), str) and ioc["note_ar"]
    assert "sample" in ioc["note"].lower()
    assert any(ch in ioc["note_ar"] for ch in ("نموذج", "تجزئ", "ثابت"))


# ── collect_iocs(): sample IOCs must be tagged, real OTX IOCs must not ───────

def test_collect_iocs_tags_all_sample_iocs_with_no_otx_key(monkeypatch):
    monkeypatch.setattr(ic, "OTX_API_KEY", "")
    iocs = ic.collect_iocs()
    assert len(iocs) == len(_SAMPLE_IOCS)
    for ioc in iocs:
        _assert_sample_tag(ioc)


def test_collect_iocs_does_not_tag_real_otx_iocs(monkeypatch):
    fake_otx_ioc = {
        "id": "otxabc123",
        "type": "ip",
        "value": "198.51.100.42",
        "malware": "RealOtxMalware",
        "confidence": 84,
        "adversary": "APT28",
        "tags": ["real-otx-tag"],
        "threat_score": 88,
        "pulse_name": "Real Pulse",
    }
    monkeypatch.setattr(ic, "OTX_API_KEY", "fake-key-for-test")
    monkeypatch.setattr(ic, "_load_otx_iocs", lambda: [fake_otx_ioc])

    iocs = ic.collect_iocs()
    sample_count = len(_SAMPLE_IOCS)
    assert len(iocs) == sample_count + 1

    otx_entries = [i for i in iocs if i["source"] == "ALIENVAULT-OTX" and i.get("pulse_name")]
    assert len(otx_entries) == 1
    otx_ioc = otx_entries[0]
    assert otx_ioc["value"] == "198.51.100.42"
    assert otx_ioc["malware"] == "RealOtxMalware"
    assert otx_ioc["confidence"] == 84
    assert "is_sample" not in otx_ioc
    assert "note" not in otx_ioc
    assert "note_ar" not in otx_ioc

    # Every remaining entry is still a tagged sample IOC.
    sample_entries = [i for i in iocs if i is not otx_ioc]
    assert len(sample_entries) == sample_count
    for ioc in sample_entries:
        _assert_sample_tag(ioc)


def test_collect_iocs_preserves_real_sample_ioc_fields_untouched(monkeypatch):
    monkeypatch.setattr(ic, "OTX_API_KEY", "")
    iocs = ic.collect_iocs()
    by_value = {i["value"]: i for i in iocs}

    for original in _SAMPLE_IOCS:
        collected = by_value[original["value"]]
        assert collected["type"] == original["type"]
        assert collected["malware"] == original["malware"]
        assert collected["confidence"] == original["confidence"]
        assert collected["source"] == original["source"]
        # The global_feed source list itself must never be mutated in place.
        assert "is_sample" not in original
        assert "note" not in original
        assert "note_ar" not in original


# ── correlate_iocs(): tag must propagate into clusters without altering math ─

def test_sample_tag_propagates_into_clusters_unchanged(monkeypatch):
    monkeypatch.setattr(ic, "OTX_API_KEY", "")
    iocs = ic.collect_iocs()
    clusters = ic.correlate_iocs(iocs)
    assert clusters, "expected at least one cluster"

    for cluster in clusters:
        for member in cluster["iocs"]:
            _assert_sample_tag(member)


def test_correlation_math_unaffected_by_presence_of_tag(monkeypatch):
    """Stripping is_sample/note/note_ar from the IOC dicts must not change
    cluster scores, severities, relationships or pattern detection at all —
    proves the tag is inert w.r.t. the correlation/clustering logic."""
    monkeypatch.setattr(ic, "OTX_API_KEY", "")
    tagged_iocs = ic.collect_iocs()

    stripped_iocs = []
    for ioc in tagged_iocs:
        stripped = copy.deepcopy(ioc)
        stripped.pop("is_sample", None)
        stripped.pop("note", None)
        stripped.pop("note_ar", None)
        stripped_iocs.append(stripped)

    tagged_clusters = ic.correlate_iocs(copy.deepcopy(tagged_iocs))
    stripped_clusters = ic.correlate_iocs(stripped_iocs)

    assert len(tagged_clusters) == len(stripped_clusters)
    for tagged_c, stripped_c in zip(tagged_clusters, stripped_clusters):
        assert tagged_c["cluster_id"] == stripped_c["cluster_id"]
        assert tagged_c["threat_score"] == stripped_c["threat_score"]
        assert tagged_c["severity"] == stripped_c["severity"]
        assert tagged_c["ioc_count"] == stripped_c["ioc_count"]
        assert tagged_c["ioc_types"] == stripped_c["ioc_types"]
        assert tagged_c["patterns"] == stripped_c["patterns"]
        assert len(tagged_c["relationships"]) == len(stripped_c["relationships"])


def test_run_correlation_summary_stats_unaffected(monkeypatch, tmp_path):
    monkeypatch.setattr(ic, "OTX_API_KEY", "")
    monkeypatch.setattr(ic, "DATA_FILE", tmp_path / "ioc_correlations.json")
    result = ic.run_correlation(save=False)
    assert result["total_iocs"] == len(_SAMPLE_IOCS)
    assert result["total_clusters"] > 0
    assert result["average_score"] >= 0
    # Sanity: tag doesn't leak into top-level summary fields.
    assert "is_sample" not in result


# ── Guard against the tag leaking into the real, live-queried feed modules ───

def test_no_sample_tag_leak_into_otx_feed_module():
    import inspect
    import modules.threat_intel.otx_feed as otx

    source = inspect.getsource(otx)
    assert "is_sample" not in source
    assert "IOC_SAMPLE_NOTE" not in source


def test_no_sample_tag_leak_into_urlhaus_feed_module():
    import inspect
    import modules.threat_intel.urlhaus_feed as urlhaus

    source = inspect.getsource(urlhaus)
    assert "is_sample" not in source
    assert "IOC_SAMPLE_NOTE" not in source
