"""
Tests for the simulated/fabricated-data tagging on
modules/firewall/ngfw_v2.py::simulate_traffic_burst.

simulate_traffic_burst() generates synthetic demo traffic (randomly sampled
source IPs, request paths and bodies) and feeds it through the REAL DPI
signature engine and ML entropy scorer (deep_inspect() — 30+ real regex
signatures in DPI_SIGNATURES plus Shannon-entropy-based scoring in
_ml_threat_score()/_shannon_entropy()). Only the traffic being analyzed is
fabricated, not the detection logic itself.

Because deep_inspect() persists every result it scores (real or simulated)
into the same shared traffic_log, simulate_traffic_burst() must tag every
event it produces — both the dicts it returns AND the copies deep_inspect()
already persisted to disk — with simulated=True plus a bilingual note/note_ar,
following the same convention as modules/darkweb/intelligence.py and
app/services/recon/recon_engine.py's SIMULATED_NOTE_EN/AR.

deep_inspect() itself (and everything else in ngfw_v2.py / ai_firewall.py)
must remain completely untouched by this fix — real inspected traffic must
never carry a "simulated" key, and the real signature/entropy logic must be
unchanged.
"""
import inspect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.firewall.ngfw_v2 as ngfw


def _isolate_data_file(monkeypatch, tmp_path):
    monkeypatch.setattr(ngfw, "DATA_FILE", tmp_path / "ngfw_v2_state.json")


def _assert_simulated_tag(d: dict):
    assert d["simulated"] is True
    assert isinstance(d.get("note"), str) and d["note"]
    assert isinstance(d.get("note_ar"), str) and d["note_ar"]
    assert "simulat" in d["note"].lower()
    assert "محاكاة" in d["note_ar"]


# ── simulate_traffic_burst(): every produced event must be tagged ───────────

def test_simulate_traffic_burst_returns_are_all_tagged_simulated(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    results = ngfw.simulate_traffic_burst(10)
    assert len(results) == 10
    for r in results:
        _assert_simulated_tag(r)


def test_simulate_traffic_burst_note_text_matches_module_constants(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    results = ngfw.simulate_traffic_burst(3)
    for r in results:
        assert r["note"] == ngfw.SIMULATED_NOTE_EN
        assert r["note_ar"] == ngfw.SIMULATED_NOTE_AR


def test_simulate_traffic_burst_respects_cap_of_50(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    results = ngfw.simulate_traffic_burst(200)
    assert len(results) == 50
    for r in results:
        _assert_simulated_tag(r)


def test_simulate_traffic_burst_still_carries_real_dpi_ml_fields(monkeypatch, tmp_path):
    """The tag is additive — the real signature/ML output on each event is untouched."""
    _isolate_data_file(monkeypatch, tmp_path)
    results = ngfw.simulate_traffic_burst(5)
    for r in results:
        assert "threat_score" in r
        assert "ml_score" in r
        assert "ml_category" in r
        assert "signature_hits" in r
        assert "ml_features" in r
        assert set(r["ml_features"].keys()) == {
            "payload_length", "header_count", "path_depth", "param_count",
            "entropy", "special_char_density", "non_ascii_ratio",
            "hex_encoding_count", "double_encoding_count",
            "sql_keyword_count", "script_injection_count",
        }


def test_simulate_traffic_burst_persisted_state_entries_are_also_tagged(monkeypatch, tmp_path):
    """deep_inspect() persists each result to the shared traffic_log; those
    on-disk copies must be tagged too, since get_traffic_stats() reads them
    back for the dashboard."""
    _isolate_data_file(monkeypatch, tmp_path)
    results = ngfw.simulate_traffic_burst(7)

    state = ngfw._load_state()
    persisted = state["traffic_log"][:7]
    assert len(persisted) == 7
    for entry in persisted:
        _assert_simulated_tag(entry)

    stats = ngfw.get_traffic_stats()
    for entry in stats["recent_log"][:7]:
        _assert_simulated_tag(entry)


def test_simulate_traffic_burst_does_not_tag_pre_existing_real_entries(monkeypatch, tmp_path):
    """A real (pre-existing) traffic_log entry from deep_inspect() must not
    retroactively gain the simulated tag when a later burst runs."""
    _isolate_data_file(monkeypatch, tmp_path)

    real_result = ngfw.deep_inspect(
        method="GET", path="/api/health", headers={}, body="",
        src_ip="8.8.8.8", dst_port=443,
    )
    assert "simulated" not in real_result

    ngfw.simulate_traffic_burst(3)

    state = ngfw._load_state()
    real_entries = [e for e in state["traffic_log"] if e.get("src_ip") == "8.8.8.8" and e.get("path") == "/api/health"]
    assert len(real_entries) == 1
    assert "simulated" not in real_entries[0]


# ── Real surface (deep_inspect() called directly) must stay untouched ───────

def test_deep_inspect_called_directly_never_carries_simulated_flag(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    result = ngfw.deep_inspect(
        method="POST", path="/login", headers={"User-Agent": "Mozilla/5.0"},
        body="username=admin&password=admin", src_ip="203.0.113.5", dst_port=443,
    )
    assert "simulated" not in result


def test_get_traffic_stats_and_geo_block_list_never_carry_simulated_flag(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    ngfw.deep_inspect(method="GET", path="/", headers={}, body="", src_ip="1.2.3.4")
    stats = ngfw.get_traffic_stats()
    assert "simulated" not in stats
    geo = ngfw.get_geo_block_list()
    assert "simulated" not in geo


def test_deep_inspect_source_has_no_simulated_tag():
    """Guards against the fabricated-data tag ever leaking into the real
    DPI/ML inspection engine itself."""
    assert "simulated" not in inspect.getsource(ngfw.deep_inspect)
    assert "simulated" not in inspect.getsource(ngfw._ml_threat_score)
    assert "simulated" not in inspect.getsource(ngfw._extract_ml_features)
    assert "simulated" not in inspect.getsource(ngfw._shannon_entropy)
    assert "simulated" not in inspect.getsource(ngfw.get_traffic_stats)
    assert "simulated" not in inspect.getsource(ngfw.get_geo_block_list)


def test_ai_firewall_module_untouched_by_this_fix():
    """ai_firewall.py's real signature-matching/entropy-scoring logic
    (inspect_request_api) is a separate module with no cross-import to
    ngfw_v2.py, and must not have been modified by this fix."""
    import modules.firewall.ai_firewall as aifw

    assert "ngfw_v2" not in inspect.getsource(aifw)
    assert "simulate_traffic_burst" not in inspect.getsource(aifw)
