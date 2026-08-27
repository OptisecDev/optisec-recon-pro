"""
Tests for the simulated/fabricated-data tagging on modules/darkweb/intelligence.py.

This module is a legacy mock surface: simulate_tor_monitor() invents
response_time_ms/threat_score with `random`, and check_domain_breach()/
check_email_breach()/generate_threat_report() fabricate breach hits via
random and hashlib.md5-seeded generators. None of it queries a real breach
or dark-web feed. Every response from these functions must carry
"simulated": True at the root plus a bilingual note/note_ar, following the
same convention as app/services/recon/recon_engine.py's simulate_attack_chain()
and modules/quantum/encryption.py's mode="simulated".

The real, live-queried surface (modules/darkweb/monitor.py's build_leak_events(),
backed by HIBP/IntelligenceX/LeakCheck/OTX) must be completely unaffected by
this tag — it never carries a "simulated" key.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.darkweb.intelligence as dwi


def _isolate_data_file(monkeypatch, tmp_path):
    monkeypatch.setattr(dwi, "DATA_FILE", tmp_path / "darkweb_intel.json")


def _assert_simulated_tag(d: dict):
    assert d["simulated"] is True
    assert isinstance(d.get("note"), str) and d["note"]
    assert isinstance(d.get("note_ar"), str) and d["note_ar"]
    assert "simulat" in d["note"].lower()
    assert "محاكاة" in d["note_ar"]


# ── Legacy mock surface: every response must be tagged ───────────────────────

def test_simulate_tor_monitor_is_tagged_simulated_at_root():
    result = dwi.simulate_tor_monitor()
    _assert_simulated_tag(result)


def test_check_domain_breach_is_tagged_for_known_domain(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    result = dwi.check_domain_breach("adobe.com")
    _assert_simulated_tag(result)
    assert result["breaches_found"] >= 1


def test_check_domain_breach_is_tagged_for_unknown_domain(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    result = dwi.check_domain_breach("some-random-unknown-domain-xyz123.test")
    _assert_simulated_tag(result)


def test_check_email_breach_is_tagged_simulated_at_root():
    result = dwi.check_email_breach("someone@example.com")
    _assert_simulated_tag(result)


def test_generate_threat_report_is_tagged_simulated_at_root(monkeypatch, tmp_path):
    _isolate_data_file(monkeypatch, tmp_path)
    result = dwi.generate_threat_report("example.com")
    _assert_simulated_tag(result)
    # The nested breach_exposure (from check_domain_breach) is tagged too.
    _assert_simulated_tag(result["breach_exposure"])


def test_scan_paste_content_is_real_regex_analysis_and_untagged(monkeypatch, tmp_path):
    """scan_paste_content() runs real regex matching against caller-supplied
    content — it fabricates nothing, so it must NOT carry the simulated tag."""
    _isolate_data_file(monkeypatch, tmp_path)
    result = dwi.scan_paste_content("no secrets here")
    assert "simulated" not in result


# ── Real surface (HIBP/IntelX/LeakCheck/OTX-backed) must stay untouched ──────

def test_real_leak_events_never_carry_simulated_flag():
    import modules.darkweb.monitor as mon

    darkweb_result = {
        "breaches": [{"name": "ExampleCo", "title": "ExampleCo breach", "verified": True, "alias": ""}],
        "pastes": [{"id": "p1", "source": "pastebin"}],
        "github_exposures": [{"html_url": "https://github.com/x/y", "repository": "x/y"}],
        "threat_actors": ["some-actor"],
    }
    leakcheck_result = {"found": True, "sources": ["breach-db-1"], "fields": ["email"]}

    events = mon.build_leak_events(darkweb_result, leakcheck_result)
    assert len(events) == 5
    for event in events:
        assert "simulated" not in event
        assert set(event.keys()) == {"fingerprint", "source", "severity", "title", "detail"}


def test_real_monitor_module_source_has_no_simulated_tag():
    """Guards against the fabricated-data tag ever leaking into the real,
    live-queried monitoring surface."""
    import inspect
    import modules.darkweb.monitor as mon
    import modules.osint.darkweb_intelligence as osint_dw

    assert "simulated" not in inspect.getsource(mon)
    assert "simulated" not in inspect.getsource(osint_dw)
