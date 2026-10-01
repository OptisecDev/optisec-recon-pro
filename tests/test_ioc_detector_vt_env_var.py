"""Regression test: modules/threat_intel/ioc_detector.py used to read
os.environ["VIRUSTOTAL_API_KEY"] — a name documented nowhere (.env.example
defines VT_API_KEY) and different from modules/osint/unified_engine.py's
VT_API_KEY, the name this project actually uses for the VirusTotal key
everywhere else. A correctly-configured instance (VT_API_KEY set, per
.env.example) silently never enabled ioc_detector.py's VT checks.

ioc_detector.py reads the module-level VIRUSTOTAL_KEY constant at import
time, so this reloads the module under each env to verify the fix.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _reload_with_env(monkeypatch, **env):
    for key in ("VT_API_KEY", "VIRUSTOTAL_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import modules.threat_intel.ioc_detector as mod
    return importlib.reload(mod)


def test_reads_vt_api_key_matching_env_example_and_unified_engine(monkeypatch):
    mod = _reload_with_env(monkeypatch, VT_API_KEY="real-vt-key-123")
    assert mod.VIRUSTOTAL_KEY == "real-vt-key-123"


def test_no_longer_reads_the_undocumented_virustotal_api_key_name(monkeypatch):
    mod = _reload_with_env(monkeypatch, VIRUSTOTAL_API_KEY="stale-wrong-var")
    assert mod.VIRUSTOTAL_KEY == ""


def test_empty_when_neither_var_is_set(monkeypatch):
    mod = _reload_with_env(monkeypatch)
    assert mod.VIRUSTOTAL_KEY == ""
