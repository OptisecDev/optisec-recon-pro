"""
Tests for web.app._finding_kwargs_from_vuln() — the pure function that turns
one scanner result dict (now carrying every WAF-aware classifier verdict,
not just CONFIRMED — see modules/vuln/waf_aware_classifier.py and the five
vuln scanners) into Finding(**kwargs), and in particular the
include_in_report flag.

Retaining WAF_BLOCKED/ENDPOINT_INVALID/ENCODED_SAFE/INCONCLUSIVE findings in
the database (instead of discarding them pre-save, as before) must not
change what the client sees: include_in_report is False for all of those,
True only for CONFIRMED, and web/app.py's dashboard/report/API reads filter
on it accordingly (see web/migrate_add_finding_include_in_report_column.py).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# web.app is a module-level singleton (route registration happens at import
# time) and tests/test_migration_endpoint.py also imports it after setting
# this same env var to register a production-only route. Whichever test file
# runs first under pytest's alphabetical collection wins the real import, so
# this must match that file's env var exactly or the other suite's routes
# silently go missing depending on run order.
os.environ.setdefault("GROQ_ENV", "production")

import web.app as app_module


def _kwargs(verdict, **extra):
    v = {"type": "XSS", "severity": "High", "url": "https://x/", "parameter": "q",
         "payload": "<script>", "evidence": "reason", "waf_detected": None,
         "verdict": verdict, **extra}
    return app_module._finding_kwargs_from_vuln(v, "scan-1", 42, None)


def test_confirmed_is_included_in_report():
    kwargs = _kwargs("CONFIRMED")
    assert kwargs["include_in_report"] is True
    assert kwargs["verdict"] == "CONFIRMED"


def test_waf_blocked_is_saved_but_excluded_from_report():
    kwargs = _kwargs("WAF_BLOCKED", waf_detected="Cloudflare")
    assert kwargs["include_in_report"] is False
    assert kwargs["verdict"] == "WAF_BLOCKED"
    assert kwargs["waf_detected"] == "Cloudflare"


def test_endpoint_invalid_is_saved_but_excluded_from_report():
    kwargs = _kwargs("ENDPOINT_INVALID")
    assert kwargs["include_in_report"] is False


def test_encoded_safe_is_saved_but_excluded_from_report():
    kwargs = _kwargs("ENCODED_SAFE")
    assert kwargs["include_in_report"] is False


def test_inconclusive_is_saved_but_excluded_from_report():
    kwargs = _kwargs("INCONCLUSIVE")
    assert kwargs["include_in_report"] is False


def test_missing_verdict_defaults_to_excluded():
    v = {"type": "XSS"}
    kwargs = app_module._finding_kwargs_from_vuln(v, "scan-1", None, None)
    assert kwargs["include_in_report"] is False
    assert kwargs["verdict"] is None


def test_triage_fields_pass_through_only_when_present():
    v = {"verdict": "CONFIRMED"}
    triage = {"triage_verdict": "CONFIRMED", "triage_confidence": 0.9, "triage_reason": "looks real"}
    kwargs = app_module._finding_kwargs_from_vuln(v, "scan-1", None, triage)
    assert kwargs["triage_verdict"] == "CONFIRMED"
    assert kwargs["triage_confidence"] == 0.9

    kwargs_no_triage = app_module._finding_kwargs_from_vuln(v, "scan-1", None, None)
    assert kwargs_no_triage["triage_verdict"] is None
    assert kwargs_no_triage["triage_confidence"] is None


def test_scan_id_and_target_id_pass_through():
    kwargs = _kwargs("CONFIRMED")
    assert kwargs["scan_id"] == "scan-1"
    assert kwargs["target_id"] == 42
