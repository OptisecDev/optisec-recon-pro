"""
Tests for the Compliance Checker (modules/compliance/checker.py).

Regression coverage for a confirmed gap: auto_probe_target() runs a real
network check for HTTPS support, but assess_target() used to score purely
from the self-reported answers dict and never looked at the probe result —
so a user could claim "yes, we use HTTPS" (or the reverse) and the score
would reflect the claim even when it contradicted what auto_probe_target()
actually found.

Fix: for the controls that are really asking "is HTTPS/TLS used in
transit?" (NIST PR.DS-02 / data_in_transit_encryption, PCI DSS Req 4 /
strong_cryptography), assess_target() now calls auto_probe_target()
itself and lets the live finding override the self-reported answer,
recording the conflict in `auto_probe_mismatches` and on the control's
`auto_probe_mismatch` field.

Mirrors tests/test_geo_intel.py's conventions: plain pytest, async
functions driven via asyncio.run(), monkeypatched dependencies, no real
network calls.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.compliance.checker as checker


def _run(coro):
    return asyncio.run(coro)


def _all_unknown_answers(framework: str) -> dict:
    return {c["check"]: "unknown" for c in checker.FRAMEWORKS[framework]["controls"]}


class TestAssessUsesProbeSignal:
    def test_self_report_no_but_probe_finds_https_overrides_to_compliant(self, monkeypatch):
        async def fake_probe(target_url):
            return {"https_in_use": True, "status_code": 200}

        monkeypatch.setattr(checker, "auto_probe_target", fake_probe)

        answers = _all_unknown_answers("nist")
        answers["data_in_transit_encryption"] = "no"
        result = _run(checker.assess_target("https://example.com", "nist", answers))

        ctrl = next(c for c in result["controls"] if c["check"] == "data_in_transit_encryption")
        assert ctrl["status"] == "compliant"
        assert "auto_probe_mismatch" in ctrl
        assert len(result["auto_probe_mismatches"]) == 1
        assert result["auto_probe_mismatches"][0]["check"] == "data_in_transit_encryption"

    def test_self_report_yes_but_probe_finds_no_https_overrides_to_non_compliant(self, monkeypatch):
        async def fake_probe(target_url):
            return {"https_in_use": False, "status_code": 200}

        monkeypatch.setattr(checker, "auto_probe_target", fake_probe)

        answers = _all_unknown_answers("pci_dss")
        answers["strong_cryptography"] = "yes"
        result = _run(checker.assess_target("http://example.com", "pci_dss", answers))

        ctrl = next(c for c in result["controls"] if c["check"] == "strong_cryptography")
        assert ctrl["status"] == "non_compliant"
        assert "auto_probe_mismatch" in ctrl
        assert len(result["auto_probe_mismatches"]) == 1

    def test_self_report_agrees_with_probe_no_mismatch_recorded(self, monkeypatch):
        async def fake_probe(target_url):
            return {"https_in_use": True, "status_code": 200}

        monkeypatch.setattr(checker, "auto_probe_target", fake_probe)

        answers = _all_unknown_answers("nist")
        answers["data_in_transit_encryption"] = "yes"
        result = _run(checker.assess_target("https://example.com", "nist", answers))

        ctrl = next(c for c in result["controls"] if c["check"] == "data_in_transit_encryption")
        assert ctrl["status"] == "compliant"
        assert "auto_probe_mismatch" not in ctrl
        assert result["auto_probe_mismatches"] == []

    def test_unanswered_check_is_filled_from_probe_without_mismatch(self, monkeypatch):
        async def fake_probe(target_url):
            return {"https_in_use": True, "status_code": 200}

        monkeypatch.setattr(checker, "auto_probe_target", fake_probe)

        answers = _all_unknown_answers("nist")  # data_in_transit_encryption left "unknown"
        result = _run(checker.assess_target("https://example.com", "nist", answers))

        ctrl = next(c for c in result["controls"] if c["check"] == "data_in_transit_encryption")
        assert ctrl["status"] == "compliant"
        assert "auto_probe_mismatch" not in ctrl

    def test_no_target_url_skips_probe_entirely(self, monkeypatch):
        def fail_if_called(target_url):
            raise AssertionError("auto_probe_target should not be called without a target_url")

        monkeypatch.setattr(checker, "auto_probe_target", fail_if_called)

        answers = _all_unknown_answers("nist")
        answers["data_in_transit_encryption"] = "no"
        result = _run(checker.assess_target("", "nist", answers))

        ctrl = next(c for c in result["controls"] if c["check"] == "data_in_transit_encryption")
        assert ctrl["status"] == "non_compliant"  # self-report stands, untouched
        assert result["auto_probe_mismatches"] == []

    def test_probe_failure_falls_back_to_self_report(self, monkeypatch):
        async def fake_probe(target_url):
            return {"probe_error": "Connection refused"}  # no "https_in_use" key

        monkeypatch.setattr(checker, "auto_probe_target", fake_probe)

        answers = _all_unknown_answers("nist")
        answers["data_in_transit_encryption"] = "yes"
        result = _run(checker.assess_target("https://unreachable.example", "nist", answers))

        ctrl = next(c for c in result["controls"] if c["check"] == "data_in_transit_encryption")
        assert ctrl["status"] == "compliant"  # self-report used, no crash
        assert result["auto_probe_mismatches"] == []

    def test_framework_without_https_linked_check_skips_probe(self, monkeypatch):
        def fail_if_called(target_url):
            raise AssertionError("auto_probe_target should not be called for gdpr")

        monkeypatch.setattr(checker, "auto_probe_target", fail_if_called)

        answers = _all_unknown_answers("gdpr")
        result = _run(checker.assess_target("https://example.com", "gdpr", answers))
        assert result["framework"] == "gdpr"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
