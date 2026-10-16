"""
Scan-authorization coverage for the CLI (cli/commands.py).

The CLI has no user accounts, so ownership verification isn't possible there
(that lives in the hosted web service). Active checks therefore run only
against the hardcoded public training targets in web/scan_authz.TRAINING_TARGETS;
passive checks run against anything. These tests mirror the four web-gate
scenarios: an unverified target is refused for active checks but allowed for
passive ones, a training target is accepted within its permitted checks, and a
denied check never reaches the scanner.

No network: every scanner cmd_* would call is monkeypatched to a recorder.
"""

import os
import sys

os.environ.setdefault("GROQ_ENV", "test")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import cli.commands as c


@pytest.fixture
def scanners(monkeypatch):
    """Replace every scanner the CLI commands call with a recorder so nothing
    touches the network and we can see exactly what was (not) run."""
    calls = {}

    def rec(name, ret):
        def _fn(*args, **kwargs):
            calls.setdefault(name, []).append((args, kwargs))
            return ret
        return _fn

    monkeypatch.setattr(c, "scan_xss", rec("xss", []))
    monkeypatch.setattr(c, "scan_sqli", rec("sqli", []))
    monkeypatch.setattr(c, "scan_ssrf", rec("ssrf", []))
    monkeypatch.setattr(c, "scan_lfi", rec("lfi", []))
    monkeypatch.setattr(c, "scan_open_redirect", rec("redirect", []))
    monkeypatch.setattr(c, "crawl", rec("crawl", type("R", (), {"urls": [], "forms": []})()))
    monkeypatch.setattr(c, "nmap_scan", rec("nmap", {"ports": []}))
    monkeypatch.setattr(c, "enumerate_subdomains", rec("subdomain", {"subdomains": [], "unconfirmed": []}))
    monkeypatch.setattr(c, "dns_lookup", rec("dns", {}))
    return calls


# ── active checks refused on an unverified (non-training) target ──────────────

def test_vuln_scan_refused_on_unverified_target(scanners):
    c.cmd_vuln_scan("example.com", scan_types=["xss", "sqli"])
    assert "xss" not in scanners and "sqli" not in scanners
    assert "crawl" not in scanners  # the crawl itself is active, so also skipped


def test_nmap_refused_on_unverified_target(scanners):
    out = c.cmd_nmap("example.com")
    assert "nmap" not in scanners
    assert out["nmap"]["error"] == "not authorized for this target"


def test_subdomain_refused_on_unverified_target(scanners):
    c.cmd_subdomain("example.com")
    assert "subdomain" not in scanners


# ── passive checks allowed on the same unverified target ──────────────────────

def test_passive_dns_runs_on_unverified_target(scanners):
    c.cmd_dns("example.com")
    assert "dns" in scanners  # passive, never gated


# ── training targets accepted within their permitted checks ───────────────────

def test_vuln_scan_allowed_on_training_target(scanners):
    c.cmd_vuln_scan("http://demo.testfire.net", scan_types=["sqli"])
    assert "sqli" in scanners


def test_nmap_allowed_on_training_target(scanners):
    c.cmd_nmap("scanme.nmap.org")
    assert "nmap" in scanners


def test_vuln_scan_training_target_runs_only_permitted_checks(scanners):
    # public-firing-range permits xss/redirect only -- sqli must be dropped.
    c.cmd_vuln_scan("https://public-firing-range.appspot.com", scan_types=["xss", "sqli"])
    assert "xss" in scanners
    assert "sqli" not in scanners
