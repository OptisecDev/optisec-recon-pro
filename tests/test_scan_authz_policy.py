"""
Unit coverage for web/scan_authz.py -- the pure scan-authorization policy
(passive checks on any target; active checks only for user-verified domains
or the hardcoded training allowlist). No DB, no network.

The classification tests read web/app.py's _run_scan_task source so that a
new scan step added there without being classified in scan_authz fails here
instead of silently running unauthorized.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from web.scan_authz import (
    ACTIVE_CHECKS, ALL_CHECKS, PASSIVE_CHECKS, SCAN_STEP_ORDER, TRAINING_TARGETS,
    VERIFY_METHOD_DNS_TXT, VERIFY_METHOD_HTTP_FILE, VerifiedScope,
    decide, expand_checks, host_in_verified_scope, normalize_host,
)

APP_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "app.py")

DNS = VerifiedScope("example.com", VERIFY_METHOD_DNS_TXT)
FILE = VerifiedScope("app.example.org", VERIFY_METHOD_HTTP_FILE)


# ── Classification ───────────────────────────────────────────────────────────

def _run_scan_task_step_names() -> set:
    src = open(APP_PY, encoding="utf-8").read()
    body = src[src.index("async def _run_scan_task("):]
    body = body[:body.index("\n@app.")]
    return set(re.findall(r'"([a-z_]+)" in scan_types', body))


def test_passive_and_active_sets_are_disjoint():
    assert not (PASSIVE_CHECKS & ACTIVE_CHECKS)


def test_every_run_scan_task_step_is_classified():
    steps = _run_scan_task_step_names()
    assert steps, "regex found no steps -- _run_scan_task layout changed"
    assert steps <= ALL_CHECKS, f"unclassified scan steps: {steps - ALL_CHECKS}"


def test_step_order_matches_classification_exactly():
    assert set(SCAN_STEP_ORDER) == ALL_CHECKS
    assert len(SCAN_STEP_ORDER) == len(ALL_CHECKS)
    assert set(SCAN_STEP_ORDER) == _run_scan_task_step_names()


@pytest.mark.parametrize("check", ["ssl", "headers", "dns", "whois", "osint"])
def test_low_touch_checks_are_passive(check):
    assert check in PASSIVE_CHECKS


@pytest.mark.parametrize("check", ["subdomain", "nmap", "ports", "xss", "sqli", "ssrf", "lfi", "redirect"])
def test_probe_checks_are_active(check):
    assert check in ACTIVE_CHECKS


def test_training_targets_only_grant_active_checks():
    for host, checks in TRAINING_TARGETS.items():
        assert checks <= ACTIVE_CHECKS, host
        assert host == normalize_host(host), host


def test_scanme_is_port_scanning_only():
    assert TRAINING_TARGETS["scanme.nmap.org"] == {"nmap", "ports"}


# ── expand_checks ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("empty", [None, [], ()])
def test_empty_scan_types_expands_to_everything(empty):
    assert expand_checks(empty) == list(SCAN_STEP_ORDER)


def test_expand_checks_dedupes_preserving_order():
    assert expand_checks(["dns", "xss", "dns"]) == ["dns", "xss"]


# ── normalize_host ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("EXAMPLE.com.", "example.com"),
    ("https://Example.com:8443/path?q=1", "example.com"),
    ("http://user:pw@example.com/", "example.com"),
    ("  example.com  ", "example.com"),
    ("http://[2001:db8::1]:80/", "2001:db8::1"),
    ("93.184.216.34", "93.184.216.34"),
    ("bücher.example", "xn--bcher-kva.example"),
    ("", ""),
    ("http://", ""),
])
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


# ── host_in_verified_scope ───────────────────────────────────────────────────

def test_dns_txt_covers_domain_and_subdomains():
    assert host_in_verified_scope("example.com", [DNS]) == DNS
    assert host_in_verified_scope("a.b.example.com", [DNS]) == DNS


def test_dns_txt_does_not_match_suffix_lookalike():
    assert host_in_verified_scope("evilexample.com", [DNS]) is None
    assert host_in_verified_scope("example.com.evil.net", [DNS]) is None


def test_http_file_covers_exact_host_only():
    assert host_in_verified_scope("app.example.org", [FILE]) == FILE
    assert host_in_verified_scope("x.app.example.org", [FILE]) is None
    assert host_in_verified_scope("example.org", [FILE]) is None


def test_ip_never_in_verified_scope():
    assert host_in_verified_scope("93.184.216.34", [VerifiedScope("93.184.216.34", VERIFY_METHOD_HTTP_FILE)]) is None


def test_unknown_method_grants_nothing():
    assert host_in_verified_scope("example.com", [VerifiedScope("example.com", "email")]) is None


# ── decide ───────────────────────────────────────────────────────────────────

def test_passive_allowed_on_any_target():
    d = decide("https://unverified.test", sorted(PASSIVE_CHECKS))
    assert d.ok
    assert d.allowed == PASSIVE_CHECKS
    assert d.basis == "passive_only"


@pytest.mark.parametrize("check", sorted(ACTIVE_CHECKS))
def test_each_active_check_denied_on_unverified_target(check):
    d = decide("unverified.test", [check])
    assert not d.ok
    assert d.denied == {check}
    assert "verif" in d.reason.lower()


def test_run_all_on_unverified_target_denies_every_active_check():
    d = decide("unverified.test", [])
    assert d.denied == ACTIVE_CHECKS
    assert d.allowed == PASSIVE_CHECKS


def test_run_all_on_verified_subdomain_allowed():
    d = decide("https://shop.example.com/login", None, [DNS])
    assert d.ok
    assert d.allowed == ALL_CHECKS
    assert d.basis == "verified:dns_txt:example.com"


def test_file_verification_does_not_extend_to_subdomain():
    d = decide("x.app.example.org", ["xss"], [FILE])
    assert d.denied == {"xss"}


def test_verification_for_other_domain_does_not_help():
    d = decide("other.test", ["sqli"], [DNS, FILE])
    assert d.denied == {"sqli"}


def test_ip_target_active_denied_even_with_matching_record():
    d = decide("http://93.184.216.34/", ["ports", "dns"], [VerifiedScope("93.184.216.34", VERIFY_METHOD_DNS_TXT)])
    assert d.denied == {"ports"}
    assert d.allowed == {"dns"}


def test_training_target_grants_only_its_own_checks():
    d = decide("http://scanme.nmap.org", ["nmap", "ports", "xss", "dns"])
    assert d.allowed == {"nmap", "ports", "dns"}
    assert d.denied == {"xss"}
    assert d.basis == "training:scanme.nmap.org"
    assert "only permits" in d.reason


def test_training_target_web_checks_allowed():
    d = decide("http://testasp.vulnweb.com/", ["xss", "sqli", "headers"])
    assert d.ok
    assert d.basis == "training:testasp.vulnweb.com"


def test_training_target_is_exact_host_not_wildcard():
    assert not decide("evil.scanme.nmap.org", ["nmap"]).ok
    assert not decide("vulnweb.com", ["xss"]).ok


def test_verification_takes_precedence_over_training_limits():
    d = decide("scanme.nmap.org", ["xss"], [VerifiedScope("nmap.org", VERIFY_METHOD_DNS_TXT)])
    assert d.ok
    assert d.basis == "verified:dns_txt:nmap.org"


def test_unknown_check_is_denied_even_when_verified():
    d = decide("example.com", ["xss", "rce_spray"], [DNS])
    assert d.denied == {"rce_spray"}
    assert "rce_spray" in d.reason


def test_invalid_target_denies_everything():
    d = decide("", ["dns"])
    assert not d.ok
    assert d.allowed == set()
    assert d.reason == "Invalid target"
