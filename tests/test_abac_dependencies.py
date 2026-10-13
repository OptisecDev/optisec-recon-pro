"""
Tests for auth/dependencies.py: config-driven ABAC beside web/auth.py's role checks.

Each roadmap rule gets an allow case and a deny case, plus default deny,
missing attributes, config validation, timezone handling, and the FastAPI
Depends() integration. The integration tests run on a throwaway FastAPI app,
with the user dependency overridden, so no database is touched.
"""

import json
import os
import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

import auth.dependencies as abac
from auth.dependencies import Decision, PolicyError, evaluate, load_policy, policy_from_dict, require_abac

RULES_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "abac_rules.json")

UTC = timezone.utc
IN_HOURS = datetime(2026, 10, 13, 10, 30, tzinfo=UTC)      # Tue 10:30 UTC
OUT_HOURS = datetime(2026, 10, 13, 22, 0, tzinfo=UTC)      # Tue 22:00 UTC


@pytest.fixture(autouse=True)
def _no_env_overrides(monkeypatch):
    monkeypatch.delenv("ABAC_TIMEZONE", raising=False)
    monkeypatch.delenv("ABAC_RULES_PATH", raising=False)
    abac.reset_policy_cache()
    yield
    abac.reset_policy_cache()


@pytest.fixture
def policy():
    return load_policy(RULES_FILE)


def attrs(role="analyst", ip="203.0.113.9", when=IN_HOURS, severity=None):
    return {"role": role, "ip_address": ip, "request_time": when, "target_severity": severity}


# ── Config file ──────────────────────────────────────────────────────────────

def test_shipped_config_loads_with_expected_rules(policy):
    ids = {r.id for r in policy.rules}
    assert ids == {
        "analyst-cve-pipeline-critical-only",
        "viewer-sqli-scan-external-deny",
        "viewer-sqli-scan-internal-allow",
        "ngfw-rules-outside-business-hours-deny",
        "ngfw-rules-business-hours-allow",
    }
    for rule in policy.rules:
        assert rule.effect in ("allow", "deny") and rule.roles and rule.resource


def test_default_rules_path_is_the_shipped_file():
    assert os.path.samefile(abac.DEFAULT_RULES_PATH, RULES_FILE)
    assert len(abac.get_policy().rules) == 5


# ── Rule 1: analyst -> CVE Pipeline only for Critical ────────────────────────

def test_analyst_cve_pipeline_allowed_for_critical(policy):
    d = evaluate(policy, "cve_pipeline", attrs(role="analyst", severity="Critical"))
    assert d.allowed and d.rule_id == "analyst-cve-pipeline-critical-only"


def test_analyst_cve_pipeline_critical_match_is_case_insensitive(policy):
    assert evaluate(policy, "cve_pipeline", attrs(role="analyst", severity="critical")).allowed


@pytest.mark.parametrize("severity", ["High", "Medium", "Low", "Info", "Critical-ish"])
def test_analyst_cve_pipeline_denied_for_non_critical(policy, severity):
    d = evaluate(policy, "cve_pipeline", attrs(role="analyst", severity=severity))
    assert not d.allowed


def test_analyst_cve_pipeline_denied_when_severity_missing(policy):
    d = evaluate(policy, "cve_pipeline", attrs(role="analyst", severity=None))
    assert not d.allowed and d.reason == "missing attribute: target_severity"


def test_viewer_cve_pipeline_default_denied_even_if_critical(policy):
    d = evaluate(policy, "cve_pipeline", attrs(role="viewer", severity="Critical"))
    assert not d.allowed and d.rule_id is None


# ── Rule 2: viewer -> SQLi scan only from internal network ───────────────────

@pytest.mark.parametrize("ip", ["10.1.2.3", "172.16.5.4", "192.168.1.10", "127.0.0.1", "::1"])
def test_viewer_sqli_allowed_from_internal_network(policy, ip):
    d = evaluate(policy, "sqli_scan", attrs(role="viewer", ip=ip))
    assert d.allowed and d.rule_id == "viewer-sqli-scan-internal-allow"


@pytest.mark.parametrize("ip", ["8.8.8.8", "203.0.113.9", "172.32.0.1", "2001:db8::1"])
def test_viewer_sqli_denied_from_external_network(policy, ip):
    d = evaluate(policy, "sqli_scan", attrs(role="viewer", ip=ip))
    assert not d.allowed and d.rule_id == "viewer-sqli-scan-external-deny"


def test_viewer_sqli_denied_when_ip_missing(policy):
    d = evaluate(policy, "sqli_scan", attrs(role="viewer", ip=None))
    assert not d.allowed and d.reason == "missing attribute: ip_address"


def test_viewer_sqli_denied_when_ip_unparseable(policy):
    d = evaluate(policy, "sqli_scan", attrs(role="viewer", ip="not-an-ip"))
    assert not d.allowed and d.reason == "invalid attribute value"


# ── Rule 3: any role -> NGFW Rules only during business hours ────────────────

@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_ngfw_rules_allowed_within_business_hours(policy, role):
    d = evaluate(policy, "ngfw_rules", attrs(role=role, when=IN_HOURS))
    assert d.allowed and d.rule_id == "ngfw-rules-business-hours-allow"


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_ngfw_rules_denied_outside_business_hours(policy, role):
    d = evaluate(policy, "ngfw_rules", attrs(role=role, when=OUT_HOURS))
    assert not d.allowed and d.rule_id == "ngfw-rules-outside-business-hours-deny"


def test_ngfw_rules_boundaries(policy):
    at_start = datetime(2026, 10, 13, 9, 0, tzinfo=UTC)
    at_end = datetime(2026, 10, 13, 17, 0, tzinfo=UTC)
    assert evaluate(policy, "ngfw_rules", attrs(when=at_start)).allowed
    assert not evaluate(policy, "ngfw_rules", attrs(when=at_end)).allowed   # end is exclusive


def test_ngfw_rules_denied_when_time_missing(policy):
    d = evaluate(policy, "ngfw_rules", attrs(when=None))
    assert not d.allowed and d.reason == "missing attribute: request_time"


def test_business_hours_use_configured_timezone_not_utc(monkeypatch):
    with open(RULES_FILE, encoding="utf-8") as fh:
        data = json.load(fh)
    # 07:00 UTC == 10:00 in Asia/Baghdad (UTC+3)
    early_utc = datetime(2026, 10, 13, 7, 0, tzinfo=UTC)

    utc_policy = policy_from_dict(data)
    assert not evaluate(utc_policy, "ngfw_rules", attrs(when=early_utc.astimezone(utc_policy.timezone))).allowed

    monkeypatch.setenv("ABAC_TIMEZONE", "Asia/Baghdad")
    bgw_policy = policy_from_dict(data)
    assert bgw_policy.timezone == ZoneInfo("Asia/Baghdad")
    assert evaluate(bgw_policy, "ngfw_rules", attrs(when=early_utc.astimezone(bgw_policy.timezone))).allowed


def test_business_days_restriction_and_overnight_window():
    data = {
        "timezone": "UTC",
        "params": {"night": {"start": "22:00", "end": "06:00", "days": ["mon"]}},
        "rules": [{"id": "night", "roles": ["*"], "resource": "r", "effect": "allow",
                   "conditions": [{"attr": "request_time", "op": "within_hours", "value": "$night"}]}],
    }
    p = policy_from_dict(data)
    mon_23 = datetime(2026, 10, 12, 23, 0, tzinfo=UTC)   # Monday
    tue_03 = datetime(2026, 10, 13, 3, 0, tzinfo=UTC)    # belongs to Monday's night
    tue_23 = datetime(2026, 10, 13, 23, 0, tzinfo=UTC)   # Tuesday night, not allowed
    mon_12 = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
    assert evaluate(p, "r", attrs(when=mon_23)).allowed
    assert evaluate(p, "r", attrs(when=tue_03)).allowed
    assert not evaluate(p, "r", attrs(when=tue_23)).allowed
    assert not evaluate(p, "r", attrs(when=mon_12)).allowed


# ── Default deny and missing attributes ──────────────────────────────────────

def test_default_deny_for_unknown_resource(policy):
    d = evaluate(policy, "some_unlisted_resource", attrs(role="admin"))
    assert d == Decision(False, None, "no matching rule (default deny)")


def test_default_deny_for_role_without_rule(policy):
    assert not evaluate(policy, "sqli_scan", attrs(role="analyst", ip="10.0.0.1")).allowed


def test_default_deny_with_empty_rule_set():
    p = policy_from_dict({"timezone": "UTC", "rules": []})
    assert not evaluate(p, "ngfw_rules", attrs(role="admin")).allowed


@pytest.mark.parametrize("role", [None, "", "   "])
def test_missing_role_is_denied(policy, role):
    d = evaluate(policy, "ngfw_rules", attrs(role=role))
    assert not d.allowed and d.reason == "missing attribute: role"


def test_missing_attribute_denies_even_when_another_rule_would_allow():
    data = {
        "timezone": "UTC",
        "rules": [
            {"id": "open", "roles": ["*"], "resource": "r", "effect": "allow", "conditions": []},
            {"id": "needs-ip", "roles": ["*"], "resource": "r", "effect": "deny",
             "conditions": [{"attr": "ip_address", "op": "not_in_networks", "value": ["10.0.0.0/8"]}]},
        ],
    }
    p = policy_from_dict(data)
    assert evaluate(p, "r", attrs(ip="10.0.0.1")).allowed
    d = evaluate(p, "r", attrs(ip=None))
    assert not d.allowed and d.reason == "missing attribute: ip_address"


def test_deny_overrides_allow():
    data = {
        "timezone": "UTC",
        "rules": [
            {"id": "a", "roles": ["*"], "resource": "r", "effect": "allow", "conditions": []},
            {"id": "d", "roles": ["viewer"], "resource": "r", "effect": "deny", "conditions": []},
        ],
    }
    p = policy_from_dict(data)
    assert evaluate(p, "r", attrs(role="admin")).allowed
    assert not evaluate(p, "r", attrs(role="viewer")).allowed


# ── Config validation fails closed ───────────────────────────────────────────

def _one_rule(**overrides):
    rule = {"id": "x", "roles": ["admin"], "resource": "r", "effect": "allow",
            "conditions": [{"attr": "target_severity", "op": "eq", "value": "Critical"}]}
    rule.update(overrides)
    return {"timezone": "UTC", "rules": [rule]}


@pytest.mark.parametrize("data", [
    _one_rule(effect="permit"),
    _one_rule(roles=[]),
    _one_rule(roles="admin"),
    _one_rule(resource=""),
    _one_rule(id=""),
    _one_rule(conditions=[{"attr": "nope", "op": "eq", "value": 1}]),
    _one_rule(conditions=[{"attr": "role", "op": "regex", "value": ".*"}]),
    _one_rule(conditions=[{"attr": "role", "op": "eq"}]),
    _one_rule(conditions=[{"attr": "role", "op": "in_networks", "value": ["10.0.0.0/8"]}]),
    _one_rule(conditions=[{"attr": "ip_address", "op": "in_networks", "value": ["999.0.0.0/8"]}]),
    _one_rule(conditions=[{"attr": "ip_address", "op": "in_networks", "value": "$undefined"}]),
    _one_rule(conditions=[{"attr": "request_time", "op": "within_hours", "value": {"start": "9"}}]),
    _one_rule(conditions=[{"attr": "request_time", "op": "within_hours",
                           "value": {"start": "09:00", "end": "17:00", "days": ["funday"]}}]),
    {"timezone": "UTC", "rules": [_one_rule()["rules"][0], _one_rule()["rules"][0]]},  # duplicate id
    {"timezone": "Mars/Olympus", "rules": []},
    {"rules": []},
    {"timezone": "UTC"},
])
def test_invalid_policy_rejected(data):
    with pytest.raises(PolicyError):
        policy_from_dict(data)


def test_unreadable_rules_file_rejected(tmp_path):
    bad = tmp_path / "rules.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(bad)
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "missing.json")


def test_rules_path_env_override(tmp_path, monkeypatch):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"timezone": "UTC", "rules": []}), encoding="utf-8")
    monkeypatch.setenv("ABAC_RULES_PATH", str(path))
    assert load_policy().rules == ()


# ── FastAPI Depends() integration ────────────────────────────────────────────

class _User:
    def __init__(self, role, uid=1):
        self.role = role
        self.id = uid


def _app(resource, role, clock, client_ip="203.0.113.9", policy_provider=None):
    app = FastAPI()
    dep = require_abac(resource, policy_provider=policy_provider or (lambda: load_policy(RULES_FILE)), clock=clock)

    @app.get("/res")
    async def get_res(user=Depends(dep)):
        return {"ok": True, "role": user.role}

    @app.post("/res")
    async def post_res(request: Request, user=Depends(dep)):
        body = await request.json()   # body still readable after the dependency read it
        return {"ok": True, "echo": body.get("x")}

    app.dependency_overrides[abac.abac_user] = lambda: _User(role)
    return TestClient(app, client=(client_ip, 50000))


def test_depends_allows_ngfw_rules_in_hours():
    c = _app("ngfw_rules", "viewer", clock=lambda: IN_HOURS)
    r = c.get("/res")
    assert r.status_code == 200 and r.json() == {"ok": True, "role": "viewer"}


def test_depends_denies_ngfw_rules_out_of_hours():
    c = _app("ngfw_rules", "admin", clock=lambda: OUT_HOURS)
    r = c.get("/res")
    assert r.status_code == 403
    assert r.json()["detail"] == "Access denied by context policy"


def test_depends_reads_target_severity_from_query_and_json_body():
    c = _app("cve_pipeline", "analyst", clock=lambda: IN_HOURS)
    assert c.get("/res?target_severity=Critical").status_code == 200
    assert c.get("/res?target_severity=High").status_code == 403
    assert c.get("/res").status_code == 403
    r = c.post("/res", json={"target_severity": "Critical", "x": 7})
    assert r.status_code == 200 and r.json() == {"ok": True, "echo": 7}
    assert c.post("/res", json={"target_severity": "Low"}).status_code == 403


def test_depends_uses_trusted_client_ip_not_forwarded_header():
    internal = _app("sqli_scan", "viewer", clock=lambda: IN_HOURS, client_ip="10.0.0.5")
    assert internal.get("/res").status_code == 200
    external = _app("sqli_scan", "viewer", clock=lambda: IN_HOURS, client_ip="8.8.8.8")
    # a spoofed X-Forwarded-For must not turn an external caller into an internal one
    assert external.get("/res", headers={"X-Forwarded-For": "10.0.0.5"}).status_code == 403


def test_depends_fails_closed_on_policy_error():
    def broken():
        raise PolicyError("bad config")

    c = _app("ngfw_rules", "admin", clock=lambda: IN_HOURS, policy_provider=broken)
    assert c.get("/res").status_code == 403


def test_depends_fails_closed_on_naive_clock():
    c = _app("ngfw_rules", "admin", clock=lambda: datetime(2026, 10, 13, 10, 0))
    assert c.get("/res").status_code == 403


def test_existing_role_checks_untouched():
    """ABAC sits beside web.auth's role helpers; they must still exist and still reject."""
    from fastapi import HTTPException
    from web.auth import require_admin, require_analyst_or_admin

    with pytest.raises(HTTPException):
        require_admin(_User("analyst"))
    with pytest.raises(HTTPException):
        require_analyst_or_admin(_User("viewer"))
    assert require_analyst_or_admin(_User("analyst")) is None
