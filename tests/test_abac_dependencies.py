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
from web.scan_authz import VerifiedScope

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


def attrs(role="analyst", ip="203.0.113.9", when=IN_HOURS, severity=None, operation="read",
          checks=None, authorized=None):
    return {"role": role, "ip_address": ip, "request_time": when,
            "operation": operation, "resource_severity": severity,
            "scan_checks": checks, "target_authorized": authorized}


def sqli(role="viewer", ip="10.1.2.3", checks=("sqli",), authorized=True):
    return attrs(role=role, ip=ip, operation="action", checks=list(checks), authorized=authorized)


# ── Config file ──────────────────────────────────────────────────────────────

def test_shipped_config_loads_with_expected_rules(policy):
    ids = {r.id for r in policy.rules}
    assert ids == {
        "cve_read",
        "cve_action",
        "cve_admin",
        "viewer-sqli-scan-external-deny",
        "sqli_scan_viewer",
        "ngfw-rules-outside-business-hours-deny",
        "ngfw-rules-business-hours-allow",
    }
    for rule in policy.rules:
        assert rule.effect in ("allow", "deny") and rule.roles and rule.resource


def test_default_rules_path_is_the_shipped_file():
    assert os.path.samefile(abac.DEFAULT_RULES_PATH, RULES_FILE)
    assert len(abac.get_policy().rules) == 7


# ── Rule 1: analyst -> CVE Pipeline (cve_read / cve_action) ──────────────────

def test_analyst_cve_pipeline_allowed_for_critical(policy):
    d = evaluate(policy, "cve_pipeline", attrs(role="analyst", severity="Critical", operation="action"))
    assert d.allowed and d.rule_id == "cve_action"


def test_analyst_cve_pipeline_critical_match_is_case_insensitive(policy):
    # scanners store Finding.severity as "Critical"; match regardless of case
    assert evaluate(policy, "cve_pipeline", attrs(role="analyst", severity="critical", operation="action")).allowed


@pytest.mark.parametrize("severity", ["High", "Medium", "Low", "Info", "Critical-ish"])
def test_analyst_cve_pipeline_denied_for_non_critical(policy, severity):
    d = evaluate(policy, "cve_pipeline", attrs(role="analyst", severity=severity, operation="action"))
    assert not d.allowed


def test_analyst_cve_pipeline_denied_when_severity_missing(policy):
    d = evaluate(policy, "cve_pipeline", attrs(role="analyst", severity=None, operation="action"))
    assert not d.allowed and d.rule_id == "cve_action" and d.reason == "missing attribute: resource_severity"


def test_viewer_cve_pipeline_default_denied_even_if_critical(policy):
    for op in ("read", "action"):
        d = evaluate(policy, "cve_pipeline", attrs(role="viewer", severity="Critical", operation=op))
        assert not d.allowed and d.rule_id is None


def test_analyst_cve_read_needs_no_severity(policy):
    d = evaluate(policy, "cve_pipeline", attrs(role="analyst", severity=None, operation="read"))
    assert d.allowed and d.rule_id == "cve_read"


@pytest.mark.parametrize("op", ["read", "action"])
def test_admin_cve_pipeline_allowed_without_severity(policy, op):
    d = evaluate(policy, "cve_pipeline", attrs(role="admin", severity=None, operation=op))
    assert d.allowed and d.rule_id == "cve_admin"


def test_missing_attribute_never_lets_an_allow_rule_match():
    data = {"timezone": "UTC", "rules": [
        {"id": "a", "roles": ["*"], "resource": "r", "effect": "allow",
         "conditions": [{"attr": "resource_severity", "op": "eq", "value": "Critical"}]}]}
    d = evaluate(policy_from_dict(data), "r", attrs(severity=None))
    assert d == Decision(False, "a", "missing attribute: resource_severity")


# ── Rule 2: viewer -> SQLi scan (POST /api/scan) internal + authorized ───────

@pytest.mark.parametrize("ip", ["10.1.2.3", "172.16.5.4", "192.168.1.10", "127.0.0.1", "::1"])
def test_viewer_sqli_allowed_from_internal_network(policy, ip):
    d = evaluate(policy, "api_scan", sqli(ip=ip))
    assert d.allowed and d.rule_id == "sqli_scan_viewer"


@pytest.mark.parametrize("ip", ["8.8.8.8", "203.0.113.9", "172.32.0.1", "2001:db8::1"])
def test_viewer_sqli_denied_from_external_network(policy, ip):
    d = evaluate(policy, "api_scan", sqli(ip=ip))
    assert not d.allowed and d.rule_id == "viewer-sqli-scan-external-deny"


def test_viewer_sqli_denied_when_ip_missing(policy):
    d = evaluate(policy, "api_scan", sqli(ip=None))
    assert not d.allowed and d.reason == "missing attribute: ip_address"


def test_viewer_sqli_denied_when_ip_unparseable(policy):
    d = evaluate(policy, "api_scan", sqli(ip="not-an-ip"))
    assert not d.allowed and d.reason == "invalid attribute value"


def test_viewer_sqli_denied_for_unauthorized_target(policy):
    d = evaluate(policy, "api_scan", sqli(authorized=False))
    assert not d.allowed and d.rule_id is None


def test_viewer_sqli_denied_when_authorization_unknown(policy):
    d = evaluate(policy, "api_scan", sqli(authorized=None))
    assert not d.allowed and d.reason == "missing attribute: target_authorized"


@pytest.mark.parametrize("checks", [["sqli", "xss"], ["xss"], ["nmap"], list(abac.scan_authz.SCAN_STEP_ORDER)])
def test_viewer_scan_denied_beyond_sqli_class(policy, checks):
    assert not evaluate(policy, "api_scan", sqli(checks=checks)).allowed


@pytest.mark.parametrize("role", ["analyst", "admin"])
def test_api_scan_has_no_rule_for_analyst_or_admin(policy, role):
    """Config defines no api_scan rule for these roles, so ABAC default-denies them."""
    d = evaluate(policy, "api_scan", sqli(role=role))
    assert d == Decision(False, None, "no matching rule (default deny)")


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


# Week of 2026-10-11: Sun 11, Mon 12, Tue 13, Wed 14, Thu 15, Fri 16, Sat 17
BGW = ZoneInfo("Asia/Baghdad")   # UTC+3, no DST


@pytest.mark.parametrize("local, allowed", [
    (datetime(2026, 10, 11, 9, 0, tzinfo=BGW), True),     # Sunday 09:00, start inclusive
    (datetime(2026, 10, 11, 16, 59, tzinfo=BGW), True),   # Sunday 16:59
    (datetime(2026, 10, 11, 17, 0, tzinfo=BGW), False),   # Sunday 17:00, end exclusive
    (datetime(2026, 10, 11, 8, 59, tzinfo=BGW), False),   # Sunday 08:59
    (datetime(2026, 10, 17, 10, 0, tzinfo=BGW), False),   # Saturday
    (datetime(2026, 10, 15, 10, 0, tzinfo=BGW), True),    # Thursday
    (datetime(2026, 10, 16, 10, 0, tzinfo=BGW), False),   # Friday
])
def test_ngfw_business_hours_sun_to_thu_in_abac_timezone(monkeypatch, local, allowed):
    """Clock is injected in UTC; the window is evaluated in ABAC_TIMEZONE."""
    monkeypatch.setenv("ABAC_TIMEZONE", "Asia/Baghdad")
    utc_clock = local.astimezone(UTC)
    c = _app("ngfw_rules", "analyst", clock=lambda: utc_clock)
    assert c.get("/res").status_code == (200 if allowed else 403)


def test_ngfw_business_hours_shipped_window(policy):
    hours = next(r for r in policy.rules if r.id == "ngfw-rules-business-hours-allow").conditions[0].value
    assert hours["days"] == {"sun", "mon", "tue", "wed", "thu"}
    assert (hours["start"].isoformat(), hours["end"].isoformat()) == ("09:00:00", "17:00:00")


def test_ngfw_business_days_and_hours_come_from_config():
    with open(RULES_FILE, encoding="utf-8") as fh:
        data = json.load(fh)
    data["params"]["business_hours"] = {"start": "08:00", "end": "12:00", "days": ["fri"]}
    p = policy_from_dict(data, timezone="UTC")
    assert evaluate(p, "ngfw_rules", attrs(when=datetime(2026, 10, 16, 8, 0, tzinfo=UTC))).allowed
    assert not evaluate(p, "ngfw_rules", attrs(when=datetime(2026, 10, 16, 12, 0, tzinfo=UTC))).allowed
    assert not evaluate(p, "ngfw_rules", attrs(when=datetime(2026, 10, 11, 10, 0, tzinfo=UTC))).allowed


@pytest.mark.parametrize("tz", ["Mars/Olympus", "Not/AZone", "../../etc/passwd", "UTC+3"])
def test_ngfw_unknown_timezone_denies(monkeypatch, tz):
    monkeypatch.setenv("ABAC_TIMEZONE", tz)
    with pytest.raises(PolicyError):
        load_policy(RULES_FILE)
    c = _app("ngfw_rules", "admin", clock=lambda: datetime(2026, 10, 11, 10, 0, tzinfo=UTC))
    assert c.get("/res").status_code == 403


def test_abac_timezone_env_overrides_config_timezone(monkeypatch):
    assert load_policy(RULES_FILE).timezone == ZoneInfo("UTC")
    monkeypatch.setenv("ABAC_TIMEZONE", "Asia/Baghdad")
    assert load_policy(RULES_FILE).timezone == BGW


# ── Default deny and missing attributes ──────────────────────────────────────

def test_default_deny_for_unknown_resource(policy):
    d = evaluate(policy, "some_unlisted_resource", attrs(role="admin"))
    assert d == Decision(False, None, "no matching rule (default deny)")


def test_default_deny_for_role_without_rule(policy):
    assert not evaluate(policy, "api_scan", sqli(role="analyst", ip="10.0.0.1")).allowed


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
            "conditions": [{"attr": "resource_severity", "op": "eq", "value": "Critical"}]}
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
    app.dependency_overrides[abac.get_db] = lambda: None   # no database in these tests
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


def test_depends_ignores_client_supplied_severity():
    """The caller must not be able to claim a severity: it comes from the record."""
    c = _app("cve_pipeline", "analyst", clock=lambda: IN_HOURS)
    assert c.post("/res", json={"target_severity": "Critical", "x": 7}).status_code == 403
    assert c.post("/res?resource_severity=Critical", json={"resource_severity": "Critical"}).status_code == 403
    assert c.get("/res?target_severity=High").status_code == 200   # read needs no severity


# ── CVE pipeline with the severity resolver (fake findings, no DB) ───────────

FAKE_FINDINGS = {11: "Critical", 12: "High"}   # finding_id -> Finding.severity, all owned by user 1


def _fake_finding_lookup(calls=None):
    async def lookup(db, finding_id, user):
        if calls is not None:
            calls.append(finding_id)
        return FAKE_FINDINGS.get(finding_id) if user.id == 1 else None
    return lookup


def _cve_app(role, finding_lookup=None, uid=1):
    async def provider(request, user, db):
        sev = await abac.resolve_resource_severity(request, user, db,
                                                   finding_lookup=finding_lookup or _fake_finding_lookup())
        return {"resource_severity": sev}

    app = FastAPI()
    dep = require_abac("cve_pipeline", policy_provider=lambda: load_policy(RULES_FILE),
                       clock=lambda: IN_HOURS, providers=(provider,))

    # Same paths as web/routers/cve_submission.py (prefix /api/cve)
    @app.get("/api/cve/search")
    async def search(user=Depends(dep)):
        return {"ok": True}

    @app.post("/api/cve/draft")
    async def draft(request: Request, user=Depends(dep)):
        return {"ok": True, "finding_id": (await request.json()).get("finding_id")}

    @app.post("/api/cve/drafts/{draft_id}/run")   # hypothetical write route on a CVE record
    async def run_on_draft(draft_id: int, user=Depends(dep)):
        return {"ok": True}

    app.dependency_overrides[abac.abac_user] = lambda: _User(role, uid)
    app.dependency_overrides[abac.get_db] = lambda: None
    return TestClient(app, client=("203.0.113.9", 50000))


def test_cve_analyst_get_without_target_allowed():
    assert _cve_app("analyst").get("/api/cve/search?keyword=openssl").status_code == 200


def test_cve_analyst_run_on_critical_target_allowed():
    r = _cve_app("analyst").post("/api/cve/draft", json={"finding_id": 11})
    assert r.status_code == 200 and r.json() == {"ok": True, "finding_id": 11}


def test_cve_analyst_run_on_high_target_denied():
    assert _cve_app("analyst").post("/api/cve/draft", json={"finding_id": 12}).status_code == 403


def test_cve_analyst_run_without_target_denied():
    c = _cve_app("analyst")
    assert c.post("/api/cve/draft", json={"title": "t", "description": "d"}).status_code == 403
    assert c.post("/api/cve/draft", json={"title": "t", "target_severity": "Critical"}).status_code == 403


def test_cve_analyst_run_on_cve_record_denied_without_cvss_mapping():
    # CVE-only request: no verified CVSS -> severity mapping, so no severity, so deny
    assert _cve_app("analyst").post("/api/cve/drafts/5/run").status_code == 403


@pytest.mark.parametrize("finding_id", ["11", 0, -11, True, "11abc", "1e3", [11], None])
def test_cve_malformed_finding_id_denied_without_lookup(finding_id):
    calls = []
    c = _cve_app("analyst", finding_lookup=_fake_finding_lookup(calls))
    body = {"finding_id": finding_id}
    status = c.post("/api/cve/draft", json=body).status_code
    if finding_id == "11":   # a numeric string is a valid id, same as int()
        assert status == 200 and calls == [11]
    else:
        assert status == 403 and calls == []


def test_cve_finding_of_another_user_denied():
    assert _cve_app("analyst", uid=2).post("/api/cve/draft", json={"finding_id": 11}).status_code == 403


def test_cve_finding_id_query_param_is_a_target_too():
    assert _cve_app("analyst").post("/api/cve/draft?finding_id=11", json={}).status_code == 200


def test_cve_lookup_error_fails_closed():
    async def broken(db, finding_id, user):
        raise RuntimeError("db down")
    assert _cve_app("analyst", finding_lookup=broken).post("/api/cve/draft", json={"finding_id": 11}).status_code == 403


def test_cve_viewer_denied():
    c = _cve_app("viewer")
    assert c.get("/api/cve/search").status_code == 403
    assert c.post("/api/cve/draft", json={"finding_id": 11}).status_code == 403


def test_cve_admin_allowed_per_role_logic():
    c = _cve_app("admin")
    assert c.get("/api/cve/search").status_code == 200
    assert c.post("/api/cve/draft", json={"finding_id": 12}).status_code == 200
    assert c.post("/api/cve/draft", json={}).status_code == 200


def test_provider_cannot_override_request_attributes():
    async def sneaky(request, user, db):
        return {"role": "admin"}

    app = FastAPI()
    dep = require_abac("cve_pipeline", policy_provider=lambda: load_policy(RULES_FILE),
                       clock=lambda: IN_HOURS, providers=(sneaky,))

    @app.get("/api/cve/search")
    async def search(user=Depends(dep)):
        return {"ok": True}

    app.dependency_overrides[abac.abac_user] = lambda: _User("viewer")
    app.dependency_overrides[abac.get_db] = lambda: None
    assert TestClient(app).get("/api/cve/search").status_code == 403


def test_cve_severity_provider_uses_default_finding_lookup(monkeypatch):
    import asyncio

    async def fake_lookup(db, finding_id, user):
        return "critical"

    monkeypatch.setattr(abac, "finding_severity_for_user", fake_lookup)
    scope = {"type": "http", "method": "POST", "path": "/api/cve/draft", "headers": [],
             "query_string": b"finding_id=11", "path_params": {}}
    assert asyncio.run(abac.cve_severity_provider(Request(scope), _User("analyst"), None)) == {
        "resource_severity": "critical"}


def test_finding_severity_lookup_uses_owned_finding(monkeypatch):
    import asyncio
    import web.routers.cve_submission as cve_router

    seen = {}

    async def fake_get_finding_for_user(db, finding_id, user_id):
        seen["args"] = (db, finding_id, user_id)
        return type("F", (), {"severity": "critical"})() if finding_id == 11 else None

    monkeypatch.setattr(cve_router, "get_finding_for_user", fake_get_finding_for_user)
    db = object()
    assert asyncio.run(abac.finding_severity_for_user(db, 11, _User("analyst", 7))) == "critical"
    assert seen["args"] == (db, 11, 7)
    assert asyncio.run(abac.finding_severity_for_user(db, 99, _User("analyst", 7))) is None


def test_depends_uses_trusted_client_ip_not_forwarded_header():
    body = {"target": "mine.example.com", "scan_types": ["sqli"]}
    internal = _scan_app("viewer", client_ip="10.0.0.5")
    assert internal.post("/api/scan", json=body).status_code == 200
    external = _scan_app("viewer", client_ip="8.8.8.8")
    # a spoofed X-Forwarded-For must not turn an external caller into an internal one
    assert external.post("/api/scan", json=body, headers={"X-Forwarded-For": "10.0.0.5"}).status_code == 403


# ── POST /api/scan with the scan_authz provider (fake scopes, no DB/DNS) ─────

async def _fake_scopes(db, user):
    return [VerifiedScope("mine.example.com", abac.scan_authz.VERIFY_METHOD_DNS_TXT)]


async def _no_scopes(db, user):
    return []


def _scan_app(role, client_ip="10.0.0.5", scopes_loader=_fake_scopes):
    async def provider(request, user, db):
        return await abac.scan_authz_provider(request, user, db, scopes_loader=scopes_loader)

    app = FastAPI()
    dep = require_abac("api_scan", policy_provider=lambda: load_policy(RULES_FILE),
                       clock=lambda: IN_HOURS, providers=(provider,))

    @app.post("/api/scan")   # same path as web/app.py:run_scan
    async def run_scan(request: Request, user=Depends(dep)):
        return {"ok": True, "target": (await request.json())["target"]}

    app.dependency_overrides[abac.abac_user] = lambda: _User(role)
    app.dependency_overrides[abac.get_db] = lambda: None
    return TestClient(app, client=(client_ip, 50000))


AUTHORIZED = {"target": "https://api.mine.example.com/login", "scan_types": ["sqli"]}
UNAUTHORIZED = {"target": "https://someone-else.example.org", "scan_types": ["sqli"]}


def test_scan_viewer_internal_authorized_allowed():
    r = _scan_app("viewer").post("/api/scan", json=AUTHORIZED)
    assert r.status_code == 200 and r.json()["target"] == AUTHORIZED["target"]


def test_scan_viewer_internal_unauthorized_denied():
    assert _scan_app("viewer").post("/api/scan", json=UNAUTHORIZED).status_code == 403


def test_scan_viewer_external_authorized_denied():
    assert _scan_app("viewer", client_ip="203.0.113.9").post("/api/scan", json=AUTHORIZED).status_code == 403


def test_scan_viewer_training_target_uses_scan_authz_allowlist():
    # demo.testfire.net permits sqli per scan_authz.TRAINING_TARGETS; scanme.nmap.org does not
    c = _scan_app("viewer", scopes_loader=_no_scopes)
    assert c.post("/api/scan", json={"target": "demo.testfire.net", "scan_types": ["sqli"]}).status_code == 200
    assert c.post("/api/scan", json={"target": "scanme.nmap.org", "scan_types": ["sqli"]}).status_code == 403


@pytest.mark.parametrize("body", [
    {"target": "mine.example.com", "scan_types": []},             # empty = every module
    {"target": "mine.example.com", "scan_types": ["sqli", "xss"]},
    {"target": "mine.example.com", "scan_types": "sqli"},
    {"target": "mine.example.com", "scan_types": [1]},
    {"target": "", "scan_types": ["sqli"]},
    {"target": 5, "scan_types": ["sqli"]},
    {"scan_types": ["sqli"]},
    ["not", "an", "object"],
])
def test_scan_viewer_malformed_or_broad_request_denied(body):
    assert _scan_app("viewer").post("/api/scan", json=body).status_code == 403


@pytest.mark.parametrize("role", ["analyst", "admin"])
def test_scan_analyst_and_admin_follow_config_default_deny(role):
    # No api_scan rule names these roles in config/abac_rules.json, so ABAC denies.
    # Live, run_scan's require_analyst_or_admin is what admits them; ABAC is not wired.
    assert _scan_app(role).post("/api/scan", json=AUTHORIZED).status_code == 403


def test_scan_authorization_exception_fails_closed(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("authz crashed")

    monkeypatch.setattr(abac.scan_authz, "decide", boom)
    assert _scan_app("viewer").post("/api/scan", json=AUTHORIZED).status_code == 403


def test_scan_scopes_loader_exception_fails_closed():
    async def boom(db, user):
        raise RuntimeError("db down")

    assert _scan_app("viewer", scopes_loader=boom).post("/api/scan", json=AUTHORIZED).status_code == 403


def test_scan_provider_calls_scan_authz_decide(monkeypatch):
    seen = []
    real = abac.scan_authz.decide

    def spy(target, scan_types, scopes=()):
        seen.append((target, list(scan_types), list(scopes)))
        return real(target, scan_types, scopes)

    monkeypatch.setattr(abac.scan_authz, "decide", spy)
    assert _scan_app("viewer").post("/api/scan", json=AUTHORIZED).status_code == 200
    assert seen == [(AUTHORIZED["target"], ["sqli"],
                     [VerifiedScope("mine.example.com", abac.scan_authz.VERIFY_METHOD_DNS_TXT)])]


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


def test_scan_provider_defaults_to_load_verified_scopes(monkeypatch):
    import web.domain_verification as dv

    calls = []

    async def fake_load(db, user):
        calls.append(user.id)
        return await _fake_scopes(db, user)

    monkeypatch.setattr(dv, "load_verified_scopes", fake_load)
    c = _scan_app("viewer", scopes_loader=None)
    assert c.post("/api/scan", json=AUTHORIZED).status_code == 200 and calls == [1]
