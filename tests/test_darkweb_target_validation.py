"""
Tests for the /darkweb monitoring rework: target validation + normalization,
explicit per-provider query types, API error handling, field/password
sanitization, the severity model (incl. the Stealer Logs rule), dedupe,
cascade delete/hide, monitor status updates, server-side masking, the
DB migration, and the alert()-free UI.

No real network calls — every provider is mocked. Only project-approved test
targets are used (example.com / test@example.com); "tp-link" appears only as a
string fixture reproducing the original bug report, never queried.
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import modules.darkweb.monitor as mon
import modules.osint.darkweb_intelligence as dw
from modules.darkweb import leak_records as lr
from modules.darkweb.targets import validate_target, normalize_target, mask_value

TEST_DOMAIN = "example.com"
TEST_EMAIL = "test@example.com"


def _run(coro):
    return asyncio.run(coro)


# ── Fake aiohttp plumbing ────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, status=200, json_data=None):
        self.status = status
        self._json = {} if json_data is None else json_data

    async def json(self):
        return self._json

    def raise_for_status(self):
        if self.status >= 400:
            raise aiohttp.ClientResponseError(request_info=None, history=(), status=self.status)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    def __init__(self, responder):
        self._responder = responder

    def get(self, url, **kw):
        return self._responder("GET", url, kw)

    def post(self, url, **kw):
        return self._responder("POST", url, kw)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _capture(monkeypatch, module, response):
    calls = []

    def responder(method, url, kw):
        calls.append({"method": method, "url": url, **kw})
        return response

    monkeypatch.setattr(module.aiohttp, "ClientSession", lambda *a, **kw: _FakeSession(responder))
    return calls


# ═══ 1. Target validation + normalization ════════════════════════════════════

class TestTargetValidation:
    @pytest.mark.parametrize("raw,expected", [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("https://example.com/login?x=1", "example.com"),
        ("http://www.example.com:8443/", "example.com"),
        ("example.com.", "example.com"),
        ("sub.example.co.uk", "sub.example.co.uk"),
        ("tp-link.com", "tp-link.com"),
        ("xn--mgbh0fb.xn--kgbechtv", "xn--mgbh0fb.xn--kgbechtv"),
        ("exa mple.com", "example.com"),
    ])
    def test_valid_domains_are_normalized(self, raw, expected):
        v = validate_target(raw)
        assert v.ok, v.error_en
        assert v.target == expected
        assert v.target_type == "domain"

    @pytest.mark.parametrize("raw", [
        "tp-link", "localhost", "-bad.com", "bad-.com", "exa_mple.com", "example..com",
        "example.c", "example.123", "a" * 64 + ".com", "1.2.3.4",
    ])
    def test_invalid_domains_are_rejected(self, raw):
        v = validate_target(raw)
        assert not v.ok
        assert v.target_type == "domain"
        assert v.error_en and v.error_ar

    def test_tp_link_suggests_dot_com_bilingually(self):
        v = validate_target("tp-link")
        assert v.suggestion == "tp-link.com"
        assert "Did you mean tp-link.com?" in v.error_en
        assert "هل تقصد tp-link.com؟" in v.error_ar
        payload = v.error_payload()
        assert payload["suggestion"] == "tp-link.com"
        assert payload["message_ar"] and payload["message_en"]

    def test_underscore_suggests_hyphen(self):
        assert validate_target("tp_link.com").suggestion == "tp-link.com"

    def test_emails(self):
        assert validate_target("Test@Example.COM").target == TEST_EMAIL
        assert validate_target("Test@Example.COM").target_type == "email"
        bad = validate_target("user@tp-link")
        assert not bad.ok and bad.suggestion == "user@tp-link.com"
        assert not validate_target("@example.com").ok
        assert not validate_target("a..b@example.com").ok

    def test_username_only_when_explicit(self):
        assert validate_target("someuser").target_type == "domain"  # never inferred
        v = validate_target("SomeUser", "username")
        assert v.ok and v.target == "someuser" and v.target_type == "username"
        assert not validate_target("ab", "username").ok

    def test_unknown_type_and_empty(self):
        assert not validate_target("example.com", "auto").ok
        assert not validate_target("   ").ok
        assert normalize_target(None) == ""


# ═══ 2. Explicit query types + API error handling ════════════════════════════

class TestQueryTypes:
    def test_mapping_never_auto(self):
        for provider in ("leakcheck", "leaklookup", "breachdirectory"):
            for tt in ("domain", "email", "username"):
                assert lr.query_type_for(provider, tt) != "auto"
        assert lr.query_type_for("leakcheck", "domain") == "domain"
        assert lr.query_type_for("leakcheck", "email") == "email"
        assert lr.query_type_for("leakcheck", "username") == "username"
        assert lr.query_type_for("leaklookup", "email") == "email_address"
        assert lr.query_type_for("breachdirectory", "domain") == "domain"
        with pytest.raises(ValueError):
            lr.query_type_for("leakcheck", "auto")

    @pytest.mark.parametrize("tt,target", [("domain", TEST_DOMAIN), ("email", TEST_EMAIL), ("username", "someuser")])
    def test_leakcheck_v2_sends_explicit_type(self, monkeypatch, tt, target):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "fake-key")
        calls = _capture(monkeypatch, mon, _FakeResponse(200, {"success": True, "found": 0, "result": []}))
        result = _run(mon._query_leakcheck(target, tt))
        assert calls[0]["params"] == {"type": tt}
        assert result["query_type"] == tt and result["type_enforced"] is True

    def test_leakcheck_public_flags_type_not_enforced(self, monkeypatch):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "")
        calls = _capture(monkeypatch, mon, _FakeResponse(200, {"success": True, "found": 0}))
        result = _run(mon._query_leakcheck(TEST_DOMAIN, "domain"))
        assert "auto" not in str(calls[0].get("params"))
        assert result["type_enforced"] is False

    def test_breachdirectory_func_is_explicit(self, monkeypatch):
        monkeypatch.setattr(dw, "RAPIDAPI_KEY", "k")
        calls = _capture(monkeypatch, dw, _FakeResponse(200, {"result": []}))
        _run(dw._query_breachdirectory(TEST_DOMAIN, "domain"))
        _run(dw._query_breachdirectory(TEST_EMAIL, "email"))
        assert [c["params"]["func"] for c in calls] == ["domain", "sources"]

    def test_leaklookup_type_is_explicit(self, monkeypatch):
        monkeypatch.setattr(dw, "LEAKLOOKUP_API_KEY", "k")
        calls = _capture(monkeypatch, dw, _FakeResponse(200, {"error": "false", "message": {}}))
        _run(dw._query_leaklookup("someuser", "username"))
        _run(dw._query_leaklookup(TEST_DOMAIN, "domain"))
        assert [c["data"]["type"] for c in calls] == ["username", "domain"]

    @pytest.mark.parametrize("status,needle", [(400, "bad request"), (401, "API key"),
                                               (422, "could not be processed"), (429, "rate limit")])
    def test_leakcheck_http_errors_are_explicit(self, monkeypatch, status, needle):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "fake-key")
        _capture(monkeypatch, mon, _FakeResponse(status, {"success": False, "error": "x"}))
        result = _run(mon._query_leakcheck(TEST_DOMAIN, "domain"))
        assert needle in result["error"]
        assert f"HTTP {status}" in result["error"]
        assert result["error_ar"] and result["status"] == status
        assert result["found"] is False

    @pytest.mark.parametrize("status", [400, 401, 422, 429])
    def test_breachdirectory_and_leaklookup_http_errors(self, monkeypatch, status):
        monkeypatch.setattr(dw, "RAPIDAPI_KEY", "k")
        monkeypatch.setattr(dw, "LEAKLOOKUP_API_KEY", "k")
        _capture(monkeypatch, dw, _FakeResponse(status))
        bd = _run(dw._query_breachdirectory(TEST_DOMAIN, "domain"))
        ll = _run(dw._query_leaklookup(TEST_DOMAIN, "domain"))
        assert f"HTTP {status}" in bd["error"] and f"HTTP {status}" in ll["error"]

    def test_leaklookup_limit_message_maps_to_429(self, monkeypatch):
        monkeypatch.setattr(dw, "LEAKLOOKUP_API_KEY", "k")
        _capture(monkeypatch, dw, _FakeResponse(200, {"error": "true", "message": "REQUEST LIMIT REACHED"}))
        assert _run(dw._query_leaklookup(TEST_DOMAIN, "domain"))["status"] == 429

    def test_source_errors_surface_in_check_result(self, monkeypatch):
        async def gather(target, **kw):
            return {"breaches": [], "pastes": [], "github_exposures": [], "threat_actors": [],
                    "leaklookup": {"available": True, **lr.api_error("leaklookup", 429)}}

        async def lc(target, tt="domain"):
            return {"available": True, "found": False, "records": [], **lr.api_error("leakcheck", 401)}

        monkeypatch.setattr(dw, "gather_darkweb_intelligence", gather)
        monkeypatch.setattr(mon, "_query_leakcheck", lc)
        result = _run(mon.run_monitor_check(TEST_DOMAIN, "domain"))
        assert {e["source"] for e in result["source_errors"]} == {"leakcheck", "leaklookup"}
        assert mon.check_succeeded(result) is False


# ═══ 3. Stored fields — never password values ════════════════════════════════

class TestFieldSanitization:
    def test_leakcheck_v2_rows_keep_field_names_only(self, monkeypatch):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "fake-key")
        _capture(monkeypatch, mon, _FakeResponse(200, {"success": True, "found": 1, "result": [{
            "email": "alice@example.com", "password": "Hunter2!", "first_name": "Alice", "ip": "10.0.0.1",
            "source": {"name": "SomeBreach", "breach_date": "2024-03"},
            "fields": ["email", "password", "first_name", "ip"],
        }]}))
        result = _run(mon._query_leakcheck(TEST_DOMAIN, "domain"))
        assert "Hunter2!" not in str(result) and "10.0.0.1" not in str(result)
        rec = result["records"][0]
        assert rec["matched_field"] == "email"
        assert rec["source_name"] == "SomeBreach" and rec["leak_date"] == "2024-03"
        assert lr.canonical_fields(rec["leaked_fields"]) == ["email", "ip", "name", "password"]

    def test_hash_value_classified_as_hash(self):
        assert lr.password_field_kind("5f4dcc3b5aa765d61d8327deb882cf99") == "password_hash"
        assert lr.password_field_kind("$2b$12$abcdefghijklmnopqrstuv") == "password_hash"
        assert lr.password_field_kind("hunter2") == "password"
        assert lr.password_field_kind("") is None

    def test_event_stores_masked_value_and_no_raw(self):
        ev = lr.record_to_event({"provider": "leakcheck", "source_name": "X", "matched_field": "email",
                                 "matched_value": "alice@example.com", "leaked_fields": ["email"]},
                                TEST_DOMAIN, "domain")
        assert ev["detail"]["matched_value_masked"] == "a***@example.com"
        assert "alice@" not in str(ev["detail"]) and "alice@" not in ev["title"]

    def test_build_leak_events_drops_in_memory_raw_value(self):
        lc = {"found": True, "records": [{"provider": "leakcheck", "source_name": "X", "matched_field": "email",
                                          "matched_value": "alice@example.com", "leaked_fields": []}]}
        events = mon.build_leak_events({}, lc, TEST_DOMAIN, "domain")
        assert "alice@example.com" not in str(events)


# ═══ 4 + 11. Severity ════════════════════════════════════════════════════════

def _sev(fields=(), source="SomeBreach", mf="email", mv="bob@other.org", target=TEST_DOMAIN,
         tt="domain", date=None):
    return lr.compute_severity(source_name=source, leaked_fields=list(fields), matched_field=mf,
                               matched_value=mv, target=target, target_type=tt, leak_date=date)


OLD = (datetime.now(timezone.utc) - timedelta(days=365 * 7)).strftime("%Y-%m")
RECENT = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m")


class TestSeverity:
    def test_plaintext_password_is_critical(self):
        assert _sev(["email", "password"], date=RECENT) == "critical"

    def test_target_domain_email_with_hash_is_critical(self):
        assert _sev(["password_hash"], mv="alice@example.com") == "critical"
        assert _sev(["password_hash"], mv="alice@mail.example.com") == "critical"

    def test_hash_is_high(self):
        assert _sev(["email", "password_hash"], mv="bob@other.org", date=RECENT) == "high"
        assert _sev(["password_hash"], mf="email", mv=TEST_EMAIL, target=TEST_EMAIL, tt="email") == "high"

    def test_email_with_personal_data_is_medium(self):
        assert _sev(["email", "name", "phone"], date=RECENT) == "medium"
        assert _sev(["ip"], date=RECENT) == "medium"

    def test_email_or_username_only_is_low(self):
        assert _sev(["email"]) == "low"
        assert _sev(["username"], mf="username", mv="bob") == "low"
        assert _sev(["name"], mf="username", mv="bob") == "low"  # PII without email

    def test_older_than_five_years_is_low(self):
        assert _sev(["email", "name", "phone"], date=OLD) == "low"

    @pytest.mark.parametrize("kwargs", [
        {}, {"fields": ["email"]}, {"date": OLD}, {"fields": ["email"], "date": "2001"},
        {"mf": "username", "mv": "x"},
    ])
    def test_stealer_logs_always_critical(self, kwargs):
        assert _sev(source="Stealer Logs", **kwargs) == "critical"
        assert _sev(source="stealer logs (combolist)", **kwargs) == "critical"

    def test_leak_date_parsing(self):
        assert lr.parse_leak_date("2019-07").year == 2019
        assert lr.parse_leak_date("2019-07-15").day == 15
        assert lr.parse_leak_date("2019").year == 2019
        assert lr.parse_leak_date("") is None and lr.parse_leak_date("garbage") is None

    def test_tp_link_public_result_is_critical(self):
        """The real tp-link.com response shape from LeakCheck's public API."""
        lc = {"found": True, "records": [{"provider": "leakcheck", "source_name": "Stealer Logs", "leak_date": "",
                                          "matched_field": "domain", "matched_value": "tp-link.com",
                                          "leaked_fields": ["username", "password", "origin", "id"]}]}
        events = mon.build_leak_events({}, lc, "tp-link.com", "domain")
        assert len(events) == 1
        assert events[0]["severity"] == "critical"
        assert events[0]["leaked_fields"] == ["origin", "password", "username"]

    def test_severity_counts(self):
        assert lr.severity_counts(["critical", "low", "low", "bogus"]) == \
            {"critical": 1, "high": 0, "medium": 0, "low": 2}


# ═══ 5. Dedupe ═══════════════════════════════════════════════════════════════

class TestDedupe:
    def test_fingerprint_is_source_field_target(self):
        a = lr.record_fingerprint("Stealer Logs", "domain", "tp-link.com", "tp-link.com")
        assert a == lr.record_fingerprint("stealer logs ", "DOMAIN", "TP-Link.com", "tp-link.com")
        assert a != lr.record_fingerprint("Other", "domain", "tp-link.com", "tp-link.com")
        assert a != lr.record_fingerprint("Stealer Logs", "email", "tp-link.com", "tp-link.com")
        assert a != lr.record_fingerprint("Stealer Logs", "domain", "tp-link.com", "example.com")

    def test_same_breach_from_two_providers_merges(self):
        recs = {"provider": "leakcheck", "source_name": "BreachX", "matched_field": "email",
                "matched_value": "bob@other.org", "leaked_fields": ["email"]}
        lc = {"found": True, "records": [recs]}
        ll = {"records": [{**recs, "provider": "leaklookup", "leaked_fields": ["password_hash"]}]}
        events = mon.build_leak_events({"leaklookup": ll}, lc, TEST_DOMAIN, "domain")
        assert len(events) == 1
        assert events[0]["leaked_fields"] == ["email", "password_hash"]
        assert events[0]["severity"] == "high"
        assert events[0]["detail"]["providers"] == ["leakcheck", "leaklookup"]

    def test_merge_escalates_on_domain_email_with_hash(self):
        rec = {"provider": "leakcheck", "source_name": "B", "matched_field": "email",
               "matched_value": "alice@example.com", "leaked_fields": ["email"]}
        events = mon.build_leak_events(
            {"leaklookup": {"records": [{**rec, "provider": "leaklookup", "leaked_fields": ["password_hash"]}]}},
            {"found": True, "records": [rec]}, TEST_DOMAIN, "domain")
        assert events[0]["severity"] == "critical"

    def test_per_provider_cap(self):
        recs = [{"provider": "leakcheck", "source_name": f"S{i}", "matched_field": "domain",
                 "matched_value": TEST_DOMAIN, "leaked_fields": []} for i in range(250)]
        events = mon.build_leak_events({}, {"found": True, "records": recs}, TEST_DOMAIN, "domain")
        assert len(events) == mon.MAX_RECORDS_PER_PROVIDER


# ═══ 12. Masking ═════════════════════════════════════════════════════════════

class TestMasking:
    def test_mask_value(self):
        assert mask_value("alice@example.com") == "a***@example.com"
        assert mask_value("a***@example.com") == "a***@example.com"  # idempotent
        assert mask_value("johnny", "username") == "j***y"
        assert mask_value("ab", "username") == "a***"
        assert mask_value("tp-link.com", "domain") == "tp-link.com"
        assert mask_value("") == ""


# ═══ Router: 1, 5, 7, 8, 10, 12 end-to-end ═══════════════════════════════════

from web.database import Base, get_db  # noqa: E402
from web.models import User, DarkWebMonitor, DarkWebAlert  # noqa: E402
import web.app as app_module  # noqa: E402
import web.rate_limit as rate_limit  # noqa: E402
import web.routers.darkweb_monitor as monitor_router  # noqa: E402


@pytest.fixture
def env(monkeypatch):
    rate_limit._buckets.clear()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
                                 connect_args={"check_same_thread": False})
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with Session() as s:
            s.add(User(username="dwuser", email="dwuser@example.com", password_hash="x", role="analyst",
                       is_active=True, api_key_hash="unused-dwv", subscription_tier="enterprise"))
            await s.commit()

    _run(setup())

    async def get_db_override():
        async with Session() as s:
            yield s

    async def user_override():
        async with Session() as s:
            return (await s.execute(select(User).where(User.username == "dwuser"))).scalar_one()

    app_module.app.dependency_overrides[get_db] = get_db_override
    app_module.app.dependency_overrides[monitor_router._user] = user_override

    state = {"events": [], "source_errors": [], "leakcheck": {"error": None}, "calls": 0}

    async def fake_check(target, target_type=None, **kw):
        state["calls"] += 1
        return {"target": target, "target_type": target_type, "events": [dict(e) for e in state["events"]],
                "source_errors": state["source_errors"], "leakcheck": state["leakcheck"],
                "exposure": {}, "checked_at": "now"}

    monkeypatch.setattr(mon, "run_monitor_check", fake_check)
    client = TestClient(app_module.app)

    def query(sql, **params):
        async def go():
            async with engine.begin() as c:
                res = await c.execute(text(sql), params)
                return res.all() if res.returns_rows else []
        return _run(go())

    yield client, state, query
    app_module.app.dependency_overrides.clear()
    rate_limit._buckets.clear()
    _run(engine.dispose())


def _stealer_event(target="tp-link.com"):
    return lr.record_to_event({"provider": "leakcheck", "source_name": "Stealer Logs", "matched_field": "domain",
                               "matched_value": target, "leaked_fields": ["username", "password"]},
                              target, "domain")


def _email_event(email, fields, target="tp-link.com"):
    return lr.record_to_event({"provider": "leakcheck", "source_name": "BreachX", "matched_field": "email",
                               "matched_value": email, "leaked_fields": fields, "leak_date": RECENT},
                              target, "domain")


class TestRouter:
    def test_add_rejects_invalid_domain_with_suggestion(self, env):
        client, _, query = env
        r = client.post("/api/darkweb/monitor", json={"target": "tp-link"})
        assert r.status_code == 422
        body = r.json()
        assert body["suggestion"] == "tp-link.com"
        assert "هل تقصد" in body["message_ar"] and "Did you mean" in body["message_en"]
        assert query("SELECT count(*) FROM darkweb_monitors")[0][0] == 0

    def test_add_normalizes(self, env):
        client, _, _ = env
        r = client.post("/api/darkweb/monitor", json={"target": "  HTTPS://www.TP-Link.com/us/ "})
        assert r.status_code == 200
        m = r.json()["monitor"]
        assert m["target"] == "tp-link.com" and m["target_type"] == "domain"
        assert m["validation_status"] == "valid"
        dup = client.post("/api/darkweb/monitor", json={"target": "tp-link.com"})
        assert dup.status_code == 409 and dup.json()["message_ar"]

    def test_check_updates_last_checked_and_dedupes(self, env):
        client, state, query = env
        mid = client.post("/api/darkweb/monitor", json={"target": "tp-link.com"}).json()["monitor"]["id"]
        state["events"] = [_stealer_event()]
        r1 = client.post(f"/api/darkweb/monitor/{mid}/check")
        assert r1.status_code == 200
        body = r1.json()
        assert body["monitor"]["last_checked_at"].endswith("Z")
        assert body["new_alerts_count"] == 1
        assert body["new_alerts"][0]["severity"] == "critical"
        r2 = client.post(f"/api/darkweb/monitor/{mid}/check")
        assert r2.json()["new_alerts_count"] == 0
        assert query("SELECT count(*) FROM darkweb_alerts")[0][0] == 1

    def test_failed_check_keeps_last_checked_and_reports(self, env):
        client, state, query = env
        mid = client.post("/api/darkweb/monitor", json={"target": "example.com"}).json()["monitor"]["id"]
        state["leakcheck"] = {"error": "leakcheck: rate limit exceeded (HTTP 429)"}
        state["source_errors"] = [{"source": "leakcheck", "error": "leakcheck: rate limit exceeded (HTTP 429)",
                                   "error_ar": "leakcheck: تم تجاوز حد الطلبات", "status": 429}]
        r = client.post(f"/api/darkweb/monitor/{mid}/check")
        assert r.status_code == 502
        body = r.json()
        assert body["monitor"]["last_checked_at"] is None
        assert "429" in body["monitor"]["last_check_error"]
        assert body["message_ar"] and body["message_en"]

        state["leakcheck"], state["source_errors"] = {"error": None}, []
        ok = client.post(f"/api/darkweb/monitor/{mid}/check").json()
        assert ok["monitor"]["last_checked_at"] and ok["monitor"]["last_check_error"] is None

    def test_recent_alerts_sorted_filtered_summarized(self, env):
        client, state, _ = env
        mid = client.post("/api/darkweb/monitor", json={"target": "tp-link.com"}).json()["monitor"]["id"]
        state["events"] = [
            _email_event("low@other.org", ["email"]),
            _email_event("med@other.org", ["email", "phone"]),
            _email_event("hi@other.org", ["password_hash"]),
            _stealer_event(),
        ]
        client.post(f"/api/darkweb/monitor/{mid}/check")
        data = client.get("/api/darkweb/monitor/alerts/recent").json()
        assert [a["severity"] for a in data["alerts"]] == ["critical", "high", "medium", "low"]
        assert data["summary"] == {"critical": 1, "high": 1, "medium": 1, "low": 1, "total": 4}
        only = client.get("/api/darkweb/monitor/alerts/recent?severity=high").json()
        assert [a["severity"] for a in only["alerts"]] == ["high"]
        assert only["summary"]["total"] == 4
        assert client.get("/api/darkweb/monitor/alerts/recent?severity=bogus").status_code == 400

    def test_details_are_masked_server_side(self, env):
        client, state, _ = env
        mid = client.post("/api/darkweb/monitor", json={"target": "tp-link.com"}).json()["monitor"]["id"]
        state["events"] = [_email_event("alice@tp-link.com", ["email", "password_hash", "name"])]
        alert = client.post(f"/api/darkweb/monitor/{mid}/check").json()["new_alerts"][0]
        d = alert["details"]
        assert d["matched_field"] == "email"
        assert d["matched_value_masked"] == "a***@tp-link.com"
        assert d["source_name"] == "BreachX" and d["leak_date"] == RECENT
        assert d["leaked_fields"] == ["email", "name", "password_hash"]
        assert alert["severity"] == "critical"  # on-domain email + hash
        one = client.get(f"/api/darkweb/alerts/{alert['id']}")
        assert one.status_code == 200
        raw = one.text + client.get("/api/darkweb/monitor/alerts/recent").text
        assert "alice@" not in raw
        assert "detail" not in one.json()  # legacy raw blob never sent

    def test_details_mask_legacy_rows(self, env):
        client, _, query = env
        mid = client.post("/api/darkweb/monitor", json={"target": "tp-link.com"}).json()["monitor"]["id"]
        # A legacy row with a raw, un-masked value in `detail`:
        query("INSERT INTO darkweb_alerts (monitor_id, fingerprint, source, severity, title, detail, hidden) "
              "VALUES (:m, 'legacy', 'leakcheck', 'high', 't', :d, 0)",
              m=mid, d='{"matched_field": "email", "matched_value_masked": "alice@tp-link.com", '
                       '"password": "Hunter2!", "source_name": "X"}')
        body = client.get("/api/darkweb/monitor/alerts/recent").text
        assert "alice@" not in body and "Hunter2!" not in body

    def test_delete_cascades_alerts(self, env):
        client, state, query = env
        mid = client.post("/api/darkweb/monitor", json={"target": "tp-link.com"}).json()["monitor"]["id"]
        state["events"] = [_stealer_event()]
        client.post(f"/api/darkweb/monitor/{mid}/check")
        assert client.delete(f"/api/darkweb/monitor/{mid}").status_code == 200
        assert query("SELECT count(*) FROM darkweb_alerts")[0][0] == 0
        assert client.get("/api/darkweb/monitor/alerts/recent").json()["summary"]["total"] == 0

    def test_invalid_monitor_hidden_blocked_then_corrected(self, env):
        client, state, query = env
        mid = client.post("/api/darkweb/monitor", json={"target": "tp-link.com"}).json()["monitor"]["id"]
        state["events"] = [_stealer_event()]
        client.post(f"/api/darkweb/monitor/{mid}/check")
        # Simulate a legacy bad row: flag invalid via the shared helper.
        query("UPDATE darkweb_monitors SET target='tp-link' WHERE id=:id", id=mid)

        async def flag():
            async for db in app_module.app.dependency_overrides[get_db]():
                m = await db.get(DarkWebMonitor, mid)
                n = await monitor_router.mark_monitor_invalid(m, "no TLD", db)
                await db.commit()
                return n
        assert _run(flag()) == 1
        assert client.get("/api/darkweb/monitor/alerts/recent").json()["alerts"] == []

        calls_before = state["calls"]
        blocked = client.post(f"/api/darkweb/monitor/{mid}/check")
        assert blocked.status_code == 409
        assert blocked.json()["message_ar"] and blocked.json()["monitor"]["validation_status"] == "invalid"
        assert state["calls"] == calls_before  # provider never queried

        bad_fix = client.patch(f"/api/darkweb/monitor/{mid}", json={"target": "tp-link"})
        assert bad_fix.status_code == 422
        fixed = client.patch(f"/api/darkweb/monitor/{mid}", json={"target": "tp-link.com"})
        assert fixed.status_code == 200
        m = fixed.json()["monitor"]
        assert m["validation_status"] == "valid" and m["target"] == "tp-link.com"
        assert m["last_checked_at"] is None
        assert query("SELECT count(*) FROM darkweb_alerts")[0][0] == 0  # old-query alerts dropped
        assert client.post(f"/api/darkweb/monitor/{mid}/check").status_code == 200


# ═══ 8 + 10. Migration ═══════════════════════════════════════════════════════

def test_migration_flags_invalid_upgrades_legacy_and_cleans(monkeypatch):
    import web.migrate_darkweb_target_validation as mig
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
                                 connect_args={"check_same_thread": False})
    monkeypatch.setattr(mig, "engine", engine)

    legacy_detail = '{"source_name": "Stealer Logs", "fields": ["username", "password", "origin", "id"]}'

    async def go():
        # Pre-migration schema: the old darkweb tables, without the new columns.
        async with engine.begin() as c:
            await c.execute(text("CREATE TABLE darkweb_monitors (id INTEGER PRIMARY KEY, user_id INTEGER, "
                                 "target VARCHAR(255), target_type VARCHAR(10), label VARCHAR(200), "
                                 "is_active BOOLEAN, created_at DATETIME, last_checked_at DATETIME)"))
            await c.execute(text("CREATE TABLE darkweb_alerts (id INTEGER PRIMARY KEY, monitor_id INTEGER, "
                                 "fingerprint VARCHAR(64), source VARCHAR(50), severity VARCHAR(20), "
                                 "title VARCHAR(300), detail JSON, discovered_at DATETIME, acknowledged BOOLEAN)"))
            await c.execute(text("INSERT INTO darkweb_monitors (id, user_id, target, target_type) VALUES "
                                 "(1, 1, 'tp-link', 'domain'), (2, 1, 'tp-link.com', 'domain'), "
                                 "(3, 1, 'HTTPS://Example.com/x', 'domain')"))
            for i in range(26):
                await c.execute(text("INSERT INTO darkweb_alerts (monitor_id, fingerprint, source, severity, title) "
                                     "VALUES (1, :fp, 'leakcheck', 'high', 'x')"), {"fp": f"old{i}"})
            await c.execute(text("INSERT INTO darkweb_alerts (monitor_id, fingerprint, source, severity, title, detail) "
                                 "VALUES (2, 'legacyfp', 'leakcheck', 'high', 'LeakCheck match: Stealer Logs', :d)"),
                            {"d": legacy_detail})
            await c.execute(text("INSERT INTO darkweb_alerts (monitor_id, fingerprint, source, severity, title) "
                                 "VALUES (99, 'orphan', 'leakcheck', 'high', 'orphan')"))
            await c.execute(text("INSERT INTO darkweb_alerts (monitor_id, fingerprint, source, severity, title) "
                                 "VALUES (3, 'dup', 'paste', 'medium', 'a'), (3, 'dup', 'paste', 'medium', 'b')"))

        report = await mig.migrate()
        async with engine.connect() as c:
            mons = {r[0]: r for r in (await c.execute(text(
                "SELECT id, target, validation_status, validation_error FROM darkweb_monitors"))).all()}
            hidden = (await c.execute(text("SELECT count(*) FROM darkweb_alerts WHERE monitor_id=1 AND hidden"))).scalar()
            legacy = (await c.execute(text(
                "SELECT fingerprint, severity, matched_field, title FROM darkweb_alerts WHERE monitor_id=2"))).one()
            orphans = (await c.execute(text("SELECT count(*) FROM darkweb_alerts WHERE monitor_id=99"))).scalar()
            dups = (await c.execute(text("SELECT count(*) FROM darkweb_alerts WHERE monitor_id=3"))).scalar()
        report2 = await mig.migrate()  # idempotent
        await engine.dispose()
        return report, report2, mons, hidden, legacy, orphans, dups

    report, report2, mons, hidden, legacy, orphans, dups = _run(go())
    assert mons[1][2] == "invalid" and "TLD" in mons[1][3]
    assert report["invalid"][0]["suggestion"] == "tp-link.com"
    assert hidden == 26 and report["hidden_alerts"] == 26
    assert mons[2][2] == "valid"
    assert mons[3][1] == "example.com"  # normalized in place
    assert legacy[1] == "critical"      # Stealer Logs rule applied to legacy row
    assert legacy[0] == lr.record_fingerprint("Stealer Logs", "domain", "tp-link.com", "tp-link.com")
    assert legacy[2] == "domain" and legacy[3] == "Stealer Logs — tp-link.com"
    assert orphans == 0 and report["orphans_deleted"] == 1
    assert dups == 1 and report["duplicates_deleted"] == 1
    assert report2["columns_added"] == [] and report2["upgraded_alerts"] == 0 and report2["hidden_alerts"] == 0


# ═══ 6. UI: no alert() ═══════════════════════════════════════════════════════

def test_darkweb_template_has_no_alert_or_confirm_calls():
    import re
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "web", "templates", "darkweb.html")
    src = open(path, encoding="utf-8").read()
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("//"))
    assert not re.search(r"(?<![\w.])alert\(", code)
    assert not re.search(r"(?<![\w.])confirm\(", code)
    assert "dwToast" in src and "dw-summary" in src and "toggleAlertDetails" in src
