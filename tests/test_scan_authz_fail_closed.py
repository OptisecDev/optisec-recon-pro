"""
End-to-end coverage for the strict ("Option B", fail-closed) scan
authorization policy:

  * passive checks (ssl, headers, dns, whois) run against any target;
  * active checks (xss, sqli, lfi, ssrf, port scans, ...) run only on a
    domain the user verified with a DNS TXT record carrying their token,
    or on a hardcoded training target;
  * every active scan re-queries that TXT record, and anything other than
    a matching answer -- no record, wrong token, timeout, resolver crash --
    refuses the scan with a 403;
  * nothing in the request or the environment can switch this off.

Unlike tests/test_scan_authz_gates.py, the real check_dns_txt() runs here;
only the lowest DNS seam (_resolve_txt) is faked, so the token comparison
and the error handling are what's under test. Scanners are never run.
"""

import asyncio
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.exception
import dns.resolver
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import modules.scan_scope as scan_scope_module
import web.app as app_module
import web.domain_verification as dv
import web.rate_limit as rate_limit
from web.auth import create_access_token
from web.database import Base, get_db
from web.models import DomainVerification, Scan, User

TOKEN = "test-token-not-a-secret"


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    rate_limit._buckets.clear()
    monkeypatch.setattr(scan_scope_module, "_resolve", lambda host: {"93.184.216.34"})
    yield
    rate_limit._buckets.clear()


@pytest.fixture
def dns_txt(monkeypatch):
    """Controls what the live TXT lookup returns. Default: no DNS at all --
    any lookup is a test failure unless the test configures one."""
    state = {"values": None, "exc": AssertionError("unexpected DNS lookup"), "calls": []}

    async def fake(name):
        state["calls"].append(name)
        if state["exc"] is not None:
            raise state["exc"]
        return state["values"]
    monkeypatch.setattr(dv, "_resolve_txt", fake)

    def publish(values=None, exc=None):
        state["values"], state["exc"] = values, exc
    state["publish"] = publish
    return state


@pytest.fixture
def env():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    sf = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    _run(setup())

    async def override_get_db():
        async with sf() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app_module.app), sf
    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


@pytest.fixture
def launched(monkeypatch):
    calls = []

    async def fake_task(*args, **kwargs):
        calls.append(kwargs)
    monkeypatch.setattr(app_module, "_run_scan_task", fake_task)
    return calls


@pytest.fixture
def nmap_calls(monkeypatch):
    calls = []

    def fake(target):
        calls.append(target)
        return {"ports": []}
    monkeypatch.setattr(app_module, "nmap_scan", fake)
    return calls


def _user(sf, username="alice", records=()):
    """`records` is a list of (domain, status) dns_txt verifications."""
    async def go():
        async with sf() as db:
            u = User(
                username=username, email=f"{username}@example.com", password_hash="x",
                role="analyst", subscription_tier="enterprise", is_active=True,
            )
            db.add(u)
            await db.flush()
            for domain, status in records:
                db.add(DomainVerification(
                    user_id=u.id, domain=domain, method="dns_txt", token=TOKEN,
                    status=status, verified_at=datetime.utcnow(), last_checked_at=datetime.utcnow(),
                ))
            await db.commit()
            return u.id
    uid = _run(go())
    return {"access_token": create_access_token(uid, "analyst")}


def _status(sf, domain):
    async def go():
        async with sf() as db:
            return (await db.execute(
                select(DomainVerification.status).where(DomainVerification.domain == domain)
            )).scalar_one()
    return _run(go())


def _scan_count(sf):
    async def go():
        async with sf() as db:
            return len((await db.execute(select(Scan))).scalars().all())
    return _run(go())


def _scan(c, cookies, target, checks, **extra):
    return c.post("/api/scan", json={"target": target, "scan_types": checks, **extra}, cookies=cookies)


# ── Unverified targets ───────────────────────────────────────────────────────

@pytest.mark.parametrize("check", ["xss", "sqli", "lfi", "ssrf", "ports", "nmap"])
def test_active_check_on_unverified_target_refused(env, launched, dns_txt, check):
    c, sf = env
    r = _scan(c, _user(sf), "unverified.test", [check])
    assert r.status_code == 403
    body = r.json()
    assert body["denied_checks"] == [check]
    assert "DNS TXT" in body["error"]
    assert launched == [] and _scan_count(sf) == 0
    assert dns_txt["calls"] == []  # no record to look up -> nothing to grant


def test_port_scan_endpoint_on_unverified_target_refused(env, nmap_calls, dns_txt):
    c, sf = env
    r = c.post("/api/scan/ports", json={"target": "unverified.test"}, cookies=_user(sf))
    assert r.status_code == 403
    assert nmap_calls == []


# ── Passive checks ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("target", ["unverified.test", "https://any-site.example.net/path", "93.184.216.34"])
def test_passive_checks_on_any_target_allowed(env, launched, dns_txt, target):
    c, sf = env
    r = _scan(c, _user(sf), target, ["ssl", "headers", "dns", "whois"])
    assert r.status_code == 200, r.text
    assert launched[0]["authorized_checks"] == {"ssl", "headers", "dns", "whois"}
    assert dns_txt["calls"] == []  # passive work never needs a verification lookup


# ── DNS TXT verification ─────────────────────────────────────────────────────

def test_matching_txt_record_allows_active_checks(env, launched, dns_txt):
    c, sf = env
    cookies = _user(sf, records=[("example.com", "verified")])
    dns_txt["publish"](values=["v=spf1 -all", f"optisec-verify={TOKEN}"])
    r = _scan(c, cookies, "https://shop.example.com", ["xss", "sqli", "lfi", "ssrf", "ports"])
    assert r.status_code == 200, r.text
    assert launched[0]["authorized_checks"] == {"xss", "sqli", "lfi", "ssrf", "ports"}
    assert dns_txt["calls"] == ["_optisec-verify.example.com"]


def test_wrong_txt_token_refused_and_verification_revoked(env, launched, dns_txt):
    c, sf = env
    cookies = _user(sf, records=[("example.com", "verified")])
    dns_txt["publish"](values=["optisec-verify=someone-elses-token"])
    r = _scan(c, cookies, "example.com", ["sqli"])
    assert r.status_code == 403
    assert launched == []
    assert _status(sf, "example.com") == "revoked"


def test_txt_for_another_domain_does_not_cover_target(env, launched, dns_txt):
    c, sf = env
    cookies = _user(sf, records=[("example.com", "verified")])
    dns_txt["publish"](values=[f"optisec-verify={TOKEN}"])
    r = _scan(c, cookies, "example.com.evil.net", ["xss"])
    assert r.status_code == 403
    assert dns_txt["calls"] == []


def test_another_users_txt_verification_does_not_count(env, launched, dns_txt):
    c, sf = env
    _user(sf, "owner", records=[("example.com", "verified")])
    dns_txt["publish"](values=[f"optisec-verify={TOKEN}"])
    r = _scan(c, _user(sf, "intruder"), "example.com", ["xss"])
    assert r.status_code == 403


@pytest.mark.parametrize("status", ["pending", "failed", "revoked"])
def test_unconfirmed_verification_refused_without_lookup(env, launched, dns_txt, status):
    c, sf = env
    cookies = _user(sf, records=[("example.com", status)])
    r = _scan(c, cookies, "example.com", ["xss"])
    assert r.status_code == 403
    assert dns_txt["calls"] == []


def test_full_flow_create_publish_check_scan(env, launched, dns_txt):
    """Token is generated server-side, shown only to its owner, and the scan
    is allowed only once the TXT record carrying it is published."""
    c, sf = env
    alice = _user(sf, "alice")
    bob = _user(sf, "bob")
    auth = {"Authorization": f"Bearer {alice['access_token']}"}

    created = c.post("/api/domains/verify", json={"domain": "example.com", "method": "dns_txt"}, headers=auth)
    assert created.status_code == 201, created.text
    token = created.json()["token"]
    assert len(token) >= 40

    others_view = c.get("/api/domains", headers={"Authorization": f"Bearer {bob['access_token']}"}).json()
    assert others_view["verifications"] == []
    assert token not in str(others_view)

    assert _scan(c, alice, "example.com", ["xss"]).status_code == 403  # still pending

    dns_txt["publish"](values=[f"optisec-verify={token}"])
    checked = c.post(f"/api/domains/{created.json()['id']}/check", headers=auth)
    assert checked.json()["status"] == "verified"
    assert _scan(c, alice, "example.com", ["xss"]).status_code == 200

    dns_txt["publish"](exc=dns.resolver.NXDOMAIN())  # record removed
    assert _scan(c, alice, "example.com", ["xss"]).status_code == 403


# ── Fail-closed ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("exc", [
    dns.exception.Timeout(),
    dns.resolver.NoNameservers(),
    dns.resolver.NXDOMAIN(),
    dns.resolver.NoAnswer(),
    RuntimeError("resolver crashed"),
    OSError("network unreachable"),
])
def test_failed_txt_lookup_refuses_active_checks(env, launched, dns_txt, exc):
    c, sf = env
    cookies = _user(sf, records=[("example.com", "verified")])
    dns_txt["publish"](exc=exc)
    r = _scan(c, cookies, "example.com", ["sqli"])
    assert r.status_code == 403, r.text
    assert launched == [] and _scan_count(sf) == 0


def test_empty_txt_answer_refuses(env, launched, dns_txt):
    c, sf = env
    cookies = _user(sf, records=[("example.com", "verified")])
    dns_txt["publish"](values=[])
    assert _scan(c, cookies, "example.com", ["lfi"]).status_code == 403


def test_failed_lookup_refuses_port_scan_endpoint(env, nmap_calls, dns_txt):
    c, sf = env
    cookies = _user(sf, records=[("example.com", "verified")])
    dns_txt["publish"](exc=dns.exception.Timeout())
    r = c.post("/api/scan/ports", json={"target": "example.com"}, cookies=cookies)
    assert r.status_code == 403
    assert nmap_calls == []


# ── Training targets ─────────────────────────────────────────────────────────

def test_training_target_allowed_without_verification(env, launched, dns_txt):
    c, sf = env
    r = _scan(c, _user(sf), "http://demo.testfire.net/", ["xss", "sqli", "lfi", "ssrf"])
    assert r.status_code == 200, r.text
    assert launched[0]["authorized_checks"] == {"xss", "sqli", "lfi", "ssrf"}
    assert dns_txt["calls"] == []


def test_training_port_target_allowed_on_port_scan_endpoint(env, nmap_calls, dns_txt):
    c, sf = env
    r = c.post("/api/scan/ports", json={"target": "scanme.nmap.org"}, cookies=_user(sf))
    assert r.status_code == 200, r.text
    assert nmap_calls == ["scanme.nmap.org"]


def test_training_allowlist_is_exact_host(env, launched, dns_txt):
    c, sf = env
    r = _scan(c, _user(sf), "evil.demo.testfire.net", ["sqli"])
    assert r.status_code == 403


@pytest.mark.parametrize("target", ["localhost", "127.0.0.1", "http://10.0.0.5/"])
def test_local_and_internal_hosts_not_allowlisted(env, launched, dns_txt, target):
    c, sf = env
    r = _scan(c, _user(sf), target, ["xss"])
    assert r.status_code in (400, 403)
    assert launched == []


# ── No bypass ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("extra", [
    {"force": True},
    {"skip_authorization": True},
    {"authorized": True},
    {"bypass_authz": True},
    {"authz_basis": "verified:dns_txt:unverified.test"},
    {"authorized_checks": ["xss"]},
    {"training": True},
])
def test_request_fields_cannot_bypass(env, launched, dns_txt, extra):
    c, sf = env
    r = _scan(c, _user(sf), "unverified.test", ["xss"], **extra)
    assert r.status_code == 403
    assert launched == []


def test_query_params_and_headers_cannot_bypass(env, launched, dns_txt):
    c, sf = env
    r = c.post(
        "/api/scan?force=1&skip_authz=true&authorized=1",
        json={"target": "unverified.test", "scan_types": ["sqli"]},
        headers={"X-Skip-Authorization": "1", "X-Authorized": "true"},
        cookies=_user(sf),
    )
    assert r.status_code == 403
    assert launched == []


@pytest.mark.parametrize("name,value", [
    ("SCAN_AUTHZ_ENFORCE", "false"),
    ("SCAN_AUTHZ_ENFORCE", "0"),
    ("SCAN_AUTHZ_BYPASS", "1"),
    ("SCAN_VERIFICATION_TTL_DAYS", "100000"),
    ("GROQ_ENV", "development"),
    ("DEBUG", "true"),
])
def test_environment_cannot_bypass(env, launched, dns_txt, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    c, sf = env
    r = _scan(c, _user(sf), "unverified.test", ["ssrf"])
    assert r.status_code == 403
    assert launched == []


def test_environment_cannot_skip_live_txt_recheck(env, launched, dns_txt, monkeypatch):
    monkeypatch.setenv("SCAN_VERIFICATION_TTL_DAYS", "100000")
    c, sf = env
    cookies = _user(sf, records=[("example.com", "verified")])  # checked just now
    dns_txt["publish"](exc=dns.resolver.NXDOMAIN())
    assert _scan(c, cookies, "example.com", ["xss"]).status_code == 403
    assert dns_txt["calls"] == ["_optisec-verify.example.com"]
