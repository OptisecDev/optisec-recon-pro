"""
Endpoint coverage for scan authorization (web/scan_authz.py via
web/domain_verification.check_scan_authorization): every route that can
start an active check refuses it for an unverified target, lets passive
work through, and records why a scan was allowed. There is no log-only
switch.

Gated routes: POST /api/scan (+ _run_scan_task itself), /api/scan/ports,
/api/osint (subdomain step only), /api/osint/network-scan with
deep_scan, /federation/api/scan. /autonomous-redteam/api/start is covered in
tests/test_autonomous_rt_router.py.

No network: every scanner the routes would call is monkeypatched to a
recorder, and the live ownership re-check every active scan runs is faked
as still matching (see _isolation).
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest import mock
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import modules.federation.federated_scan as federated_scan
import modules.osint.network_intelligence as network_intelligence
import modules.scan_scope as scan_scope_module
import web.app as app_module
import web.domain_verification as dv
import web.migrate_add_scan_authz_columns as scan_cols_migration
import web.rate_limit as rate_limit
from web.auth import create_access_token, generate_csrf_token
from web.database import Base, get_db
from web.models import DomainVerification, Scan, User
from web.scan_authz import ACTIVE_CHECKS, PASSIVE_CHECKS, SCAN_STEP_ORDER
from modules.recon.nmap_scanner import nmap_scan as real_nmap_scan

# The real checks, before _isolation fakes them, for tests that only fake DNS.
REAL_CHECK_DNS_TXT = dv.check_dns_txt


CSRF_SECRET = "scan-authz-test-csrf-secret"

def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    rate_limit._buckets.clear()

    async def still_matches(*a, **k):
        return dv.CheckResult(True)
    monkeypatch.setattr(dv, "check_dns_txt", still_matches)
    monkeypatch.setattr(dv, "check_http_file", still_matches)
    # network_scope_for() resolves the scope's hosts; keep that offline.
    monkeypatch.setattr(scan_scope_module, "_resolve", lambda host: {"93.184.216.34"})
    yield
    rate_limit._buckets.clear()


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
    # POST /api/scan, /api/scan/ports and /api/osint require X-CSRF-Token
    # for cookie auth; every session cookie set below carries CSRF_SECRET.
    client = TestClient(app_module.app, headers={"X-CSRF-Token": generate_csrf_token(CSRF_SECRET)})
    yield client, sf
    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def _user(sf, username="alice", verified=()):
    async def go():
        async with sf() as db:
            u = User(
                username=username, email=f"{username}@example.com", password_hash="x",
                role="analyst", subscription_tier="enterprise", is_active=True,
            )
            db.add(u)
            await db.flush()
            for domain in verified:
                db.add(DomainVerification(
                    user_id=u.id, domain=domain, method="dns_txt", token=f"{username}-{domain}",
                    status="verified", verified_at=datetime.utcnow(), last_checked_at=datetime.utcnow(),
                ))
            await db.commit()
            return u.id
    uid = _run(go())
    return {"access_token": create_access_token(uid, "analyst"), "csrf_secret": CSRF_SECRET}


def _scans(sf):
    async def go():
        async with sf() as db:
            return (await db.execute(select(Scan))).scalars().all()
    return _run(go())


@pytest.fixture
def launched(monkeypatch):
    """Record what /api/scan hands to the background task instead of running it."""
    calls = []

    async def fake_task(*args, **kwargs):
        calls.append((args, kwargs))
    monkeypatch.setattr(app_module, "_run_scan_task", fake_task)
    return calls


# ── POST /api/scan ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("check", sorted(ACTIVE_CHECKS))
def test_api_scan_refuses_each_active_check_on_unverified(env, launched, check):
    c, sf = env
    r = c.post("/api/scan", json={"target": "unverified.test", "scan_types": [check]}, cookies=_user(sf))
    assert r.status_code == 403
    assert r.json()["denied_checks"] == [check]
    assert r.json()["verify_endpoint"] == "/api/domains/verify"
    assert _scans(sf) == [] and launched == []


def test_api_scan_run_all_on_unverified_refused_whole_request(env, launched):
    c, sf = env
    r = c.post("/api/scan", json={"target": "unverified.test", "scan_types": []}, cookies=_user(sf))
    assert r.status_code == 403
    assert set(r.json()["denied_checks"]) == ACTIVE_CHECKS
    assert set(r.json()["allowed_checks"]) == PASSIVE_CHECKS
    assert _scans(sf) == [] and launched == []


def test_api_scan_passive_on_unverified_runs_and_records_basis(env, launched):
    c, sf = env
    r = c.post("/api/scan", json={"target": "unverified.test", "scan_types": ["headers", "dns"]}, cookies=_user(sf))
    assert r.status_code == 200, r.text
    (scan,) = _scans(sf)
    assert scan.authz_basis == "passive_only"
    assert scan.authz_checks == ["dns", "headers"]
    assert launched[0][1]["authorized_checks"] == {"dns", "headers"}
    assert launched[0][1]["scope"] is None


def test_api_scan_verified_run_all(env, launched):
    c, sf = env
    r = c.post(
        "/api/scan", json={"target": "https://shop.example.com", "scan_types": []},
        cookies=_user(sf, verified=["example.com"]),
    )
    assert r.status_code == 200, r.text
    (scan,) = _scans(sf)
    assert scan.authz_basis == "verified:dns_txt:example.com"
    assert scan.authz_checks == list(SCAN_STEP_ORDER)
    assert launched[0][1]["authorized_checks"] == set(SCAN_STEP_ORDER)
    scope = launched[0][1]["scope"]
    assert scope.suffixes == {"example.com"} and scope.hosts == frozenset()
    assert scope.allows("shop.example.com") and not scope.allows("evil.test")


def test_api_scan_rechecks_dns_before_launch(env, launched, monkeypatch):
    c, sf = env
    cookies = _user(sf, verified=["example.com"])
    order = []

    async def recheck(domain, token):
        order.append(("dns", domain))
        return dv.CheckResult(True)

    async def fake_task(*args, **kwargs):
        order.append(("launch", args[1]))
    monkeypatch.setattr(dv, "check_dns_txt", recheck)
    monkeypatch.setattr(app_module, "_run_scan_task", fake_task)
    for _ in range(2):
        r = c.post("/api/scan", json={"target": "example.com", "scan_types": ["nmap"]}, cookies=cookies)
        assert r.status_code == 200, r.text
    assert order == [("dns", "example.com"), ("launch", "example.com")] * 2


def test_api_scan_refused_when_dns_no_longer_matches(env, launched, monkeypatch):
    c, sf = env
    cookies = _user(sf, verified=["example.com"])

    async def gone(domain, token):
        return dv.CheckResult(False, "TXT record found but the token does not match")
    monkeypatch.setattr(dv, "check_dns_txt", gone)
    r = c.post("/api/scan", json={"target": "example.com", "scan_types": ["sqli", "dns"]}, cookies=cookies)
    assert r.status_code == 403
    assert r.json()["denied_checks"] == ["sqli"]
    assert launched == [] and _scans(sf) == []

    async def status():
        async with sf() as db:
            return (await db.execute(select(DomainVerification.status))).scalar_one()
    assert _run(status()) == "revoked"


def test_api_scan_another_users_verification_does_not_count(env, launched):
    c, sf = env
    _user(sf, "owner", verified=["example.com"])
    r = c.post("/api/scan", json={"target": "example.com", "scan_types": ["sqli"]}, cookies=_user(sf, "intruder"))
    assert r.status_code == 403


def test_api_scan_training_target_within_its_permissions(env, launched):
    c, sf = env
    r = c.post("/api/scan", json={"target": "scanme.nmap.org", "scan_types": ["nmap", "dns"]}, cookies=_user(sf))
    assert r.status_code == 200, r.text
    assert _scans(sf)[0].authz_basis == "training:scanme.nmap.org"
    scope = launched[0][1]["scope"]
    assert scope.hosts == {"scanme.nmap.org"} and not scope.allows("sub.scanme.nmap.org")


def test_api_scan_training_target_beyond_its_permissions(env, launched):
    c, sf = env
    r = c.post("/api/scan", json={"target": "scanme.nmap.org", "scan_types": ["nmap", "xss"]}, cookies=_user(sf))
    assert r.status_code == 403
    assert r.json()["denied_checks"] == ["xss"]
    assert "only permits" in r.json()["error"]


def test_api_scan_unknown_type_refused(env, launched):
    c, sf = env
    r = c.post(
        "/api/scan", json={"target": "example.com", "scan_types": ["dns", "rce"]},
        cookies=_user(sf, verified=["example.com"]),
    )
    assert r.status_code == 403
    assert r.json()["denied_checks"] == ["rce"]


@pytest.mark.parametrize("bad", ["xss", [1, 2], {"xss": True}, None])
def test_api_scan_malformed_scan_types(env, launched, bad):
    c, sf = env
    r = c.post("/api/scan", json={"target": "example.com", "scan_types": bad}, cookies=_user(sf))
    assert r.status_code == 400
    assert launched == []


@pytest.mark.parametrize("value", ["false", "0", "off", "no"])
def test_scan_authz_enforce_env_is_ignored(env, launched, monkeypatch, value):
    """The old SCAN_AUTHZ_ENFORCE=false log-only switch is gone: setting it
    changes nothing, and active checks on an unverified target are refused."""
    monkeypatch.setenv("SCAN_AUTHZ_ENFORCE", value)
    c, sf = env
    r = c.post("/api/scan", json={"target": "unverified.test", "scan_types": ["xss", "dns"]}, cookies=_user(sf))
    assert r.status_code == 403
    assert r.json()["denied_checks"] == ["xss"]
    assert launched == [] and _scans(sf) == []
    assert not hasattr(dv, "scan_authz_enforced")


def test_denial_is_logged(env, launched, caplog):
    c, sf = env
    with caplog.at_level(logging.WARNING, logger="optisec.scan_authz"):
        c.post("/api/scan", json={"target": "unverified.test", "scan_types": ["nmap"]}, cookies=_user(sf))
    assert any("source=api_scan" in m and "denied=['nmap']" in m for m in caplog.messages)


# ── _run_scan_task ───────────────────────────────────────────────────────────

def test_run_scan_task_requires_authorized_checks_and_scope():
    with pytest.raises(TypeError):
        _run(app_module._run_scan_task("s", "example.com", [], 1, None))
    with pytest.raises(TypeError):
        _run(app_module._run_scan_task("s", "example.com", [], 1, None, authorized_checks={"dns"}))


def test_run_scan_task_runs_only_authorized_steps(env, monkeypatch):
    """Defence in depth: even with scan_types=[] ("run all"), only the
    authorized steps execute."""
    _, sf = env
    _run(_seed_scan(sf, "scan-authz-1"))
    monkeypatch.setattr(app_module, "SessionLocal", sf)

    async def no_broadcast(*a, **k):
        return None
    monkeypatch.setattr(app_module.ws_manager, "broadcast", no_broadcast)

    called = []

    def recorder(name, result):
        def f(*a, **k):
            called.append(name)
            return result
        return f
    monkeypatch.setattr(app_module, "enumerate_subdomains", recorder("subdomain", {"subdomains": [], "unconfirmed": []}))
    monkeypatch.setattr(app_module, "dns_lookup", recorder("dns", {}))
    monkeypatch.setattr(app_module, "whois_lookup", recorder("whois", {}))
    monkeypatch.setattr(app_module, "nmap_scan", recorder("nmap", {}))
    monkeypatch.setattr(app_module, "scan_xss", recorder("xss", []))
    monkeypatch.setattr(app_module, "scan_sqli", recorder("sqli", []))

    _run(app_module._run_scan_task(
        "scan-authz-1", "example.com", [], 1, None, authorized_checks={"dns", "whois"}, scope=None,
    ))
    assert sorted(called) == ["dns", "whois"]


async def _seed_scan(sf, scan_id):
    async with sf() as db:
        db.add(Scan(id=scan_id, user_id=1, target_url="example.com", scan_types=[], status="pending"))
        await db.commit()


# ── /api/scan/ports ──────────────────────────────────────────────────────────

@pytest.fixture
def nmap_calls(monkeypatch):
    calls = []

    def fake(target):
        calls.append(target)
        return {"ports": []}
    monkeypatch.setattr(app_module, "nmap_scan", fake)
    return calls


def test_ports_refused_on_unverified(env, nmap_calls):
    c, sf = env
    r = c.post("/api/scan/ports", json={"target": "unverified.test"}, cookies=_user(sf))
    assert r.status_code == 403
    assert r.json()["denied_checks"] == ["nmap"]
    assert nmap_calls == []


def test_ports_allowed_on_training_target(env, nmap_calls):
    c, sf = env
    r = c.post("/api/scan/ports", json={"target": "scanme.nmap.org"}, cookies=_user(sf))
    assert r.status_code == 200
    assert nmap_calls == ["scanme.nmap.org"]


def test_ports_allowed_on_verified(env, nmap_calls):
    c, sf = env
    r = c.post("/api/scan/ports", json={"target": "api.example.com"}, cookies=_user(sf, verified=["example.com"]))
    assert r.status_code == 200
    assert nmap_calls == ["api.example.com"]


def test_api_scan_ports_refused_when_ownership_mismatch(env, monkeypatch):
    """The real TXT re-check (only the resolver faked) finds another token:
    403 before nmap_scan is ever entered, nothing recorded."""
    c, sf = env
    cookies = _user(sf, verified=["example.com"])
    lookups = []

    async def txt(name):
        lookups.append(name)
        return ["optisec-verify=someone-elses-token"]
    monkeypatch.setattr(dv, "check_dns_txt", REAL_CHECK_DNS_TXT)
    monkeypatch.setattr(dv, "_resolve_txt", txt)
    scanner = mock.create_autospec(real_nmap_scan, side_effect=AssertionError("nmap_scan launched"))
    monkeypatch.setattr(app_module, "nmap_scan", scanner)

    r = c.post("/api/scan/ports", json={"target": "api.example.com"}, cookies=cookies)
    assert r.status_code == 403
    assert r.json()["denied_checks"] == ["nmap"]
    assert lookups == ["_optisec-verify.example.com"]
    assert scanner.call_count == 0
    assert _scans(sf) == []


# ── /api/osint ───────────────────────────────────────────────────────────────

@pytest.fixture
def osint_calls(monkeypatch):
    calls = []

    async def emails(domain):
        return {"emails": []}

    async def social(domain):
        return {}

    def subs(domain, passive=False):
        calls.append((domain, passive))
        if passive:
            return {"subdomains": [], "unconfirmed": [{"subdomain": "www." + domain, "reason": "dns_only"}]}
        return {"subdomains": ["www." + domain], "unconfirmed": []}
    monkeypatch.setattr(app_module, "find_emails", emails)
    monkeypatch.setattr(app_module, "find_social_profiles", social)
    monkeypatch.setattr(app_module, "dns_lookup", lambda d: {"a": []})
    monkeypatch.setattr(app_module, "whois_lookup", lambda d: {})
    monkeypatch.setattr(app_module, "enumerate_subdomains", subs)
    return calls


def test_osint_unverified_uses_passive_subdomains(env, osint_calls):
    c, sf = env
    r = c.post("/api/osint", json={"domain": "unverified.test"}, cookies=_user(sf))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["subdomains"] == []
    assert body["subdomains_unconfirmed"] == [{"subdomain": "www.unverified.test", "reason": "dns_only"}]
    assert body["subdomains_mode"] == "passive"
    assert "verif" in body["subdomains_note"].lower()
    assert body["dns"] == {"a": []}
    assert osint_calls == [("unverified.test", True)]


def test_osint_verified_enumerates_subdomains(env, osint_calls):
    c, sf = env
    r = c.post("/api/osint", json={"domain": "example.com"}, cookies=_user(sf, verified=["example.com"]))
    body = r.json()
    assert body["subdomains"] == ["www.example.com"]
    assert body["subdomains_mode"] == "active"
    assert body["subdomains_note"] is None
    assert osint_calls == [("example.com", False)]


# ── /api/osint/network-scan ────────────────────────────────────────────

@pytest.fixture
def netintel_calls(monkeypatch):
    calls = []

    async def fake(target, deep_scan=False):
        calls.append((target, deep_scan))
        return {"target": target}
    monkeypatch.setattr(network_intelligence, "gather_network_intelligence", fake)
    return calls


def test_network_scan_passive_needs_no_verification(env, netintel_calls):
    c, sf = env
    r = c.post("/api/osint/network-scan", json={"target": "unverified.test"}, cookies=_user(sf))
    assert r.status_code == 200, r.text
    assert netintel_calls == [("unverified.test", False)]


def test_network_deep_scan_refused_on_unverified(env, netintel_calls):
    c, sf = env
    r = c.post("/api/osint/network-scan", json={"target": "unverified.test", "deep_scan": True}, cookies=_user(sf))
    assert r.status_code == 403
    assert r.json()["denied_checks"] == ["ports"]
    assert netintel_calls == []


def test_network_deep_scan_allowed_on_verified(env, netintel_calls):
    c, sf = env
    r = c.post(
        "/api/osint/network-scan", json={"target": "example.com", "deep_scan": True},
        cookies=_user(sf, verified=["example.com"]),
    )
    assert r.status_code == 200
    assert netintel_calls == [("example.com", True)]


# ── /federation/api/scan ─────────────────────────────────────────────────────

@pytest.fixture
def federation_calls(monkeypatch):
    calls = []

    async def fake(**kwargs):
        calls.append(kwargs)
        return {"task_id": "t1"}
    monkeypatch.setattr(federated_scan, "dispatch_scan", fake)
    return calls


def test_federation_scan_refused_on_unverified(env, federation_calls):
    c, sf = env
    r = c.post("/federation/api/scan", json={"target": "unverified.test", "scan_types": ["recon"]}, cookies=_user(sf))
    assert r.status_code == 403
    assert federation_calls == []


def test_federation_scan_refused_on_training_target(env, federation_calls):
    c, sf = env
    r = c.post("/federation/api/scan", json={"target": "scanme.nmap.org"}, cookies=_user(sf))
    assert r.status_code == 403
    assert federation_calls == []


def test_federation_scan_allowed_on_verified(env, federation_calls):
    c, sf = env
    r = c.post(
        "/federation/api/scan", json={"target": "example.com", "scan_types": ["recon"]},
        cookies=_user(sf, verified=["example.com"]),
    )
    assert r.status_code == 200, r.text
    assert federation_calls[0]["target"] == "example.com"


def test_federation_scan_requires_target(env, federation_calls):
    c, sf = env
    assert c.post("/federation/api/scan", json={}, cookies=_user(sf)).status_code == 400


# ── Scan.authz_* column migration ────────────────────────────────────────────

def test_scan_authz_columns_migration_on_pre_existing_table(monkeypatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    monkeypatch.setattr(scan_cols_migration, "engine", engine)

    async def go():
        async with engine.begin() as conn:
            await conn.execute(text(
                "CREATE TABLE scans (id VARCHAR(64) PRIMARY KEY, user_id INTEGER NOT NULL, "
                "target_url VARCHAR(500) NOT NULL)"
            ))
            await conn.execute(text("INSERT INTO scans (id, user_id, target_url) VALUES ('old', 1, 'x')"))
        first = await scan_cols_migration.migrate()
        second = await scan_cols_migration.migrate()
        async with engine.begin() as conn:
            cols = await conn.run_sync(lambda c: {col["name"] for col in inspect(c).get_columns("scans")})
            row = (await conn.execute(text("SELECT authz_basis, authz_checks FROM scans WHERE id='old'"))).one()
        return first, second, cols, row
    try:
        first, second, cols, row = _run(go())
    finally:
        _run(engine.dispose())
    assert first == ["authz_basis", "authz_checks"]
    assert second == []
    assert {"authz_basis", "authz_checks"} <= cols
    assert tuple(row) == (None, None)


def test_startup_sequence_runs_scan_authz_migration():
    import inspect as pyinspect
    src = pyinspect.getsource(app_module._startup_db_sequence)
    assert "migrate_add_scan_authz_columns" in src
