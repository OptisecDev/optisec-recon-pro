"""
Passive scan endpoints refuse internal targets and go through scan
authorization (web/domain_verification.authorize_passive_target).

POST /api/scan/ssl and /api/scan/headers previously took any target and
connected straight to it -- 127.0.0.1, 169.254.169.254, a private 10.x host
or a public name resolving to one -- with no check_scan_authorization call
at all, so the server could be pointed at its own internal network (SSRF).
/api/osint, /api/osint/domain and /api/osint/network-scan (whose SSL
analysis also opens a socket at the target) had the same gap for their
passive steps.

Each route now rejects an internal host with 403 before any scanner runs
(every scanner is monkeypatched to a recorder that must stay empty), and
calls check_scan_authorization for its passive checks. Per the scan
authorization policy (web/scan_authz.py, "Option B"), passive checks are
still allowed on unverified public domains.
"""

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import modules.osint.network_intelligence as network_intelligence
import modules.recon.security_headers as security_headers
import modules.recon.ssl_analysis as ssl_analysis
import web.app as app_module
import web.domain_verification as dv
import web.rate_limit as rate_limit
from web.auth import create_access_token, generate_csrf_token
from web.database import Base, get_db
from web.models import User

CSRF_SECRET = "passive-guard-test-csrf-secret"

# What each name "resolves" to in these tests -- no real DNS.
FAKE_DNS = {
    "public.example": ["93.184.216.34"],
    "rebind.example": ["10.0.0.5"],
}

INTERNAL_TARGETS = [
    "127.0.0.1", "http://127.0.0.1:8000/", "localhost", "10.1.2.3",
    "169.254.169.254", "[::1]", "rebind.example",
]


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    rate_limit._buckets.clear()
    monkeypatch.delenv("SCAN_AUTHZ_ENFORCE", raising=False)

    async def fake_resolve(host):
        if host in FAKE_DNS:
            return FAKE_DNS[host]
        raise OSError("NXDOMAIN")
    monkeypatch.setattr(dv, "_resolve_addresses", fake_resolve)
    yield
    rate_limit._buckets.clear()


@pytest.fixture
def client():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    sf = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with sf() as db:
            u = User(
                username="alice", email="alice@example.com", password_hash="x",
                role="analyst", subscription_tier="enterprise", is_active=True,
            )
            db.add(u)
            await db.commit()
            return u.id
    uid = _run(setup())

    async def override_get_db():
        async with sf() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db
    c = TestClient(app_module.app)
    c.cookies.set("access_token", create_access_token(uid, "analyst"))
    c.cookies.set("csrf_secret", CSRF_SECRET)
    c.headers["X-CSRF-Token"] = generate_csrf_token(CSRF_SECRET)
    yield c
    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


@pytest.fixture
def scanner_calls(monkeypatch):
    calls = []

    def fake_ssl(target):
        calls.append(("ssl", target))
        return {"target": target}

    def fake_headers(target):
        calls.append(("headers", target))
        return {"target": target}

    async def fake_netintel(target, deep_scan=False):
        calls.append(("netintel", target))
        return {"target": target}

    async def fake_emails(domain):
        calls.append(("emails", domain))
        return {}

    async def fake_social(domain):
        return {}

    monkeypatch.setattr(ssl_analysis, "analyze_ssl", fake_ssl)
    monkeypatch.setattr(security_headers, "check_security_headers", fake_headers)
    monkeypatch.setattr(network_intelligence, "gather_network_intelligence", fake_netintel)
    monkeypatch.setattr(app_module, "find_emails", fake_emails)
    monkeypatch.setattr(app_module, "find_social_profiles", fake_social)
    monkeypatch.setattr(app_module, "dns_lookup", lambda d: calls.append(("dns", d)) or {})
    monkeypatch.setattr(app_module, "whois_lookup", lambda d: calls.append(("whois", d)) or {})
    monkeypatch.setattr(app_module, "enumerate_subdomains", lambda d, passive=False: {"subdomains": [], "unconfirmed": []})
    return calls


ROUTES = [
    ("/api/scan/ssl", "target"),
    ("/api/scan/headers", "target"),
    ("/api/osint", "domain"),
    ("/api/osint/network-scan", "target"),
]


@pytest.mark.parametrize("path,field", [("/api/scan/headers", "target"), ("/api/scan/ssl", "target")])
def test_loopback_is_refused_with_403(client, scanner_calls, path, field):
    r = client.post(path, json={field: "127.0.0.1"})
    assert r.status_code == 403, r.text
    assert scanner_calls == []


@pytest.mark.parametrize("path,field", ROUTES)
@pytest.mark.parametrize("target", INTERNAL_TARGETS)
def test_internal_targets_refused_before_any_connection(client, scanner_calls, path, field, target):
    r = client.post(path, json={field: target})
    assert r.status_code == 403, r.text
    assert "internal" in r.json()["error"]
    assert scanner_calls == []


def test_osint_domain_router_refuses_internal_target(client, monkeypatch):
    import modules.recon.dns_lookup as dns_mod
    called = []
    monkeypatch.setattr(dns_mod, "dns_lookup", lambda d: called.append(d) or {})
    r = client.post("/api/osint/domain", json={"domain": "127.0.0.1"})
    assert r.status_code == 403
    assert called == []


def test_invalid_target_refused(client, scanner_calls):
    r = client.post("/api/scan/headers", json={"target": "http://"})
    assert r.status_code == 403
    assert scanner_calls == []


@pytest.mark.parametrize("path,field,scanner", [
    ("/api/scan/ssl", "target", "ssl"),
    ("/api/scan/headers", "target", "headers"),
    ("/api/osint/network-scan", "target", "netintel"),
])
def test_public_unverified_target_still_allowed_for_passive(client, scanner_calls, path, field, scanner):
    r = client.post(path, json={field: "public.example"})
    assert r.status_code == 200, r.text
    assert [c[0] for c in scanner_calls] == [scanner]


def test_passive_routes_go_through_check_scan_authorization(client, scanner_calls, monkeypatch):
    seen = []
    real = dv.check_scan_authorization

    async def spy(db, user, target, scan_types, *, source):
        seen.append((source, list(scan_types)))
        return await real(db, user, target, scan_types, source=source)
    monkeypatch.setattr(dv, "check_scan_authorization", spy)

    client.post("/api/scan/ssl", json={"target": "public.example"})
    client.post("/api/scan/headers", json={"target": "public.example"})
    assert ("api_scan_ssl", ["ssl"]) in seen
    assert ("api_scan_headers", ["headers"]) in seen


def test_denied_authorization_is_returned_before_connecting(client, scanner_calls, monkeypatch):
    """If the policy ever denies a passive check (e.g. it's reclassified as
    active), the route returns that 403 and never reaches the scanner."""
    from web.scan_authz import AuthzDecision

    async def deny(db, user, target, scan_types, *, source):
        return AuthzDecision(allowed=set(), denied=set(scan_types), reason="not authorized")
    monkeypatch.setattr(dv, "check_scan_authorization", deny)

    r = client.post("/api/scan/headers", json={"target": "public.example"})
    assert r.status_code == 403
    assert r.json()["denied_checks"] == ["headers"]
    assert scanner_calls == []


def test_internal_target_refusal_is_logged(client, scanner_calls, caplog):
    with caplog.at_level(logging.WARNING, logger="optisec.scan_authz"):
        client.post("/api/scan/ssl", json={"target": "127.0.0.1"})
    assert "source=api_scan_ssl" in caplog.text
