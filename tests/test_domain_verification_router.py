"""
Endpoint coverage for web/routers/domain_verification.py: create/list/
check/delete, role and CSRF enforcement, input validation, and per-user
isolation (another user's record is a 404, and its token never leaks).

Same TestClient + in-memory-SQLite + _seed_user_token pattern as
tests/test_targets_idor.py. The ownership check itself is faked via
web.domain_verification's check functions -- the real checks are covered
in tests/test_domain_verification.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import web.app as app_module
import web.domain_verification as dv
import web.rate_limit as rate_limit
from web import auth as auth_module
from web.auth import create_access_token, hash_password
from web.database import Base, get_db
from web.models import DomainVerification, User
from web.routers import domain_verification as router_module

CSRF_SECRET = "domain-verification-fixture-csrf-secret"
CSRF_TOKEN = auth_module.generate_csrf_token(CSRF_SECRET)


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    rate_limit._buckets.clear()
    yield
    rate_limit._buckets.clear()


@pytest.fixture(autouse=True)
def _no_real_checks(monkeypatch):
    async def boom(*a, **k):
        raise AssertionError("real ownership check attempted in a router test")
    monkeypatch.setattr(dv, "check_dns_txt", boom)
    monkeypatch.setattr(dv, "check_http_file", boom)


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
    _run(setup())

    async def override_get_db():
        async with sf() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app_module.app), sf
    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def _seed_user(sf, username, role="analyst"):
    async def go():
        async with sf() as db:
            u = User(
                username=username, email=f"{username}@example.com",
                password_hash=hash_password("Passw0rd!1"), role=role, is_active=True,
            )
            db.add(u)
            await db.commit()
            await db.refresh(u)
            return u.id
    uid = _run(go())
    return uid, create_access_token(uid, role)


def _cookie_auth(token):
    """Browser-style: JWT cookie + double-submit CSRF."""
    return {
        "cookies": {"access_token": token, "csrf_secret": CSRF_SECRET},
        "headers": {"X-CSRF-Token": CSRF_TOKEN},
    }


def _create(c, token, domain="example.com", method="dns_txt"):
    return c.post("/api/domains/verify", json={"domain": domain, "method": method}, **_cookie_auth(token))


def _fake_check(monkeypatch, verified, error=None, transient=False):
    async def fake(*a, **k):
        return dv.CheckResult(verified, error, transient)
    monkeypatch.setattr(dv, "check_dns_txt", fake)
    monkeypatch.setattr(dv, "check_http_file", fake)


def _db_rows(sf):
    async def go():
        async with sf() as db:
            return (await db.execute(select(DomainVerification))).scalars().all()
    return _run(go())


# ── wiring ───────────────────────────────────────────────────────────────────

def test_csrf_cookie_name_matches_app():
    assert router_module.CSRF_COOKIE_NAME == app_module.CSRF_COOKIE_NAME


# ── create ───────────────────────────────────────────────────────────────────

def test_create_dns_returns_token_and_instructions(client):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    r = _create(c, tok, "https://Example.COM/some/path")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["domain"] == "example.com"
    assert body["status"] == "pending"
    assert body["instructions"]["name"] == "_optisec-verify.example.com"
    assert body["instructions"]["value"] == f"optisec-verify={body['token']}"


def test_create_http_file_instructions(client):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    body = _create(c, tok, "app.example.com", "http_file").json()
    assert body["instructions"]["url"] == "https://app.example.com/.well-known/optisec-verify.txt"
    assert body["instructions"]["content"] == body["token"]


def test_create_is_idempotent_per_domain_and_method(client):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    first = _create(c, tok).json()
    again = _create(c, tok)
    assert again.status_code == 200
    assert again.json()["id"] == first["id"]
    assert again.json()["token"] == first["token"]
    other_method = _create(c, tok, method="http_file").json()
    assert other_method["id"] != first["id"]
    assert len(_db_rows(sf)) == 2


def test_same_domain_two_users_get_separate_tokens(client):
    c, sf = client
    _, a = _seed_user(sf, "alice")
    _, b = _seed_user(sf, "bob")
    ta = _create(c, a).json()["token"]
    tb = _create(c, b).json()["token"]
    assert ta != tb


@pytest.mark.parametrize("payload", [
    {"domain": "example.com", "method": "email"},
    {"domain": "example.com"},
    {"method": "dns_txt"},
    {"domain": 123, "method": "dns_txt"},
    {"domain": "localhost", "method": "dns_txt"},
    {"domain": "10.0.0.5", "method": "http_file"},
    {"domain": "93.184.216.34", "method": "dns_txt"},
    {"domain": "intranet", "method": "dns_txt"},
])
def test_create_rejects_invalid_input(client, payload):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    r = c.post("/api/domains/verify", json=payload, **_cookie_auth(tok))
    assert r.status_code == 400, r.text
    assert _db_rows(sf) == []


def test_create_rejects_non_object_body(client):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    r = c.post("/api/domains/verify", json=["example.com"], **_cookie_auth(tok))
    assert r.status_code == 400


def test_viewer_cannot_create(client):
    c, sf = client
    _, tok = _seed_user(sf, "victor", role="viewer")
    assert _create(c, tok).status_code == 403
    assert _db_rows(sf) == []


def test_unauthenticated_rejected(client):
    c, _ = client
    r = c.post("/api/domains/verify", json={"domain": "example.com", "method": "dns_txt"})
    assert r.status_code == 401


def test_cookie_auth_without_csrf_rejected(client):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    r = c.post(
        "/api/domains/verify", json={"domain": "example.com", "method": "dns_txt"},
        cookies={"access_token": tok},
    )
    assert r.status_code == 403
    assert _db_rows(sf) == []


def test_cookie_auth_with_wrong_csrf_rejected(client):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    r = c.post(
        "/api/domains/verify", json={"domain": "example.com", "method": "dns_txt"},
        cookies={"access_token": tok, "csrf_secret": CSRF_SECRET},
        headers={"X-CSRF-Token": "forged"},
    )
    assert r.status_code == 403


def test_bearer_auth_needs_no_csrf(client):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    r = c.post(
        "/api/domains/verify", json={"domain": "example.com", "method": "dns_txt"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 201, r.text


def test_per_user_record_cap(client, monkeypatch):
    c, sf = client
    monkeypatch.setattr(router_module, "MAX_RECORDS_PER_USER", 2)
    monkeypatch.setenv("RATE_LIMIT_DOMAINS_VERIFY", "100")
    _, tok = _seed_user(sf, "alice")
    assert _create(c, tok, "a.example.com").status_code == 201
    assert _create(c, tok, "b.example.com").status_code == 201
    assert _create(c, tok, "c.example.com").status_code == 403
    # Re-requesting an existing one still works at the cap.
    assert _create(c, tok, "a.example.com").status_code == 200


def test_create_rate_limited(client, monkeypatch):
    c, sf = client
    monkeypatch.setenv("RATE_LIMIT_DOMAINS_VERIFY", "2")
    _, tok = _seed_user(sf, "alice")
    assert _create(c, tok, "a.example.com").status_code == 201
    assert _create(c, tok, "b.example.com").status_code == 201
    assert _create(c, tok, "c.example.com").status_code == 429


# ── check ────────────────────────────────────────────────────────────────────

def test_check_success_marks_verified(client, monkeypatch):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    rid = _create(c, tok).json()["id"]
    _fake_check(monkeypatch, True)
    r = c.post(f"/api/domains/{rid}/check", **_cookie_auth(tok))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "verified"
    assert r.json()["verified_at"] and r.json()["last_checked_at"]


def test_check_failure_reports_error(client, monkeypatch):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    rid = _create(c, tok).json()["id"]
    _fake_check(monkeypatch, False, "TXT record not found")
    body = c.post(f"/api/domains/{rid}/check", **_cookie_auth(tok)).json()
    assert body["status"] == "failed"
    assert body["last_error"] == "TXT record not found"


def test_check_other_users_record_is_404(client):
    c, sf = client
    _, owner = _seed_user(sf, "owner")
    _, attacker = _seed_user(sf, "attacker")
    rid = _create(c, owner).json()["id"]
    r = c.post(f"/api/domains/{rid}/check", **_cookie_auth(attacker))
    assert r.status_code == 404


def test_check_requires_csrf_and_role(client):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    rid = _create(c, tok).json()["id"]
    assert c.post(f"/api/domains/{rid}/check", cookies={"access_token": tok}).status_code == 403
    _, viewer = _seed_user(sf, "victor", role="viewer")
    assert c.post(f"/api/domains/{rid}/check", **_cookie_auth(viewer)).status_code == 403


def test_check_rate_limited(client, monkeypatch):
    c, sf = client
    monkeypatch.setenv("RATE_LIMIT_DOMAINS_CHECK", "1")
    _, tok = _seed_user(sf, "alice")
    rid = _create(c, tok).json()["id"]
    _fake_check(monkeypatch, False, "TXT record not found")
    assert c.post(f"/api/domains/{rid}/check", **_cookie_auth(tok)).status_code == 200
    assert c.post(f"/api/domains/{rid}/check", **_cookie_auth(tok)).status_code == 429


# ── list ─────────────────────────────────────────────────────────────────────

def test_list_returns_only_own_records(client):
    c, sf = client
    _, a = _seed_user(sf, "alice")
    _, b = _seed_user(sf, "bob")
    _create(c, a, "alice.example.com")
    b_token = _create(c, b, "bob.example.com").json()["token"]
    r = c.get("/api/domains", cookies={"access_token": a})
    assert r.status_code == 200
    rows = r.json()["verifications"]
    assert [x["domain"] for x in rows] == ["alice.example.com"]
    assert b_token not in r.text


def test_viewer_can_list_own(client):
    c, sf = client
    _, tok = _seed_user(sf, "victor", role="viewer")
    r = c.get("/api/domains", cookies={"access_token": tok})
    assert r.status_code == 200
    assert r.json() == {"verifications": []}


# ── delete ───────────────────────────────────────────────────────────────────

def test_delete_own_record(client):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    rid = _create(c, tok).json()["id"]
    r = c.delete(f"/api/domains/{rid}", **_cookie_auth(tok))
    assert r.status_code == 200
    assert _db_rows(sf) == []


def test_delete_other_users_record_is_404(client):
    c, sf = client
    _, owner = _seed_user(sf, "owner")
    _, attacker = _seed_user(sf, "attacker")
    rid = _create(c, owner).json()["id"]
    assert c.delete(f"/api/domains/{rid}", **_cookie_auth(attacker)).status_code == 404
    assert len(_db_rows(sf)) == 1


def test_delete_requires_csrf(client):
    c, sf = client
    _, tok = _seed_user(sf, "alice")
    rid = _create(c, tok).json()["id"]
    assert c.delete(f"/api/domains/{rid}", cookies={"access_token": tok}).status_code == 403
    assert len(_db_rows(sf)) == 1
