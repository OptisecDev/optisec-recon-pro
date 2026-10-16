"""
Unit coverage for web/domain_verification.py: the DNS TXT and HTTP file
ownership checks, run_check()'s status transitions, the DB-backed
authorize_scan() wrapper, and the domain_verifications migration.

No network: DNS goes through the monkeypatched _resolve_txt /
_resolve_addresses seams, HTTP through an httpx.MockTransport injected via
_http_client. DB tests use a private in-memory SQLite engine.
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.exception
import dns.resolver
import httpx
import pytest
from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import web.domain_verification as dv
import web.migrate_add_domain_verifications_table as migrate_module
from web.database import Base
from web.models import DomainVerification, User
from web.scan_authz import ACTIVE_CHECKS, PASSIVE_CHECKS

TOKEN = "tok_abc123"
NOW = datetime(2026, 10, 6, 12, 0, 0)


def _run(coro):
    return asyncio.run(coro)


# ── Fakes ────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _block_real_network(monkeypatch):
    """Any test that forgets to install a fake fails loudly instead of
    quietly hitting real DNS/HTTP."""
    async def no_dns(*a, **k):
        raise AssertionError("real DNS lookup attempted in a unit test")

    def no_http():
        raise AssertionError("real HTTP client created in a unit test")
    monkeypatch.setattr(dv, "_resolve_txt", no_dns)
    monkeypatch.setattr(dv, "_resolve_addresses", no_dns)
    monkeypatch.setattr(dv, "_http_client", no_http)


def _txt(monkeypatch, values=None, exc=None):
    calls = []

    async def fake(name):
        calls.append(name)
        if exc is not None:
            raise exc
        return values
    monkeypatch.setattr(dv, "_resolve_txt", fake)
    return calls


def _addrs(monkeypatch, addrs=("93.184.216.34",), exc=None):
    async def fake(host):
        if exc is not None:
            raise exc
        return list(addrs)
    monkeypatch.setattr(dv, "_resolve_addresses", fake)


def _http(monkeypatch, handler):
    seen = []

    def wrapped(request):
        seen.append(str(request.url))
        return handler(request)
    monkeypatch.setattr(
        dv, "_http_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(wrapped), follow_redirects=False),
    )
    return seen


# ── validate_domain / instructions ───────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("https://shop.example.com/path", "shop.example.com"),
])
def test_validate_domain_normalizes(raw, expected):
    assert dv.validate_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "93.184.216.34", "10.0.0.1", "intranet", "foo.localhost", "http://"])
def test_validate_domain_rejects(raw):
    with pytest.raises(ValueError):
        dv.validate_domain(raw)


def test_instructions_per_method():
    dns_rec = DomainVerification(domain="example.com", method="dns_txt", token=TOKEN)
    file_rec = DomainVerification(domain="app.example.com", method="http_file", token=TOKEN)
    assert dv.instructions(dns_rec)["name"] == "_optisec-verify.example.com"
    assert dv.instructions(dns_rec)["value"] == f"optisec-verify={TOKEN}"
    assert dv.instructions(file_rec)["url"] == "https://app.example.com/.well-known/optisec-verify.txt"
    assert dv.instructions(file_rec)["content"] == TOKEN


def test_tokens_are_unique_and_long():
    toks = {dv.new_token() for _ in range(50)}
    assert len(toks) == 50
    assert all(len(t) >= 40 for t in toks)


# ── check_dns_txt ────────────────────────────────────────────────────────────

def test_dns_match(monkeypatch):
    calls = _txt(monkeypatch, ["v=spf1 -all", f"optisec-verify={TOKEN}"])
    assert _run(dv.check_dns_txt("example.com", TOKEN)).verified
    assert calls == ["_optisec-verify.example.com"]


def test_dns_mismatch_is_definitive(monkeypatch):
    _txt(monkeypatch, ["optisec-verify=someone-elses-token"])
    r = _run(dv.check_dns_txt("example.com", TOKEN))
    assert not r.verified and not r.transient


def test_dns_token_prefix_must_be_exact(monkeypatch):
    _txt(monkeypatch, [f"optisec-verify={TOKEN}extra"])
    assert not _run(dv.check_dns_txt("example.com", TOKEN)).verified


@pytest.mark.parametrize("exc", [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()])
def test_dns_missing_record_is_definitive(monkeypatch, exc):
    _txt(monkeypatch, exc=exc)
    r = _run(dv.check_dns_txt("example.com", TOKEN))
    assert not r.verified and not r.transient


@pytest.mark.parametrize("exc", [dns.exception.Timeout(), dns.resolver.NoNameservers()])
def test_dns_failure_is_transient(monkeypatch, exc):
    _txt(monkeypatch, exc=exc)
    r = _run(dv.check_dns_txt("example.com", TOKEN))
    assert not r.verified and r.transient


# ── check_http_file ──────────────────────────────────────────────────────────

def test_file_match(monkeypatch):
    _addrs(monkeypatch)
    seen = _http(monkeypatch, lambda req: httpx.Response(200, text=f"  {TOKEN}\n"))
    assert _run(dv.check_http_file("example.com", TOKEN)).verified
    assert seen == ["https://example.com/.well-known/optisec-verify.txt"]


@pytest.mark.parametrize("body", [
    TOKEN,
    f"optisec-verify={TOKEN}",
    f"\n\t {TOKEN} \r\n",
    f"  optisec-verify={TOKEN}\n",
])
def test_file_accepts_bare_and_prefixed_token(monkeypatch, body):
    _addrs(monkeypatch)
    _http(monkeypatch, lambda req: httpx.Response(200, text=body))
    assert _run(dv.check_http_file("example.com", TOKEN)).verified


@pytest.mark.parametrize("body", [
    "optisec-verify=wrong-token",
    f"optisec-verify={TOKEN}x",
    f"optisec-verify=x{TOKEN}",
    "optisec-verify=",
    f"other-prefix={TOKEN}",
    "",
    "   \n",
])
def test_file_wrong_or_empty_token_rejected(monkeypatch, body):
    _addrs(monkeypatch)
    _http(monkeypatch, lambda req: httpx.Response(200, text=body))
    r = _run(dv.check_http_file("example.com", TOKEN))
    assert not r.verified and not r.transient
    assert r.error == "Verification file found but the token does not match"


def test_file_mismatch_does_not_echo_body(monkeypatch):
    _addrs(monkeypatch)
    _http(monkeypatch, lambda req: httpx.Response(200, text="SECRET-INTERNAL-CONTENT"))
    r = _run(dv.check_http_file("example.com", TOKEN))
    assert not r.verified and not r.transient
    assert "SECRET" not in r.error


def test_file_404_is_definitive(monkeypatch):
    _addrs(monkeypatch)
    _http(monkeypatch, lambda req: httpx.Response(404))
    r = _run(dv.check_http_file("example.com", TOKEN))
    assert not r.verified and not r.transient


def test_file_5xx_is_transient(monkeypatch):
    _addrs(monkeypatch)
    _http(monkeypatch, lambda req: httpx.Response(503))
    assert _run(dv.check_http_file("example.com", TOKEN)).transient


def test_file_falls_back_to_http_when_https_cannot_connect(monkeypatch):
    _addrs(monkeypatch)

    def handler(req):
        if req.url.scheme == "https":
            raise httpx.ConnectError("refused", request=req)
        return httpx.Response(200, text=TOKEN)
    seen = _http(monkeypatch, handler)
    assert _run(dv.check_http_file("example.com", TOKEN)).verified
    assert seen[-1].startswith("http://example.com/")


def test_file_unreachable_is_transient(monkeypatch):
    _addrs(monkeypatch)

    def handler(req):
        raise httpx.ConnectError("refused", request=req)
    _http(monkeypatch, handler)
    assert _run(dv.check_http_file("example.com", TOKEN)).transient


def test_file_same_host_redirect_followed(monkeypatch):
    _addrs(monkeypatch)

    def handler(req):
        if req.url.path == "/.well-known/optisec-verify.txt":
            return httpx.Response(301, headers={"location": "/.well-known/moved.txt"})
        return httpx.Response(200, text=TOKEN)
    seen = _http(monkeypatch, handler)
    assert _run(dv.check_http_file("example.com", TOKEN)).verified
    assert seen[-1] == "https://example.com/.well-known/moved.txt"


@pytest.mark.parametrize("location", [
    "https://attacker.test/token.txt",
    "https://sub.example.com/.well-known/optisec-verify.txt",
    "https://example.com:8443/.well-known/optisec-verify.txt",
    "http://127.0.0.1/",
    "file:///etc/passwd",
])
def test_file_redirect_off_host_refused(monkeypatch, location):
    _addrs(monkeypatch)
    seen = _http(monkeypatch, lambda req: httpx.Response(302, headers={"location": location}))
    r = _run(dv.check_http_file("example.com", TOKEN))
    assert not r.verified and not r.transient
    assert len(seen) == 1, "followed a redirect to another host"


def test_file_redirect_loop_capped(monkeypatch):
    _addrs(monkeypatch)
    seen = _http(monkeypatch, lambda req: httpx.Response(302, headers={"location": req.url.path}))
    assert not _run(dv.check_http_file("example.com", TOKEN)).verified
    assert len(seen) == dv._MAX_REDIRECTS + 1


def test_file_size_capped(monkeypatch):
    _addrs(monkeypatch)
    _http(monkeypatch, lambda req: httpx.Response(200, content=TOKEN.encode() + b" " * 10_000))
    r = _run(dv.check_http_file("example.com", TOKEN))
    assert not r.verified
    assert "too large" in r.error


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fd00::1"])
def test_file_host_resolving_internal_refused_before_fetch(monkeypatch, addr):
    _addrs(monkeypatch, ("93.184.216.34", addr))
    seen = _http(monkeypatch, lambda req: httpx.Response(200, text=TOKEN))
    r = _run(dv.check_http_file("rebind.example.com", TOKEN))
    assert not r.verified
    assert seen == []


def test_file_localhost_name_refused_without_resolving(monkeypatch):
    _addrs(monkeypatch, exc=AssertionError("must not resolve"))
    assert not _run(dv.check_http_file("localhost", TOKEN)).verified


# ── run_check status transitions ─────────────────────────────────────────────

def _rec(status="pending", method="dns_txt", last_checked_at=None):
    return DomainVerification(
        user_id=1, domain="example.com", method=method, token=TOKEN,
        status=status, last_checked_at=last_checked_at,
    )


def test_run_check_pending_to_verified(monkeypatch):
    _txt(monkeypatch, [f"optisec-verify={TOKEN}"])
    rec = _rec()
    _run(dv.run_check(rec, NOW))
    assert (rec.status, rec.verified_at, rec.last_checked_at, rec.last_error) == ("verified", NOW, NOW, None)


def test_run_check_pending_definitive_fail(monkeypatch):
    _txt(monkeypatch, exc=dns.resolver.NXDOMAIN())
    rec = _rec()
    _run(dv.run_check(rec, NOW))
    assert rec.status == "failed" and rec.last_error


def test_run_check_verified_definitive_fail_revokes(monkeypatch):
    _txt(monkeypatch, exc=dns.resolver.NXDOMAIN())
    rec = _rec(status="verified", last_checked_at=NOW - timedelta(days=30))
    _run(dv.run_check(rec, NOW))
    assert rec.status == "revoked"
    assert rec.last_checked_at == NOW


def test_run_check_verified_transient_keeps_status_and_timestamp(monkeypatch):
    _txt(monkeypatch, exc=dns.exception.Timeout())
    old = NOW - timedelta(days=30)
    rec = _rec(status="verified", last_checked_at=old)
    _run(dv.run_check(rec, NOW))
    assert rec.status == "verified"
    assert rec.last_checked_at == old
    assert rec.last_error


def test_run_check_revoked_can_be_reverified(monkeypatch):
    _addrs(monkeypatch)
    _http(monkeypatch, lambda req: httpx.Response(200, text=TOKEN))
    rec = _rec(status="revoked", method="http_file")
    _run(dv.run_check(rec, NOW))
    assert rec.status == "verified" and rec.verified_at == NOW


# ── authorize_scan (DB) ──────────────────────────────────────────────────────

@pytest.fixture
def session_factory():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    _run(setup())
    yield async_sessionmaker(engine, expire_on_commit=False)
    _run(engine.dispose())


def _seed(sf, username, records=()):
    async def go():
        async with sf() as db:
            u = User(username=username, email=f"{username}@example.com", password_hash="x", role="analyst")
            db.add(u)
            await db.flush()
            for i, (domain, method, status, checked) in enumerate(records):
                db.add(DomainVerification(
                    user_id=u.id, domain=domain, method=method, token=f"{username}-{i}",
                    status=status, last_checked_at=checked,
                ))
            await db.commit()
            return u
    return _run(go())


def _authorize(sf, user, target, scan_types):
    async def go():
        async with sf() as db:
            return await dv.authorize_scan(db, user, target, scan_types, now=NOW)
    return _run(go())


def _status(sf, domain, user_id):
    async def go():
        async with sf() as db:
            return (await db.execute(select(DomainVerification.status).where(
                DomainVerification.domain == domain, DomainVerification.user_id == user_id,
            ))).scalar_one()
    return _run(go())


def _no_network(monkeypatch):
    _txt(monkeypatch, exc=AssertionError("unexpected DNS"))
    _addrs(monkeypatch, exc=AssertionError("unexpected resolve"))


FRESH = NOW - timedelta(hours=1)
STALE = NOW - timedelta(days=8)


def test_authorize_fresh_verification_no_network(session_factory, monkeypatch):
    _no_network(monkeypatch)
    u = _seed(session_factory, "alice", [("example.com", "dns_txt", "verified", FRESH)])
    d = _authorize(session_factory, u, "https://shop.example.com", ["xss", "dns"])
    assert d.ok and d.basis == "verified:dns_txt:example.com"


def test_authorize_passive_only_skips_db_and_network(session_factory, monkeypatch):
    _no_network(monkeypatch)
    u = _seed(session_factory, "alice")
    d = _authorize(session_factory, u, "anything.test", sorted(PASSIVE_CHECKS))
    assert d.ok


def test_authorize_unverified_denies_active(session_factory, monkeypatch):
    _no_network(monkeypatch)
    u = _seed(session_factory, "alice")
    d = _authorize(session_factory, u, "example.com", [])
    assert d.denied == ACTIVE_CHECKS


@pytest.mark.parametrize("status", ["pending", "failed", "revoked"])
def test_authorize_ignores_non_verified_records(session_factory, monkeypatch, status):
    _no_network(monkeypatch)
    u = _seed(session_factory, "alice", [("example.com", "dns_txt", status, FRESH)])
    assert not _authorize(session_factory, u, "example.com", ["sqli"]).ok


def test_authorize_ignores_other_users_verification(session_factory, monkeypatch):
    _no_network(monkeypatch)
    _seed(session_factory, "owner", [("example.com", "dns_txt", "verified", FRESH)])
    other = _seed(session_factory, "other")
    assert not _authorize(session_factory, other, "example.com", ["sqli"]).ok


def test_authorize_file_record_does_not_cover_subdomain(session_factory, monkeypatch):
    _no_network(monkeypatch)
    u = _seed(session_factory, "alice", [("example.com", "http_file", "verified", FRESH)])
    assert not _authorize(session_factory, u, "www.example.com", ["xss"]).ok


def test_authorize_stale_recheck_success(session_factory, monkeypatch):
    u = _seed(session_factory, "alice", [("example.com", "dns_txt", "verified", STALE)])
    _txt(monkeypatch, ["optisec-verify=alice-0"])
    assert _authorize(session_factory, u, "example.com", ["nmap"]).ok
    assert _status(session_factory, "example.com", u.id) == "verified"


def test_authorize_stale_recheck_definitive_fail_revokes_and_denies(session_factory, monkeypatch):
    u = _seed(session_factory, "alice", [("example.com", "dns_txt", "verified", STALE)])
    _txt(monkeypatch, exc=dns.resolver.NXDOMAIN())
    assert not _authorize(session_factory, u, "example.com", ["nmap"]).ok
    assert _status(session_factory, "example.com", u.id) == "revoked"


def test_authorize_stale_recheck_transient_denies_but_keeps_record(session_factory, monkeypatch):
    u = _seed(session_factory, "alice", [("example.com", "dns_txt", "verified", STALE)])
    _txt(monkeypatch, exc=dns.exception.Timeout())
    assert not _authorize(session_factory, u, "example.com", ["nmap"]).ok
    assert _status(session_factory, "example.com", u.id) == "verified"


def test_authorize_only_rechecks_records_covering_target(session_factory, monkeypatch):
    u = _seed(session_factory, "alice", [
        ("unrelated.test", "dns_txt", "verified", STALE),
        ("example.com", "dns_txt", "verified", FRESH),
    ])
    _no_network(monkeypatch)
    assert _authorize(session_factory, u, "example.com", ["xss"]).ok


def test_authorize_ttl_env_override(session_factory, monkeypatch):
    monkeypatch.setenv("SCAN_VERIFICATION_TTL_DAYS", "30")
    _no_network(monkeypatch)
    u = _seed(session_factory, "alice", [("example.com", "dns_txt", "verified", STALE)])
    assert _authorize(session_factory, u, "example.com", ["xss"]).ok


def test_authorize_training_target_without_verification(session_factory, monkeypatch):
    _no_network(monkeypatch)
    u = _seed(session_factory, "alice")
    d = _authorize(session_factory, u, "scanme.nmap.org", ["nmap"])
    assert d.ok and d.basis == "training:scanme.nmap.org"


# ── Migration ────────────────────────────────────────────────────────────────

def test_migration_creates_table_idempotently(monkeypatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    monkeypatch.setattr(migrate_module, "engine", engine)

    async def inspect_table():
        async with engine.begin() as conn:
            return await conn.run_sync(lambda c: (
                inspect(c).has_table("domain_verifications"),
                {col["name"] for col in inspect(c).get_columns("domain_verifications")}
                if inspect(c).has_table("domain_verifications") else set(),
                inspect(c).get_unique_constraints("domain_verifications")
                if inspect(c).has_table("domain_verifications") else [],
            ))
    try:
        _run(migrate_module.migrate())
        _run(migrate_module.migrate())
        exists, cols, uniques = _run(inspect_table())
        assert exists
        assert {"user_id", "domain", "method", "token", "status", "verified_at", "last_checked_at"} <= cols
        assert any(set(u["column_names"]) == {"user_id", "domain", "method"} for u in uniques)
    finally:
        _run(engine.dispose())
