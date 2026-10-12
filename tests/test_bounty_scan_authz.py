"""Authorization coverage for the standalone bounty-scan scripts
(scripts/bounty_scan*.py).

Each script runs active checks (XSS/SSRF/LFI, a TCP port preflight, and —
for chime/saltlabs — GraphQL introspection) against real third-party hosts.
After the security hardening they no longer carry a self-granted
ALLOWED_TARGETS allowlist: every host must clear the same gate /api/scan
uses (web.domain_verification.check_scan_authorization) before any
connection, via each script's authorize_host().

What's under test, per script:
  * an unverified target is REFUSED (SystemExit, non-zero) before any
    network connection is attempted — socket.create_connection is replaced
    with a fake that fails the test if it is ever called;
  * a target covered by the running user's DNS-TXT-verified domain is
    ACCEPTED and yields a ScanScope confined to that domain;
  * any error performing the authorization query REFUSES the scan
    (fail-closed), again before any connection.

No real network: the DNS TXT re-check and the scope resolver are faked.
"""

import asyncio
import importlib.util
import os
import socket
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import modules.scan_scope as scan_scope_module
import web.domain_verification as dv
from web.database import Base
from web.models import DomainVerification, User

_SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")

# (module filename, an in-scope host, the domain the user verifies to cover it)
SCRIPTS = [
    ("bounty_scan", "blog.verisign.com", "verisign.com"),
    ("bounty_scan_chime", "app.chime.com", "chime.com"),
    ("bounty_scan_saltlabs", "app.staging.saltlabs.com", "saltlabs.com"),
]


def _load(name):
    spec = importlib.util.spec_from_file_location(
        f"_bounty_under_test_{name}", os.path.join(_SCRIPTS_DIR, f"{name}.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Keep the scope resolver offline, and make any real TCP connection a
    hard test failure — the authorization gate must decide before any
    connection to the target."""
    monkeypatch.setattr(scan_scope_module, "_resolve", lambda host: {"93.184.216.34"})

    def _boom(*a, **k):
        raise AssertionError("a real network connection was attempted before/despite authorization")

    monkeypatch.setattr(socket, "create_connection", _boom)
    yield


@pytest.fixture
def db_factory():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    sf = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    _run(setup())
    yield sf
    _run(engine.dispose())


def _make_user(sf, verified=()):
    async def go():
        async with sf() as db:
            u = User(
                username="alice", email="alice@example.com", password_hash="x",
                role="analyst", subscription_tier="enterprise", is_active=True,
            )
            db.add(u)
            await db.flush()
            for domain in verified:
                db.add(DomainVerification(
                    user_id=u.id, domain=domain, method="dns_txt", token=f"tok-{domain}",
                    status="verified", verified_at=datetime.utcnow(), last_checked_at=datetime.utcnow(),
                ))
            await db.commit()
            return u.id
    return _run(go())


@pytest.mark.parametrize("name,host,domain", SCRIPTS)
def test_unverified_target_refused_before_any_connection(db_factory, name, host, domain):
    mod = _load(name)
    uid = _make_user(db_factory)  # no verified domains

    async def go():
        async with db_factory() as db:
            user = await db.get(User, uid)
            await mod.authorize_host(db, user, host)

    with pytest.raises(SystemExit) as exc:
        _run(go())
    assert exc.value.code == 1


@pytest.mark.parametrize("name,host,domain", SCRIPTS)
def test_verified_target_accepted(db_factory, monkeypatch, name, host, domain):
    mod = _load(name)
    uid = _make_user(db_factory, verified=[domain])

    async def txt_published(d, token):
        return dv.CheckResult(True)
    monkeypatch.setattr(dv, "check_dns_txt", txt_published)

    async def go():
        async with db_factory() as db:
            user = await db.get(User, uid)
            return await mod.authorize_host(db, user, host)

    scope = _run(go())
    assert isinstance(scope, scan_scope_module.ScanScope)
    assert scope.allows(host)
    assert not scope.allows("evil.test")


@pytest.mark.parametrize("name,host,domain", SCRIPTS)
def test_query_failure_refuses(db_factory, monkeypatch, name, host, domain):
    mod = _load(name)
    uid = _make_user(db_factory, verified=[domain])

    async def boom(*a, **k):
        raise RuntimeError("DB/authorization query failed")
    # The same gate /api/scan uses, as this script imported it.
    monkeypatch.setattr(mod, "check_scan_authorization", boom)

    async def go():
        async with db_factory() as db:
            user = await db.get(User, uid)
            await mod.authorize_host(db, user, host)

    with pytest.raises(SystemExit) as exc:
        _run(go())
    assert exc.value.code == 1
