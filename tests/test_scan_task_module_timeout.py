"""Test for the orchestration-level per-step timeout in
web.app._run_scan_task (the fix for sequential scan modules hanging with
no orchestration-level timeout).

Each of the 13 scan steps is wrapped in asyncio.wait_for(...); on timeout
the step's stored result becomes {"error": "module_timeout",
"timeout_seconds": N} instead of the scan task blocking forever, and the
loop continues on to the remaining steps. This test simulates one module
hanging past its timeout and confirms both that its result carries the
module_timeout marker and that the other (fast) steps still complete
normally in the same scan.

Follows tests/test_ioc_scan_integration.py's convention for an in-memory
SQLite db_factory fixture and monkeypatching web.app's module-level
singletons.
"""

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("GROQ_ENV", "production")

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.app as app_module
from web.database import Base
from web.models import Scan


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def db_factory():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())
    yield session_factory
    _run(engine.dispose())


class TestModuleTimeoutIsolatesOneStep:
    def test_one_hung_module_times_out_without_blocking_the_rest(self, db_factory, monkeypatch):
        scan_id = "scan-timeout-1"

        async def _seed():
            async with db_factory() as db:
                db.add(Scan(
                    id=scan_id, user_id=1, target_url="example.com",
                    scan_types=["subdomain", "dns", "whois"], status="pending",
                ))
                await db.commit()
        _run(_seed())

        monkeypatch.setattr(app_module, "SessionLocal", db_factory)

        async def _noop_broadcast(scan_id, data):
            return None
        monkeypatch.setattr(app_module.ws_manager, "broadcast", _noop_broadcast)

        # Clamp every wait_for's timeout to 0.05s so the deliberately-hung
        # module (real timeout=40s per _run_scan_task) times out almost
        # instantly here, without touching the timeout values the app
        # actually passes.
        real_wait_for = asyncio.wait_for

        async def _fast_wait_for(aw, timeout):
            return await real_wait_for(aw, timeout=min(timeout, 0.05))

        monkeypatch.setattr(asyncio, "wait_for", _fast_wait_for)

        def hung_enumerate_subdomains(domain):
            time.sleep(0.3)
            return {"subdomains": ["should-not-appear"]}

        def fast_dns_lookup(domain):
            return {"records": ["1.2.3.4"]}

        def fast_whois_lookup(domain):
            return {"registrar": "Example Registrar"}

        monkeypatch.setattr(app_module, "enumerate_subdomains", hung_enumerate_subdomains)
        monkeypatch.setattr(app_module, "dns_lookup", fast_dns_lookup)
        monkeypatch.setattr(app_module, "whois_lookup", fast_whois_lookup)

        _run(app_module._run_scan_task(
            scan_id, "example.com", ["subdomain", "dns", "whois"],
            user_id=1, target_id=None,
        ))

        async def _read():
            async with db_factory() as db:
                return await db.get(Scan, scan_id)
        scan = _run(_read())

        assert scan.status == "done"
        assert scan.results["subdomains"] == {
            "error": "module_timeout", "timeout_seconds": 40,
        }
        assert scan.results["dns"] == {"records": ["1.2.3.4"]}
        assert scan.results["whois"] == {"registrar": "Example Registrar"}
