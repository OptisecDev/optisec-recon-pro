"""Tests for web.app._extract_and_store_iocs() — the non-blocking hook that
mines IOCs (modules/ioc/ioc_engine.py::extract_iocs_from_finding) out of
every Finding saved after a scan (XSS/SQLi/SSRF/LFI/Open Redirect) and
persists them via IOCRepository, added alongside GET /api/iocs.

Uses a real in-memory SQLite DB (same fixture convention as
tests/test_ioc_engine.py / tests/test_honeypot.py) — no mocking of the DB
layer. Only modules.ioc.ioc_engine.IOCEngine.extract_iocs_from_finding is
monkeypatched, and only in the one test that verifies the non-blocking
guarantee.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# web.app is a module-level singleton (route registration happens at import
# time) — see tests/test_finding_include_in_report.py for why this env var
# must be set before the first import of web.app in the pytest session.
os.environ.setdefault("GROQ_ENV", "production")

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.app as app_module
from web.database import Base
from web.models import Finding
from modules.ioc.ioc_engine import IOCRepository


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


def _finding_row(**overrides) -> Finding:
    defaults = dict(
        scan_id="scan-1", target_id=None, vuln_type="SSRF", severity="Critical",
        url="https://myapp.example/fetch?url=x", parameter="url", payload="x",
        evidence="Outbound connection observed to 8.8.8.8 before timeout",
        waf_detected=None, verdict="CONFIRMED", include_in_report=True,
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestExtractAndStoreIocs:
    def test_mines_and_persists_ioc_linked_to_finding(self, db_factory):
        async def go():
            async with db_factory() as db:
                row = _finding_row()
                db.add(row)
                await db.flush()
                finding_id = row.id

                v = {"type": row.vuln_type, "url": row.url, "evidence": row.evidence}
                await app_module._extract_and_store_iocs(db, [(row, v)])
                await db.commit()

                repo = IOCRepository(db)
                stored = await repo.get_by_value("ip", "8.8.8.8")
                return finding_id, stored
        finding_id, stored = _run(go())

        assert stored is not None
        assert stored.source == "scan_finding"
        assert stored.related_finding_id == finding_id
        assert stored.tags == ["vuln_type:SSRF"]

    def test_no_candidates_leaves_ioc_table_empty(self, db_factory):
        async def go():
            async with db_factory() as db:
                row = _finding_row(evidence="", vuln_type="XSS")
                db.add(row)
                await db.flush()
                v = {"type": row.vuln_type, "url": row.url, "evidence": row.evidence}
                await app_module._extract_and_store_iocs(db, [(row, v)])
                await db.commit()

                repo = IOCRepository(db)
                return await repo.list_active()
        rows = _run(go())
        assert rows == []

    def test_extraction_failure_does_not_raise_or_block_finding_commit(self, db_factory, monkeypatch):
        def boom(self, finding):
            raise RuntimeError("simulated extraction failure")

        monkeypatch.setattr(
            "modules.ioc.ioc_engine.IOCEngine.extract_iocs_from_finding", boom,
        )

        async def go():
            async with db_factory() as db:
                row = _finding_row()
                db.add(row)
                await db.flush()
                finding_id = row.id

                v = {"type": row.vuln_type, "url": row.url, "evidence": row.evidence}
                # Must not raise, even though extract_iocs_from_finding blows up.
                await app_module._extract_and_store_iocs(db, [(row, v)])
                await db.commit()
                return finding_id
        finding_id = _run(go())
        assert finding_id is not None  # Finding row itself was saved fine

    def test_one_bad_finding_does_not_stop_the_rest_from_being_mined(self, db_factory, monkeypatch):
        from modules.ioc.ioc_engine import IOCEngine
        original = IOCEngine.extract_iocs_from_finding

        def flaky(self, finding):
            if finding.get("evidence") == "TRIGGER_BAD":
                raise RuntimeError("simulated extraction failure")
            return original(self, finding)

        monkeypatch.setattr(IOCEngine, "extract_iocs_from_finding", flaky)

        async def go():
            async with db_factory() as db:
                bad_row = _finding_row(evidence="TRIGGER_BAD")
                good_row = _finding_row(evidence="Outbound connection observed to 9.9.9.9 before timeout")
                db.add(bad_row)
                db.add(good_row)
                await db.flush()

                bad_v = {"type": "SSRF", "url": bad_row.url, "evidence": bad_row.evidence}
                good_v = {"type": "SSRF", "url": good_row.url, "evidence": good_row.evidence}
                await app_module._extract_and_store_iocs(
                    db, [(bad_row, bad_v), (good_row, good_v)],
                )
                await db.commit()

                repo = IOCRepository(db)
                return await repo.get_by_value("ip", "9.9.9.9")
        stored = _run(go())
        assert stored is not None
