"""IDOR tests for the report-generation/download flow in web/app.py.

Found during the 2026-09-01 cross-user IDOR/privilege-escalation audit
(read-only Phase 1 review of every client-supplied resource identifier).
Two confirmed gaps, both in the same feature:

1. POST /api/report (create_report): the client-supplied `scan_id` is
   looked up with `select(Scan).where(Scan.id == scan_id)` -- no
   `Scan.user_id == user.id` filter, unlike every other scan_id lookup in
   this file (GET /api/scan/{scan_id}, the /ws/scan/{scan_id} websocket,
   POST /api/scan's own target_id resolution). Any authenticated user can
   pass another user's scan_id and get a PDF built from that victim's
   recon/vulnerability data, saved as a Report row they own.

2. GET /reports/download/{filename}: only checks the file exists on disk
   -- never queries the `Report` table's `user_id` column at all, even
   though `Report.user_id` exists specifically for this purpose (see the
   correctly-scoped GET /reports page a few lines above it in app.py).

Same TestClient + real-JWT-cookie + DB-seeded-user convention as
tests/test_license_feature_gate.py's full-stack layer, so two distinct
authenticated identities can be exercised naturally through the real HTTP
stack (dependency_overrides only replaces get_db; each request carries its
own user's real access_token cookie).
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
from web.models import User, Scan, Report
from web.auth import hash_password, create_access_token
import web.app as app_module


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Reports write to config.REPORTS_DIR / <generated pdf> -- isolate to
    # tmp_path so this test never touches the real project's data/reports/.
    monkeypatch.setattr(app_module, "REPORTS_DIR", tmp_path)

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

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db

    c = TestClient(app_module.app)
    yield c, session_factory

    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def _seed_user(session_factory, username: str, role: str = "analyst") -> tuple[int, str]:
    async def go():
        async with session_factory() as db:
            user = User(
                username=username, email=f"{username}@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role=role, subscription_tier="enterprise", is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id
    user_id = _run(go())
    return user_id, create_access_token(user_id, role)


def _seed_scan(session_factory, owner_id: int, scan_id: str) -> None:
    async def go():
        async with session_factory() as db:
            db.add(Scan(
                id=scan_id, user_id=owner_id, target_url="https://victim-secret.example.com",
                status="done", progress=100,
                results={"vulnerabilities": [{"type": "SQLi", "url": "https://victim-secret.example.com/x"}]},
            ))
            await db.commit()
    _run(go())


def _seed_report(session_factory, owner_id: int, filename: str) -> None:
    async def go():
        async with session_factory() as db:
            db.add(Report(user_id=owner_id, filename=filename, file_path=f"/tmp/{filename}"))
            await db.commit()
    _run(go())


class TestCreateReportScanOwnership:
    """POST /api/report must refuse to build a report from a scan_id the
    caller doesn't own."""

    def test_attacker_cannot_generate_report_from_victims_scan(self, client, monkeypatch):
        c, session_factory = client
        victim_id, _ = _seed_user(session_factory, "victim")
        attacker_id, attacker_token = _seed_user(session_factory, "attacker")
        _seed_scan(session_factory, victim_id, "scan_victim_001")

        resp = c.post(
            "/api/report",
            json={"target": "https://victim-secret.example.com", "scan_id": "scan_victim_001"},
            cookies={"access_token": attacker_token},
        )
        # Documented pre-fix behavior: 200, PDF built from victim's scan
        # data, filename/path handed straight back to the attacker.
        assert resp.status_code in (403, 404), (
            f"IDOR: attacker generated a report from another user's scan_id "
            f"(status={resp.status_code}, body={resp.text[:300]})"
        )

    def test_owner_can_generate_report_from_own_scan(self, client, monkeypatch):
        c, session_factory = client
        owner_id, owner_token = _seed_user(session_factory, "owner1")
        _seed_scan(session_factory, owner_id, "scan_owner_001")

        resp = c.post(
            "/api/report",
            json={"target": "https://mine.example.com", "scan_id": "scan_owner_001"},
            cookies={"access_token": owner_token},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True


class TestDownloadReportOwnership:
    """GET /reports/download/{filename} must refuse to serve a PDF the
    caller doesn't own."""

    def test_attacker_cannot_download_victims_report(self, client, tmp_path):
        c, session_factory = client
        victim_id, _ = _seed_user(session_factory, "victim2")
        attacker_id, attacker_token = _seed_user(session_factory, "attacker2")

        filename = "optisec_report_victim_20260101_000000.pdf"
        (tmp_path / filename).write_bytes(b"%PDF-1.4 fake victim report")
        _seed_report(session_factory, victim_id, filename)

        resp = c.get(f"/reports/download/{filename}", cookies={"access_token": attacker_token})
        assert resp.status_code == 404, (
            f"IDOR: attacker downloaded another user's report PDF by filename "
            f"(status={resp.status_code})"
        )

    def test_owner_can_download_own_report(self, client, tmp_path):
        c, session_factory = client
        owner_id, owner_token = _seed_user(session_factory, "owner2")

        filename = "optisec_report_mine_20260101_000000.pdf"
        (tmp_path / filename).write_bytes(b"%PDF-1.4 fake own report")
        _seed_report(session_factory, owner_id, filename)

        resp = c.get(f"/reports/download/{filename}", cookies={"access_token": owner_token})
        assert resp.status_code == 200

    def test_admin_can_download_any_report(self, client, tmp_path):
        c, session_factory = client
        victim_id, _ = _seed_user(session_factory, "victim3")
        admin_id, admin_token = _seed_user(session_factory, "admin3", role="admin")

        filename = "optisec_report_admin_view_20260101_000000.pdf"
        (tmp_path / filename).write_bytes(b"%PDF-1.4 fake admin-viewable report")
        _seed_report(session_factory, victim_id, filename)

        resp = c.get(f"/reports/download/{filename}", cookies={"access_token": admin_token})
        assert resp.status_code == 200
