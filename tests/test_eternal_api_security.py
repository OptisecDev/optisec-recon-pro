"""Tests for Eternal Core (app/, port 8100) item A: /api/v1/scan,
/api/v1/history/{id}, /api/v1/simulate/{id} and /api/v1/audit/logs
previously had zero auth and zero rate limiting. They now share the
existing _require_admin (HTTP Basic, AUDIT_LOG_ADMIN_PASSWORD) dependency
plus a per-IP sliding-window rate limit (app/core/rate_limit.py).

DB/network-touching collaborators (get_eternal_db, scan_email,
simulate_attack_chain, query_timeline, save_active) are stubbed so these
tests exercise only the auth/rate-limit wiring, no live Postgres/MinIO.
"""
import base64
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import endpoints as ep
from app.core import rate_limit
from app.core.config import AUDIT_LOG_ADMIN_PASSWORD
from app.db.session import get_eternal_db
from app.main import app


class _FakeResult:
    def scalars(self):
        return self

    def all(self):
        return []


class _FakeSession:
    def add(self, obj):
        # Mirrors what a real flush/commit would assign via the column's
        # default=uuid.uuid4 -- this fake never touches a real engine.
        if getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()

    async def flush(self):
        pass

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass

    async def get(self, model, target_id):
        return object()

    async def execute(self, stmt):
        return _FakeResult()


async def _override_get_eternal_db():
    yield _FakeSession()


def _basic_auth_header(password: str) -> dict:
    token = base64.b64encode(f"admin:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def client(monkeypatch):
    assert AUDIT_LOG_ADMIN_PASSWORD, (
        "AUDIT_LOG_ADMIN_PASSWORD must be set in .env.eternal for this test run"
    )
    rate_limit._requests.clear()

    async def _fake_scan_email(value):
        return {"source": "mock_fallback", "breaches": []}

    async def _fake_simulate(target_id):
        return []

    async def _fake_query_timeline(target_id, db):
        return []

    async def _fake_save_active(record, db):
        return record

    monkeypatch.setattr(ep, "scan_email", _fake_scan_email)
    monkeypatch.setattr(ep, "simulate_attack_chain", _fake_simulate)
    monkeypatch.setattr(ep, "query_timeline", _fake_query_timeline)
    monkeypatch.setattr(ep, "save_active", _fake_save_active)

    app.dependency_overrides[get_eternal_db] = _override_get_eternal_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    rate_limit._requests.clear()


# ─── auth ────────────────────────────────────────────────────────────────

def test_scan_rejects_missing_auth(client):
    resp = client.post("/api/v1/scan", json={"type": "email", "value": "a@example.com"})
    assert resp.status_code == 401


def test_scan_rejects_wrong_password(client):
    resp = client.post(
        "/api/v1/scan",
        json={"type": "email", "value": "a@example.com"},
        headers=_basic_auth_header("wrong-password"),
    )
    assert resp.status_code == 401


def test_scan_accepts_valid_auth(client):
    resp = client.post(
        "/api/v1/scan",
        json={"type": "email", "value": "a@example.com"},
        headers=_basic_auth_header(AUDIT_LOG_ADMIN_PASSWORD),
    )
    assert resp.status_code == 200


def test_history_rejects_missing_auth(client):
    resp = client.get(f"/api/v1/history/{uuid.uuid4()}")
    assert resp.status_code == 401


def test_history_accepts_valid_auth(client):
    resp = client.get(
        f"/api/v1/history/{uuid.uuid4()}", headers=_basic_auth_header(AUDIT_LOG_ADMIN_PASSWORD)
    )
    assert resp.status_code == 200


def test_simulate_rejects_missing_auth(client):
    resp = client.post(f"/api/v1/simulate/{uuid.uuid4()}")
    assert resp.status_code == 401


def test_simulate_accepts_valid_auth(client):
    resp = client.post(
        f"/api/v1/simulate/{uuid.uuid4()}", headers=_basic_auth_header(AUDIT_LOG_ADMIN_PASSWORD)
    )
    assert resp.status_code == 200


def test_audit_logs_still_rejects_missing_auth(client):
    resp = client.get("/api/v1/audit/logs")
    assert resp.status_code == 401


def test_audit_logs_still_accepts_valid_auth(client):
    resp = client.get("/api/v1/audit/logs", headers=_basic_auth_header(AUDIT_LOG_ADMIN_PASSWORD))
    assert resp.status_code == 200


# ─── rate limiting ─────────────────────────────────────────────────────────

def test_scan_rate_limited_after_max_requests(client):
    headers = _basic_auth_header(AUDIT_LOG_ADMIN_PASSWORD)
    payload = {"type": "email", "value": "a@example.com"}

    for _ in range(rate_limit.RATE_LIMIT_MAX):
        resp = client.post("/api/v1/scan", json=payload, headers=headers)
        assert resp.status_code == 200

    resp = client.post("/api/v1/scan", json=payload, headers=headers)
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


def test_rate_limit_is_independent_of_auth_check(client):
    """An unauthenticated flood also gets capped, not just authenticated calls."""
    for _ in range(rate_limit.RATE_LIMIT_MAX):
        resp = client.get(f"/api/v1/history/{uuid.uuid4()}")
        assert resp.status_code == 401

    resp = client.get(f"/api/v1/history/{uuid.uuid4()}")
    assert resp.status_code == 429
