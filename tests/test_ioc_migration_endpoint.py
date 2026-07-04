"""
Tests for the TEMPORARY /internal/run-ioc-migration endpoint (web/app.py) —
a token-gated, no-shell-access way to trigger
web.migrate_add_ioc_table.migrate() on Render's free plan. Same pattern as
tests/test_migration_endpoint.py, except auth failures here return 404 (not
403) so the endpoint's existence isn't revealed to unauthenticated probes.

The "valid token" tests run the endpoint end-to-end but against a private
in-memory SQLite engine (monkeypatched onto web.migrate_add_ioc_table.engine,
same technique as tests/test_migrate_add_ioc_table.py) — never touches
data/optisec.db or any real database, and no real HTTP request is made
against production.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Must be set (via setdefault, not assignment) before web.app is imported:
# the route is only registered when the app thinks it's running in
# production, and web.app is a singleton module whose routes are registered
# at import time — whichever test file imports it first in the pytest
# session decides this for every other test file too (see the note in
# SESSION.md about test_finding_include_in_report.py / test_migration_endpoint.py).
os.environ.setdefault("GROQ_ENV", "production")

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

import web.app as app_module
import web.migrate_add_ioc_table as ioc_migrate_module

client = TestClient(app_module.app)

ENDPOINT = "/internal/run-ioc-migration"


def _fresh_sqlite_engine():
    return create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )


def test_missing_token_returns_404():
    resp = client.post(ENDPOINT)
    assert resp.status_code == 404


def test_wrong_token_returns_404(monkeypatch):
    monkeypatch.setenv("IOC_MIGRATION_TOKEN", "the-real-secret")
    resp = client.post(ENDPOINT, headers={"X-Migration-Token": "not-the-real-secret"})
    assert resp.status_code == 404


def test_no_secret_configured_returns_404(monkeypatch):
    monkeypatch.delenv("IOC_MIGRATION_TOKEN", raising=False)
    resp = client.post(ENDPOINT, headers={"X-Migration-Token": "anything"})
    assert resp.status_code == 404


def test_valid_token_runs_migration_against_temporary_sqlite(monkeypatch):
    test_engine = _fresh_sqlite_engine()
    monkeypatch.setattr(ioc_migrate_module, "engine", test_engine)
    monkeypatch.setenv("IOC_MIGRATION_TOKEN", "test-secret-token")

    resp = client.post(ENDPOINT, headers={"X-Migration-Token": "test-secret-token"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["created"] is True
    assert body["table"] == "iocs"
    assert "ioc_type" in body["columns"]
    assert "ioc_value" in body["columns"]

    asyncio.run(test_engine.dispose())


def test_valid_token_second_call_is_idempotent(monkeypatch):
    test_engine = _fresh_sqlite_engine()
    monkeypatch.setattr(ioc_migrate_module, "engine", test_engine)
    monkeypatch.setenv("IOC_MIGRATION_TOKEN", "test-secret-token-2")

    headers = {"X-Migration-Token": "test-secret-token-2"}
    first = client.post(ENDPOINT, headers=headers)
    second = client.post(ENDPOINT, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["created"] is True
    assert second.json()["created"] is False
    assert second.json()["table"] == "iocs"

    asyncio.run(test_engine.dispose())


def test_response_contains_no_sensitive_data(monkeypatch):
    test_engine = _fresh_sqlite_engine()
    monkeypatch.setattr(ioc_migrate_module, "engine", test_engine)
    monkeypatch.setenv("IOC_MIGRATION_TOKEN", "another-test-secret")

    resp = client.post(ENDPOINT, headers={"X-Migration-Token": "another-test-secret"})

    assert resp.status_code == 200
    raw_body = resp.text
    assert "another-test-secret" not in raw_body
    assert "sqlite" not in raw_body.lower()
    assert "DATABASE_URL" not in raw_body
    assert "postgres" not in raw_body.lower()
    # Only table/column/index/constraint names — no row data or connection info.
    assert set(resp.json().keys()) == {
        "success", "created", "table", "columns", "indexes", "constraints",
    }

    asyncio.run(test_engine.dispose())
