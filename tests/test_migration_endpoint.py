"""
Tests for the TEMPORARY /internal/run-migration endpoint (web/app.py) —
a token-gated, no-shell-access way to trigger
web.migrate_normalize_demo_severity.migrate() on Render's free plan.

Only checks the auth guard (wrong/missing token -> 403). Does not exercise
the actual migration logic here — that's covered by running the script
directly against a real DB, and by web/migrate_normalize_demo_severity.py
being a thin, already-reviewed data UPDATE.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Must be set before web.app is imported: the route is only registered
# when the app thinks it's running in production.
os.environ["GROQ_ENV"] = "production"

from fastapi.testclient import TestClient

import web.app as app_module

client = TestClient(app_module.app)


def test_missing_token_returns_403():
    resp = client.post("/internal/run-migration")
    assert resp.status_code == 403


def test_wrong_token_returns_403(monkeypatch):
    monkeypatch.setenv("MIGRATION_SECRET_TOKEN", "the-real-secret")
    resp = client.post(
        "/internal/run-migration",
        headers={"X-Migration-Token": "not-the-real-secret"},
    )
    assert resp.status_code == 403


def test_no_secret_configured_returns_403(monkeypatch):
    monkeypatch.delenv("MIGRATION_SECRET_TOKEN", raising=False)
    resp = client.post(
        "/internal/run-migration",
        headers={"X-Migration-Token": "anything"},
    )
    assert resp.status_code == 403
