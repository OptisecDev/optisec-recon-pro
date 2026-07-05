"""
Tests for the TEMPORARY /internal/run-api-key-migration endpoint (web/app.py)
— a token-gated, no-shell-access way to trigger
web.migrate_add_api_key_hash.migrate() on Render's free plan.

Only checks the auth guard (wrong/missing token -> 404, mirroring
/internal/run-ioc-migration so the endpoint's existence isn't revealed).
Does not exercise the actual migration logic here — that's covered by
running the script directly against a real DB, and by
web/migrate_add_api_key_hash.py being a thin, already-reviewed migration.
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


def test_missing_token_returns_404():
    resp = client.post("/internal/run-api-key-migration")
    assert resp.status_code == 404


def test_wrong_token_returns_404(monkeypatch):
    monkeypatch.setenv("API_KEY_MIGRATION_TOKEN", "the-real-secret")
    resp = client.post(
        "/internal/run-api-key-migration",
        headers={"X-Migration-Token": "not-the-real-secret"},
    )
    assert resp.status_code == 404


def test_no_secret_configured_returns_404(monkeypatch):
    monkeypatch.delenv("API_KEY_MIGRATION_TOKEN", raising=False)
    resp = client.post(
        "/internal/run-api-key-migration",
        headers={"X-Migration-Token": "anything"},
    )
    assert resp.status_code == 404
