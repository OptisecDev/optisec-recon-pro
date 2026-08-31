"""Tests for web/routers/federation.py's POST /api/federation/execute.

This endpoint is called by peer federation nodes to run a scan task on this
node. It does not perform any real remote execution — no scan runs, no
results ever become retrievable for the task_id it accepts — and there is
no accompanying results endpoint. This module locks in that the response
labels itself as a stub (mirrors the "simulated"/"mode" convention used by
modules/quantum/encryption.py and modules/darkweb/intelligence.py) instead
of silently claiming "accepted" as if a real job had been queued.

Follows tests/test_autonomous_rt_router.py's convention: plain pytest,
async functions driven via asyncio.run(), and calling the route handler
function directly (bypassing FastAPI's Depends resolution).
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.responses import JSONResponse

import web.license as license_module
import web.routers.federation as federation_router
from web.license import License, TIER_FEATURES
from modules.federation import federated_scan


def _run(coro):
    return asyncio.run(coro)


def _enterprise_license() -> License:
    return License(
        tier="enterprise", issued_to="test", email="",
        issued_at="2026-01-01T00:00:00", expires_at="2099-01-01T00:00:00", key="TEST",
        features=TIER_FEATURES["enterprise"], max_targets=-1, max_scans_day=-1, max_users=-1,
    )


def _free_license() -> License:
    return License(
        tier="free", issued_to="test", email="",
        issued_at="2026-01-01T00:00:00", expires_at="2099-01-01T00:00:00", key="FREE",
        features=TIER_FEATURES["free"], max_targets=1, max_scans_day=1, max_users=1,
    )


class _FakeRequest:
    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


@pytest.fixture(autouse=True)
def _fixed_node_key(monkeypatch):
    monkeypatch.setattr(federated_scan, "_node_key", lambda: "correct-node-key")


class TestFederationExecuteAuth:
    """Pre-existing behavior: transport/auth is real and must stay that way."""

    def test_missing_key_rejected(self, monkeypatch):
        monkeypatch.setattr(license_module, "get_license", _enterprise_license)
        result = _run(federation_router.federation_execute(
            _FakeRequest({"task_id": "t1", "target": "example.com"}),
            x_federation_key=None,
        ))
        assert isinstance(result, JSONResponse)
        assert result.status_code == 401

    def test_wrong_key_rejected(self, monkeypatch):
        monkeypatch.setattr(license_module, "get_license", _enterprise_license)
        result = _run(federation_router.federation_execute(
            _FakeRequest({"task_id": "t1", "target": "example.com"}),
            x_federation_key="wrong-key",
        ))
        assert isinstance(result, JSONResponse)
        assert result.status_code == 401

    def test_free_instance_license_rejects_even_with_correct_key(self, monkeypatch):
        monkeypatch.setattr(license_module, "get_license", _free_license)
        with pytest.raises(Exception) as exc_info:
            _run(federation_router.federation_execute(
                _FakeRequest({"task_id": "t1", "target": "example.com"}),
                x_federation_key="correct-node-key",
            ))
        assert getattr(exc_info.value, "status_code", None) == 402


class TestFederationExecuteIsLabeledAsStub:
    """The gap this change fixes: no real execution happens, so the response
    must say so explicitly rather than returning a bare "accepted"."""

    def test_response_is_labeled_as_stub_not_accepted(self, monkeypatch):
        monkeypatch.setattr(license_module, "get_license", _enterprise_license)
        result = _run(federation_router.federation_execute(
            _FakeRequest({
                "task_id": "task-123", "target": "example.com",
                "scan_types": ["recon", "vuln"],
            }),
            x_federation_key="correct-node-key",
        ))
        assert result["status"] != "accepted"
        assert result["status"] == "accepted_stub"
        assert "note" in result and result["note"]
        assert "unimplemented" in result["note"].lower() or "not" in result["note"].lower()

    def test_echoes_task_id_target_and_scan_types(self, monkeypatch):
        monkeypatch.setattr(license_module, "get_license", _enterprise_license)
        result = _run(federation_router.federation_execute(
            _FakeRequest({
                "task_id": "task-456", "target": "scanme.nmap.org",
                "scan_types": ["dns", "osint"],
            }),
            x_federation_key="correct-node-key",
        ))
        assert result["task_id"] == "task-456"
        assert result["target"] == "scanme.nmap.org"
        assert result["scan_types"] == ["dns", "osint"]

    def test_no_results_endpoint_exists_for_this_task(self):
        """There is deliberately no GET /api/federation/results/{task_id} —
        approach B (label the stub) was chosen instead of building a fake
        job/results pipeline with nothing real behind it. This test just
        documents that the router exposes no such route, so a future
        accidental addition doesn't silently contradict the stub label
        without this test file being revisited."""
        paths = {route.path for route in federation_router.router.routes}
        assert not any(p.endswith("/execute/results") or "/federation/results/" in p for p in paths)
