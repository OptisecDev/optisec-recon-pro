"""Tests for the stub-labeling fixes in modules/federation/federated_scan.py.

Companion to tests/test_federation_execute_stub.py (which covers the
peer-facing POST /api/federation/execute endpoint). This file covers the
two sibling stub bugs found in the same module:

- _local_fallback_scan(): used to claim "scan will run locally" and set
  status="local" without ever invoking any scan module or exposing any
  path that later executes the task.
- collect_results(): used to silently drop any peer that didn't return
  200 (instead of recording why), and always set status="completed" even
  when zero real results were retrieved -- indistinguishable from a
  genuine clean scan.

Follows tests/test_geo_intel.py's convention for faking httpx.AsyncClient,
and tests/test_autonomous_rt_router.py's convention for driving async
functions via asyncio.run() with a monkeypatched on-disk store.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import pytest

from modules.federation import federated_scan as fed


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolated_federation_db(tmp_path, monkeypatch):
    monkeypatch.setattr(fed, "FEDERATION_DB", tmp_path / "federation.json")
    monkeypatch.setattr(fed, "NODE_KEY_FILE", tmp_path / "federation_node.key")


class _FakeHttpResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}

    def json(self):
        return self._json_data


class _FakeAsyncClient:
    def __init__(self, response=None, raise_exc=None, **kw):
        self._response = response
        self._raise_exc = raise_exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        if self._raise_exc:
            raise self._raise_exc
        return self._response


class TestLocalFallbackScanIsLabeledAsStub:
    def test_status_is_not_executed_stub_not_local(self):
        result = _run(fed._local_fallback_scan(
            "task-1", "example.com", ["dns"], fed._load_federation(),
        ))
        assert result["status"] == "not_executed_stub"

    def test_note_does_not_falsely_promise_execution(self):
        result = _run(fed._local_fallback_scan(
            "task-2", "example.com", ["dns"], fed._load_federation(),
        ))
        note = result["note"].lower()
        assert "will run locally" not in note
        assert "not" in note and ("implemented" in note or "run" in note)

    def test_task_is_persisted(self):
        _run(fed._local_fallback_scan("task-3", "example.com", ["dns"], fed._load_federation()))
        tasks = fed.list_tasks()
        assert any(t["task_id"] == "task-3" for t in tasks)


class TestCollectResultsHonestlyLabelsEmptyOutcomes:
    def _seed_task_with_one_node(self, node_status="online"):
        f = fed._load_federation()
        f["nodes"].append({
            "id": "node-a", "name": "Node A", "endpoint": "http://peer.example",
            "api_key": "k", "status": node_status, "capabilities": ["recon"], "region": "r",
        })
        f["tasks"].append({
            "task_id": "task-x", "target": "example.com", "scan_types": ["recon"],
            "status": "running",
            "assignments": [{"node_id": "node-a", "node_name": "Node A", "scan_types": ["recon"]}],
        })
        fed._save_federation(f)

    def test_offline_node_recorded_not_silently_dropped(self):
        self._seed_task_with_one_node(node_status="offline")
        result = _run(fed.collect_results("task-x"))
        assert len(result["node_results"]) == 1
        assert "error" in result["node_results"][0]

    def test_status_is_completed_stub_when_peer_has_no_results_endpoint(self, monkeypatch):
        self._seed_task_with_one_node(node_status="online")
        fake = _FakeAsyncClient(_FakeHttpResponse(404))
        monkeypatch.setattr(fed.httpx, "AsyncClient", lambda *a, **kw: fake)
        result = _run(fed.collect_results("task-x"))
        assert result["results"]["note"]
        tasks = fed.list_tasks()
        task = next(t for t in tasks if t["task_id"] == "task-x")
        assert task["status"] == "completed_stub"

    def test_status_is_completed_stub_on_connection_error(self, monkeypatch):
        self._seed_task_with_one_node(node_status="online")
        fake = _FakeAsyncClient(raise_exc=httpx.ConnectError("refused"))
        monkeypatch.setattr(fed.httpx, "AsyncClient", lambda *a, **kw: fake)
        result = _run(fed.collect_results("task-x"))
        assert "error" in result["node_results"][0]
        tasks = fed.list_tasks()
        task = next(t for t in tasks if t["task_id"] == "task-x")
        assert task["status"] == "completed_stub"

    def test_status_stays_completed_when_peer_returns_real_data(self, monkeypatch):
        self._seed_task_with_one_node(node_status="online")
        real = {"findings": [{"vuln_type": "xss", "url": "http://x", "parameter": "q"}], "subdomains": ["a.example.com"]}
        fake = _FakeAsyncClient(_FakeHttpResponse(200, real))
        monkeypatch.setattr(fed.httpx, "AsyncClient", lambda *a, **kw: fake)
        result = _run(fed.collect_results("task-x"))
        assert "note" not in result["results"]
        assert result["results"]["total_findings"] == 1
        tasks = fed.list_tasks()
        task = next(t for t in tasks if t["task_id"] == "task-x")
        assert task["status"] == "completed"
