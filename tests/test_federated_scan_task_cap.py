"""
Tests that modules/federation/federated_scan.py caps fed["tasks"] instead
of growing it forever.

dispatch_scan() and _local_fallback_scan() used to append to fed["tasks"]
with no trimming, unlike the equivalent history lists in
modules/ai_advanced/{zero_day,red_team}.py (capped at 100/50). Every
federation operation (ping, dispatch, register, remove, list) does a full
read-modify-write of the whole federation.json, so an unbounded tasks list
makes every one of those operations slower as more scans get dispatched.

Follows tests/test_federated_scan_stubs.py's convention: monkeypatched
on-disk store via the _isolated_federation_db fixture, async functions
driven via asyncio.run().
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modules.federation import federated_scan as fed


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolated_federation_db(tmp_path, monkeypatch):
    monkeypatch.setattr(fed, "FEDERATION_DB", tmp_path / "federation.json")
    monkeypatch.setattr(fed, "NODE_KEY_FILE", tmp_path / "federation_node.key")


class TestLocalFallbackScanCapsTasks:
    def test_task_count_never_exceeds_max(self, monkeypatch):
        monkeypatch.setattr(fed, "MAX_STORED_TASKS", 5)
        for i in range(10):
            _run(fed.dispatch_scan(target=f"target-{i}.example.com", scan_types=["recon"]))
        assert len(fed.list_tasks()) == 5

    def test_most_recent_tasks_are_kept(self, monkeypatch):
        monkeypatch.setattr(fed, "MAX_STORED_TASKS", 3)
        for i in range(5):
            _run(fed.dispatch_scan(target=f"target-{i}.example.com", scan_types=["recon"]))
        targets = [t["target"] for t in fed.list_tasks()]
        assert targets == ["target-2.example.com", "target-3.example.com", "target-4.example.com"]


class TestDispatchScanCapsTasks:
    def test_task_count_never_exceeds_max_with_online_peer(self, monkeypatch):
        monkeypatch.setattr(fed, "MAX_STORED_TASKS", 4)
        fed.register_peer(name="Peer", endpoint="https://peer.example.com", api_key="k")
        node_id = fed.list_nodes()[0]["id"]

        async def fake_send_to_nodes(task_id, target, assignments, nodes):
            return [{"node_id": node_id, "status": "dispatched", "response": {}}]

        monkeypatch.setattr(fed, "_send_to_nodes", fake_send_to_nodes)

        fed_data = fed._load_federation()
        fed_data["nodes"][0]["status"] = "online"
        fed._save_federation(fed_data)

        for i in range(8):
            _run(fed.dispatch_scan(target=f"target-{i}.example.com", scan_types=["recon"]))

        assert len(fed.list_tasks()) == 4
        assert fed.list_tasks()[-1]["target"] == "target-7.example.com"
