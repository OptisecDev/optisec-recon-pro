"""
Tests that web/routers/federation.py never returns a node's `api_key` to a
non-admin-only endpoint.

`api_key` on a registered peer node (modules/federation/federated_scan.py's
register_peer()) or on this instance's own `this_node` (initialize_node())
is the exact secret sent as the X-Federation-Key header to authenticate as
that node. POST /api/initialize already stripped it before returning
("# Don't expose API key"), but GET /api/nodes and GET /api/this-node --
both reachable by any user with the `federation` entitlement, not just
admin -- returned it unfiltered: any ENTERPRISE-tier user could read every
registered peer's key (and this node's own key) and use it to authenticate
as this platform against a partner's federation node, or forge incoming
federation calls to this instance.

Follows tests/test_federation_execute_stub.py's convention: call the route
handler functions directly (bypassing FastAPI's Depends resolution) with a
plain in-memory User, rather than a full TestClient + DB setup.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import web.routers.federation as federation_router
from web.models import User
from modules.federation import federated_scan as fed


def _run(coro):
    return asyncio.run(coro)


def _enterprise_user() -> User:
    return User(
        id=1, username="enterprise-user", email="u@example.com", password_hash="x",
        role="analyst", is_active=True, api_key_hash="unused", subscription_tier="enterprise",
    )


class _FakeRequest:
    async def json(self):
        return {}


@pytest.fixture(autouse=True)
def _isolated_federation_db(tmp_path, monkeypatch):
    monkeypatch.setattr(fed, "FEDERATION_DB", tmp_path / "federation.json")
    monkeypatch.setattr(fed, "NODE_KEY_FILE", tmp_path / "federation_node.key")


@pytest.fixture(autouse=True)
def _seeded_nodes():
    fed.initialize_node(name="This Node", endpoint="https://this.example.com")
    fed.register_peer(name="Peer One", endpoint="https://peer1.example.com", api_key="peer-1-secret-key")
    fed.register_peer(name="Peer Two", endpoint="https://peer2.example.com", api_key="peer-2-secret-key")


class TestListNodesApiDoesNotLeakApiKey:
    def test_no_node_in_response_carries_api_key(self):
        result = _run(federation_router.list_nodes_api(user=_enterprise_user()))
        nodes = result["nodes"]
        assert len(nodes) == 2
        for node in nodes:
            assert "api_key" not in node

    def test_other_node_fields_are_still_present(self):
        result = _run(federation_router.list_nodes_api(user=_enterprise_user()))
        names = {n["name"] for n in result["nodes"]}
        assert names == {"Peer One", "Peer Two"}
        assert all("endpoint" in n and "status" in n for n in result["nodes"])


class TestThisNodeApiDoesNotLeakApiKey:
    def test_this_node_response_has_no_api_key(self):
        result = _run(federation_router.this_node(user=_enterprise_user()))
        assert "api_key" not in result
        assert result["name"] == "This Node"

    def test_uninitialized_node_returns_status_marker_not_error(self):
        # Re-isolate to a fresh, un-seeded DB for this one test (the
        # autouse _seeded_nodes fixture already initialized a node).
        fed.FEDERATION_DB.write_text('{"nodes": [], "tasks": [], "results": [], "this_node": null}')
        result = _run(federation_router.this_node(user=_enterprise_user()))
        assert result == {"status": "not_initialized"}


class TestFederationHomeContextDoesNotLeakApiKey:
    def test_nodes_passed_to_template_have_no_api_key(self, monkeypatch):
        captured = {}

        def fake_template_response(request, name, context):
            captured.update(context)
            return "rendered"

        monkeypatch.setattr(federation_router.templates, "TemplateResponse", fake_template_response)

        _run(federation_router.federation_home(_FakeRequest(), user=_enterprise_user()))

        assert all("api_key" not in n for n in captured["nodes"])
        assert "api_key" not in (captured["this_node"] or {})
