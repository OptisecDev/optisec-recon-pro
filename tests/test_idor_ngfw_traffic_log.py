"""IDOR test for web/routers/ngfw.py's traffic-inspection log
(modules/firewall/ngfw_v2.py).

Same root cause as the prior IDOR fixes this audit series found in
modules/ai_advanced/{zero_day,red_team}.py (7ec15f0),
modules/darkweb/intelligence.py (580079d),
modules/quantum/encryption.py (aaf4e50), and
modules/threat_intel/attack_navigator.py (42a0d14): deep_inspect() (POST
/api/inspect) persisted every inspection result -- including the raw
path/body/user-agent content a specific account submitted -- into one
shared data/ngfw_v2_state.json traffic_log with no user_id field.
GET /api/stats (and the /ngfw dashboard) returned the last 20 raw entries
to any account with the ngfw entitlement, regardless of who submitted
them -- if one customer tested a real attack payload found in their own
environment, every other customer could see it.

Aggregate fields (totals/category_breakdown/top_source_ips/
geo_distribution/blocked_ips) are left global on purpose -- install-wide
firewall telemetry, same category as honeypot/threat-feed's shared
stores -- only `recent_log` (the raw per-submission content) is scoped.

Same direct-router-call convention as tests/test_idor_quantum_keys.py;
the module's DATA_FILE is monkeypatched to an isolated tmp_path file.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from web.models import User
import web.routers.ngfw as ngfw_router
import modules.firewall.ngfw_v2 as ngfw_module


def _run(coro):
    return asyncio.run(coro)


def _fake_user(user_id: int, role: str = "analyst") -> User:
    return User(id=user_id, username=f"u{user_id}", email=f"u{user_id}@example.com",
                password_hash="x", role=role, subscription_tier="pro")


@pytest.fixture(autouse=True)
def _isolated_data_file(tmp_path, monkeypatch):
    monkeypatch.setattr(ngfw_module, "DATA_FILE", tmp_path / "ngfw_v2_state.json")


def _inspect(marker: str, user_id: int | None) -> dict:
    return ngfw_module.deep_inspect(
        method="POST", path=f"/api/login?marker={marker}", headers={}, body="",
        src_ip="8.8.8.8", user_id=user_id,
    )


class TestTrafficLogIsolation:
    def test_attacker_cannot_see_victims_inspection(self):
        victim, attacker = _fake_user(1), _fake_user(2)
        _inspect("victim-secret-payload", user_id=victim.id)

        stats = ngfw_module.get_traffic_stats(user_id=attacker.id, is_admin=False)

        assert not any("victim-secret-payload" in e["path"] for e in stats["recent_log"])
        assert stats["recent_log"] == []

    def test_owner_sees_their_own_inspection(self):
        victim = _fake_user(1)
        _inspect("victim-secret-payload", user_id=victim.id)

        stats = ngfw_module.get_traffic_stats(user_id=victim.id, is_admin=False)

        assert len(stats["recent_log"]) == 1
        assert "victim-secret-payload" in stats["recent_log"][0]["path"]

    def test_admin_sees_every_accounts_inspections(self):
        _inspect("m1", user_id=1)
        _inspect("m2", user_id=2)
        admin = _fake_user(99, role="admin")

        stats = ngfw_module.get_traffic_stats(user_id=admin.id, is_admin=True)

        assert len(stats["recent_log"]) == 2

    def test_aggregate_stats_stay_global_not_scoped(self):
        """Deliberate: totals/category_breakdown etc. are install-wide
        telemetry, not per-user -- only recent_log is scoped."""
        _inspect("m1", user_id=1)
        _inspect("m2", user_id=2)
        attacker = _fake_user(2)

        stats = ngfw_module.get_traffic_stats(user_id=attacker.id, is_admin=False)

        assert stats["totals"]["total"] == 2  # counts both, not just attacker's own
        assert len(stats["recent_log"]) == 1  # but recent_log is still scoped


class TestNgfwRouterThreadsUserContext:
    def test_stats_endpoint_scopes_recent_log_by_user(self):
        ngfw_module.deep_inspect(method="GET", path="/x", headers={}, body="",
                                  src_ip="1.1.1.1", user_id=1)
        attacker = _fake_user(2)

        result = _run(ngfw_router.traffic_stats(user=attacker))

        assert result["recent_log"] == []

    def test_inspect_endpoint_stamps_requesting_user(self):
        class _FakeRequest:
            async def json(self):
                return {"method": "GET", "path": "/x", "body": "", "src_ip": "1.1.1.1"}

        result = _run(ngfw_router.inspect(_FakeRequest(), user=_fake_user(7)))

        assert result["user_id"] == 7
