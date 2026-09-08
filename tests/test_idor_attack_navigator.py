"""IDOR + input-validation test for web/routers/attack_navigator.py's
detection log (modules/threat_intel/attack_navigator.py).

Same root cause as the prior IDOR fixes this audit series found in
modules/ai_advanced/{zero_day,red_team}.py (commit 7ec15f0),
modules/darkweb/intelligence.py (580079d), and
modules/quantum/encryption.py (aaf4e50): add_detection() stored every
detection in one shared data/attack_navigator_state.json list with no
user_id field. GET /api/detections returned every account's detections to
any authenticated user with the attack_navigator entitlement -- including
`details`, a free-text field that in a pentest/SOC context can name
internal hosts or client engagements.

Also covers the companion fix: technique_id must reference a real MITRE
technique. Previously an unrecognized technique_id was echoed straight
back as technique_name (_find_technique()'s not-found fallback), which
combined with the template rendering technique_id/technique_name/source
unescaped (see tests/test_attack_navigator_xss_escaping.py) made an
invalid technique_id part of the stored-XSS surface.

Same direct-router-call convention as tests/test_idor_quantum_keys.py;
the module's DATA_FILE is monkeypatched to an isolated tmp_path file.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi import HTTPException

from web.models import User
import web.routers.attack_navigator as nav_router
import modules.threat_intel.attack_navigator as nav_module


def _run(coro):
    return asyncio.run(coro)


def _fake_user(user_id: int, role: str = "analyst") -> User:
    return User(id=user_id, username=f"u{user_id}", email=f"u{user_id}@example.com",
                password_hash="x", role=role, subscription_tier="enterprise")


@pytest.fixture(autouse=True)
def _isolated_data_file(tmp_path, monkeypatch):
    monkeypatch.setattr(nav_module, "DATA_FILE", tmp_path / "attack_navigator_state.json")


_REAL_TECHNIQUE_ID = "T1595"  # Active Scanning, TA0043 -- see TECHNIQUES


class TestAddDetectionValidation:
    def test_unknown_technique_id_is_rejected(self):
        with pytest.raises(ValueError):
            nav_module.add_detection(technique_id="<script>alert(1)</script>", confidence=80, source="manual")

    def test_known_technique_id_is_accepted(self):
        d = nav_module.add_detection(technique_id=_REAL_TECHNIQUE_ID, confidence=80, source="manual")
        assert d["technique_id"] == _REAL_TECHNIQUE_ID
        assert d["technique_name"] == "Active Scanning"

    def test_source_is_length_capped(self):
        d = nav_module.add_detection(technique_id=_REAL_TECHNIQUE_ID, confidence=80, source="x" * 1000)
        assert len(d["source"]) == nav_module._MAX_SOURCE_LEN

    def test_details_is_length_capped(self):
        d = nav_module.add_detection(technique_id=_REAL_TECHNIQUE_ID, confidence=80, source="s", details="x" * 5000)
        assert len(d["details"]) == nav_module._MAX_DETAILS_LEN


class TestDetectionIsolation:
    def test_attacker_cannot_see_victims_detection(self):
        victim, attacker = _fake_user(1), _fake_user(2)
        nav_module.add_detection(technique_id=_REAL_TECHNIQUE_ID, confidence=90, source="victim-tool",
                                  details="found on victim-internal-host.corp", user_id=victim.id)

        result = nav_module.get_detections(user_id=attacker.id, is_admin=False)

        assert result == []

    def test_owner_sees_their_own_detection(self):
        victim = _fake_user(1)
        nav_module.add_detection(technique_id=_REAL_TECHNIQUE_ID, confidence=90, source="victim-tool",
                                  user_id=victim.id)

        result = nav_module.get_detections(user_id=victim.id, is_admin=False)

        assert len(result) == 1
        assert result[0]["source"] == "victim-tool"

    def test_admin_sees_every_accounts_detections(self):
        nav_module.add_detection(technique_id=_REAL_TECHNIQUE_ID, confidence=50, source="s1", user_id=1)
        nav_module.add_detection(technique_id=_REAL_TECHNIQUE_ID, confidence=50, source="s2", user_id=2)
        admin = _fake_user(99, role="admin")

        result = nav_module.get_detections(user_id=admin.id, is_admin=True)

        assert {d["source"] for d in result} == {"s1", "s2"}


class TestAttackNavigatorRouterThreadsUserContext:
    def test_get_detections_endpoint_scopes_by_user(self):
        nav_module.add_detection(technique_id=_REAL_TECHNIQUE_ID, confidence=90, source="victim-tool", user_id=1)
        attacker = _fake_user(2)

        result = _run(nav_router.get_detections(user=attacker))

        assert result["detections"] == []

    def test_add_detection_endpoint_rejects_unknown_technique_with_400(self):
        class _FakeRequest:
            async def json(self):
                return {"technique_id": "not-a-real-technique", "confidence": 80, "source": "s"}

        with pytest.raises(HTTPException) as exc_info:
            _run(nav_router.add_detection(_FakeRequest(), user=_fake_user(1)))
        assert exc_info.value.status_code == 400

    def test_add_detection_endpoint_stamps_requesting_user(self):
        class _FakeRequest:
            async def json(self):
                return {"technique_id": _REAL_TECHNIQUE_ID, "confidence": 80, "source": "s"}

        result = _run(nav_router.add_detection(_FakeRequest(), user=_fake_user(7)))

        assert result["user_id"] == 7
