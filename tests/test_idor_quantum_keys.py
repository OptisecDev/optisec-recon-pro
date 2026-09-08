"""IDOR test for web/routers/quantum.py's PQC key listing
(modules/quantum/encryption.py).

Same root cause as the AI Advanced IDOR audit (commit 7ec15f0) and the
darkweb keyword/breach-check audit (commit 580079d), found here on first
review since this module had zero prior test coverage: generate_keypair()
stored every keypair in one shared data/quantum_keys/*.json store with no
user_id field, and list_keys() (GET /quantum/api/keys, and the /quantum
dashboard) returned every account's keys to any authenticated user with
the `quantum` entitlement. private_key was already stripped from storage
by _save_key() before this fix, so this was never a private-key leak --
but which algorithm another tenant used and how many keys they generated,
when, is still cross-tenant account-activity metadata that shouldn't be
visible to a different customer.

Same direct-router-call convention as tests/test_idor_zero_day_predictions.py
/ tests/test_idor_darkweb_intelligence.py; the module's KEYS_DIR is
monkeypatched to an isolated tmp_path directory.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from web.models import User
import web.routers.quantum as quantum_router
import modules.quantum.encryption as quantum_module


def _run(coro):
    return asyncio.run(coro)


def _fake_user(user_id: int, role: str = "analyst") -> User:
    return User(id=user_id, username=f"u{user_id}", email=f"u{user_id}@example.com",
                password_hash="x", role=role, subscription_tier="enterprise")


@pytest.fixture(autouse=True)
def _isolated_keys_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(quantum_module, "KEYS_DIR", tmp_path / "quantum_keys")


class TestListKeysIsolation:
    def test_attacker_cannot_see_victims_key(self):
        victim, attacker = _fake_user(1), _fake_user(2)
        quantum_module.generate_keypair("kyber768", user_id=victim.id)

        result = quantum_module.list_keys(user_id=attacker.id, is_admin=False)

        assert result == []

    def test_owner_sees_their_own_key(self):
        victim = _fake_user(1)
        quantum_module.generate_keypair("kyber768", user_id=victim.id)

        result = quantum_module.list_keys(user_id=victim.id, is_admin=False)

        assert len(result) == 1
        assert result[0]["algorithm"] == "kyber768"

    def test_admin_sees_every_accounts_keys(self):
        quantum_module.generate_keypair("kyber768", user_id=1)
        quantum_module.generate_keypair("dilithium3", user_id=2)
        admin = _fake_user(99, role="admin")

        result = quantum_module.list_keys(user_id=admin.id, is_admin=True)

        assert {k["algorithm"] for k in result} == {"kyber768", "dilithium3"}

    def test_private_key_is_never_present_regardless_of_scope(self):
        quantum_module.generate_keypair("kyber768", user_id=1)

        own = quantum_module.list_keys(user_id=1, is_admin=False)
        admin_view = quantum_module.list_keys(user_id=99, is_admin=True)

        assert "private_key" not in own[0]
        assert "private_key" not in admin_view[0]


class TestQuantumRouterThreadsUserContext:
    def test_list_keys_api_scopes_by_user(self):
        quantum_module.generate_keypair("kyber768", user_id=1)
        attacker = _fake_user(2)

        result = _run(quantum_router.list_keys_api(user=attacker))

        assert result["keys"] == []

    def test_generate_keypair_endpoint_stamps_requesting_user(self):
        user = _fake_user(5)

        class _FakeRequest:
            async def json(self):
                return {"algorithm": "kyber768"}

        result = _run(quantum_router.generate_keypair(_FakeRequest(), user=user))

        stored = quantum_module.list_keys(user_id=5, is_admin=False)
        assert len(stored) == 1
        assert stored[0]["user_id"] == 5
        # Router must still strip private_key from its own response.
        assert "private_key" not in result
