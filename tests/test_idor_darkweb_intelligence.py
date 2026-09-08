"""IDOR test for web/routers/darkweb.py's keyword monitoring and breach
history (modules/darkweb/intelligence.py).

Same root cause as the 2026-09-01 AI Advanced IDOR audit
(tests/test_idor_zero_day_predictions.py, tests/test_idor_ai_red_team.py),
just found later in a separate module: monitored_keywords and
breach_checks are both stored in one shared data/darkweb_intel.json list
with no user_id field. GET /darkweb/api/keywords returned every account's
monitored keywords (which can name internal projects, brands, or
executives) to any authenticated user with the osint_darkweb entitlement,
and GET /darkweb/api/breach-intel's `recent_checks` similarly exposed what
domains other customers had been investigating. Adding a keyword with the
same name (case-insensitive) as another user's entry also silently
overwrote it across accounts.

Same direct-router-call convention as tests/test_idor_zero_day_predictions.py;
the module's DATA_FILE is monkeypatched to an isolated tmp_path file.
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from web.models import User
import web.routers.darkweb as darkweb_router
import modules.darkweb.intelligence as darkweb_module


def _run(coro):
    return asyncio.run(coro)


def _fake_user(user_id: int, role: str = "analyst") -> User:
    return User(id=user_id, username=f"u{user_id}", email=f"u{user_id}@example.com",
                password_hash="x", role=role, subscription_tier="enterprise")


@pytest.fixture
def isolated_darkweb_data(tmp_path, monkeypatch):
    data_file = tmp_path / "darkweb_intel.json"
    monkeypatch.setattr(darkweb_module, "DATA_FILE", data_file)
    return data_file


class TestKeywordIsolation:
    def test_attacker_cannot_see_victims_keyword(self, isolated_darkweb_data):
        victim, attacker = _fake_user(1), _fake_user(2)
        darkweb_module.add_keyword_alert("victim-internal-codename", "brand", user_id=victim.id)

        result = darkweb_module.get_monitored_keywords(user_id=attacker.id, is_admin=False)

        assert result == []

    def test_owner_sees_their_own_keyword(self, isolated_darkweb_data):
        victim = _fake_user(1)
        darkweb_module.add_keyword_alert("victim-internal-codename", "brand", user_id=victim.id)

        result = darkweb_module.get_monitored_keywords(user_id=victim.id, is_admin=False)

        assert [k["keyword"] for k in result] == ["victim-internal-codename"]

    def test_admin_sees_every_accounts_keywords(self, isolated_darkweb_data):
        darkweb_module.add_keyword_alert("kw-one", "brand", user_id=1)
        darkweb_module.add_keyword_alert("kw-two", "brand", user_id=2)
        admin = _fake_user(99, role="admin")

        result = darkweb_module.get_monitored_keywords(user_id=admin.id, is_admin=True)

        assert {k["keyword"] for k in result} == {"kw-one", "kw-two"}

    def test_same_keyword_name_from_two_users_does_not_clobber_each_other(self, isolated_darkweb_data):
        darkweb_module.add_keyword_alert("acme", "brand", user_id=1)
        darkweb_module.add_keyword_alert("ACME", "leak", user_id=2)  # case-insensitive same name, different owner

        user1_kw = darkweb_module.get_monitored_keywords(user_id=1, is_admin=False)
        user2_kw = darkweb_module.get_monitored_keywords(user_id=2, is_admin=False)

        assert len(user1_kw) == 1 and user1_kw[0]["category"] == "brand"
        assert len(user2_kw) == 1 and user2_kw[0]["category"] == "leak"

    def test_same_user_re_adding_same_keyword_does_dedupe(self, isolated_darkweb_data):
        darkweb_module.add_keyword_alert("acme", "brand", user_id=1)
        darkweb_module.add_keyword_alert("ACME", "leak", user_id=1)  # same owner, same keyword -> replace

        result = darkweb_module.get_monitored_keywords(user_id=1, is_admin=False)

        assert len(result) == 1
        assert result[0]["category"] == "leak"


class TestBreachIntelIsolation:
    def test_attacker_cannot_see_victims_domain_check_in_recent_checks(self, isolated_darkweb_data):
        victim, attacker = _fake_user(1), _fake_user(2)
        darkweb_module.check_domain_breach("victim-secret-target.example.com", user_id=victim.id)

        result = darkweb_module.get_breach_intelligence(user_id=attacker.id, is_admin=False)

        domains_seen = [c["domain"] for c in result["recent_checks"]]
        assert "victim-secret-target.example.com" not in domains_seen

    def test_owner_sees_their_own_check(self, isolated_darkweb_data):
        victim = _fake_user(1)
        darkweb_module.check_domain_breach("victim-secret-target.example.com", user_id=victim.id)

        result = darkweb_module.get_breach_intelligence(user_id=victim.id, is_admin=False)

        domains_seen = [c["domain"] for c in result["recent_checks"]]
        assert "victim-secret-target.example.com" in domains_seen

    def test_admin_sees_every_accounts_checks(self, isolated_darkweb_data):
        darkweb_module.check_domain_breach("target-one.example.com", user_id=1)
        darkweb_module.check_domain_breach("target-two.example.com", user_id=2)
        admin = _fake_user(99, role="admin")

        result = darkweb_module.get_breach_intelligence(user_id=admin.id, is_admin=True)

        domains_seen = {c["domain"] for c in result["recent_checks"]}
        assert {"target-one.example.com", "target-two.example.com"} <= domains_seen


class TestThreatReportIsolation:
    def test_report_keyword_hits_only_use_the_requesters_own_keywords(self, isolated_darkweb_data, monkeypatch):
        # Force every keyword to "hit" so the test is deterministic
        # regardless of the hash-seeded 20% simulated hit rate.
        monkeypatch.setattr(darkweb_module.random, "choice", lambda seq: seq[0])
        victim, attacker = _fake_user(1), _fake_user(2)
        darkweb_module.add_keyword_alert("victim-only-keyword", "brand", user_id=victim.id)

        report = darkweb_module.generate_threat_report(
            "example.com", user_id=attacker.id, is_admin=False,
        )

        hit_keywords = [h["keyword"] for h in report["keyword_monitoring_hits"]]
        assert "victim-only-keyword" not in hit_keywords


class TestDarkwebRouterThreadsUserContext:
    """Router-level guard: every endpoint that touches shared history must
    actually pass the requesting user's id/role through, not just the
    module functions in isolation above."""

    def test_get_keywords_endpoint_scopes_by_user(self, isolated_darkweb_data):
        darkweb_module.add_keyword_alert("victim-keyword", "brand", user_id=1)
        attacker = _fake_user(2)

        result = _run(darkweb_router.get_keywords(user=attacker))

        assert result["keywords"] == []

    def test_breach_intel_endpoint_scopes_by_user(self, isolated_darkweb_data):
        darkweb_module.check_domain_breach("victim-target.example.com", user_id=1)
        attacker = _fake_user(2)

        result = _run(darkweb_router.breach_intel(user=attacker))

        domains_seen = [c["domain"] for c in result["recent_checks"]]
        assert "victim-target.example.com" not in domains_seen
