"""
Tests for the LRU cap on modules/firewall/ai_firewall.py::_rate_tracker
(check_rate_limit(), behind POST /firewall/api/rate-check).

`ip` is caller-supplied free text from the request body, not derived from
the actual request's network layer (unlike web/rate_limit.py's
rate_limiter(), keyed by get_client_ip()) -- a single authenticated user
could call this with a different `ip` value every time and grow
_rate_tracker without bound, a slow memory-exhaustion DoS (this
deployment is already memory-constrained -- see the VULN_SCAN_CONCURRENCY
8->4 fix for Render's 512MB free tier). Now capped via LRU eviction.

Plain pytest, no network/DB involved -- check_rate_limit() is a pure
in-memory function.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.firewall.ai_firewall as fw


@pytest.fixture(autouse=True)
def _isolated_rate_tracker(monkeypatch):
    monkeypatch.setattr(fw, "_rate_tracker", fw.OrderedDict())


class TestRateTrackerBound:
    def test_tracker_never_exceeds_max_tracked_ips(self, monkeypatch):
        monkeypatch.setattr(fw, "_MAX_TRACKED_IPS", 5)
        for i in range(20):
            fw.check_rate_limit(f"ip-{i}")
        assert len(fw._rate_tracker) == 5

    def test_least_recently_used_ip_is_evicted_first(self, monkeypatch):
        monkeypatch.setattr(fw, "_MAX_TRACKED_IPS", 3)
        fw.check_rate_limit("ip-a")
        fw.check_rate_limit("ip-b")
        fw.check_rate_limit("ip-c")
        # Touch ip-a again so it's no longer the least-recently-used.
        fw.check_rate_limit("ip-a")
        fw.check_rate_limit("ip-d")  # forces an eviction

        assert "ip-b" not in fw._rate_tracker  # least recently touched -> evicted
        assert "ip-a" in fw._rate_tracker
        assert "ip-c" in fw._rate_tracker
        assert "ip-d" in fw._rate_tracker

    def test_repeated_calls_for_the_same_ip_do_not_grow_tracker(self, monkeypatch):
        monkeypatch.setattr(fw, "_MAX_TRACKED_IPS", 1000)
        for _ in range(50):
            fw.check_rate_limit("same-ip")
        assert len(fw._rate_tracker) == 1

    def test_rate_limiting_semantics_are_unaffected_by_the_cap(self, monkeypatch):
        monkeypatch.setattr(fw, "_MAX_TRACKED_IPS", 1000)
        result = None
        for _ in range(105):
            result = fw.check_rate_limit("burst-ip", window_seconds=60, max_requests=100)
        assert result["rate_limited"] is True
        assert result["requests_in_window"] == 105
