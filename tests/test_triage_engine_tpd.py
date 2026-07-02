"""
Tests for classify_findings_batch's TPD (daily token quota) fail-fast path
in modules/ai/triage_engine.py.

No real Groq API call is made here: classify_finding and
TokenBucketLimiter.acquire are both monkeypatched so the test controls
exactly when TPDExhaustedException fires, without depending on real token
usage or timing.

Same convention as tests/test_honeypot.py: plain pytest, async functions
driven via asyncio.run() through a small `_run()` helper.
"""

import asyncio
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.ai.triage_engine as triage_engine
from modules.ai.rate_limiter import TPDExhaustedException


def _run(coro):
    return asyncio.run(coro)


def test_batch_stops_immediately_on_tpd_and_defers_the_rest(monkeypatch):
    processed_ids = []

    def fake_classify_finding(finding):
        processed_ids.append(finding["id"])
        return {"triage_verdict": "CONFIRMED", "triage_confidence": 0.9, "triage_reason": "ok"}

    monkeypatch.setattr(triage_engine, "classify_finding", fake_classify_finding)

    reset_dt = datetime(2026, 7, 3, 0, 0, 0, tzinfo=timezone.utc)
    acquire_calls = 0

    async def fake_acquire(self, tokens):
        nonlocal acquire_calls
        acquire_calls += 1
        if acquire_calls >= 3:
            raise TPDExhaustedException(reset_dt)

    monkeypatch.setattr(triage_engine.TokenBucketLimiter, "acquire", fake_acquire)

    def fail_if_slept(*_args, **_kwargs):
        raise AssertionError("must not sleep on the TPD path")

    monkeypatch.setattr(asyncio, "sleep", fail_if_slept)

    findings = [{"id": i} for i in range(6)]
    # concurrency_limit=1 makes execution strictly sequential in input order.
    results, summary = _run(
        triage_engine.classify_findings_batch(findings, concurrency_limit=1)
    )

    assert len(results) == 6
    assert results[0]["triage_verdict"] == "CONFIRMED"
    assert results[1]["triage_verdict"] == "CONFIRMED"
    for deferred in results[2:]:
        assert deferred["triage_verdict"] == "NEEDS_MANUAL_REVIEW"
        assert deferred["triage_confidence"] == 0.0
        assert "Daily token quota (TPD) exhausted" in deferred["triage_reason"]
        assert reset_dt.isoformat() in deferred["triage_reason"]

    # classify_finding (the real Groq call) was never reached for the
    # findings that came after TPD tripped.
    assert processed_ids == [0, 1]

    assert summary["succeeded"] == 2
    assert summary["deferred_tpd"] == 4
    assert summary["tpd_reset_time"] == reset_dt.isoformat()


def test_batch_all_succeed_when_tpd_never_trips(monkeypatch):
    def fake_classify_finding(finding):
        return {"triage_verdict": "CONFIRMED", "triage_confidence": 0.8, "triage_reason": "ok"}

    async def fake_acquire(self, tokens):
        return None

    monkeypatch.setattr(triage_engine, "classify_finding", fake_classify_finding)
    monkeypatch.setattr(triage_engine.TokenBucketLimiter, "acquire", fake_acquire)

    findings = [{"id": i} for i in range(4)]
    results, summary = _run(triage_engine.classify_findings_batch(findings))

    assert len(results) == 4
    assert all(r["triage_verdict"] == "CONFIRMED" for r in results)
    assert summary == {"succeeded": 4, "deferred_tpd": 0, "tpd_reset_time": None}
