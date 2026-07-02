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


class _FakeResponse:
    def __init__(self, headers):
        self.headers = headers


class _FakeGroqRateLimitError(Exception):
    """Duck-types groq.RateLimitError's shape, matching a real Groq TPD 429."""

    def __init__(self, used, limit, retry_after_seconds):
        message = (
            f"Rate limit reached for model `openai/gpt-oss-120b` on tokens "
            f"per day (TPD): Limit {limit}, Used {used}, Requested 950. "
            f"Please try again in {retry_after_seconds}s."
        )
        self.status_code = 429
        self.body = {"error": {"message": message, "type": "tokens", "code": "rate_limit_exceeded"}}
        self.response = _FakeResponse({"retry-after": str(retry_after_seconds)})


def test_batch_stops_immediately_on_tpd_and_defers_the_rest(monkeypatch):
    processed_ids = []

    def fake_classify_finding(finding, **_kwargs):
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
    def fake_classify_finding(finding, **_kwargs):
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


def test_batch_seeds_real_tpd_from_first_real_429_and_stops_immediately(monkeypatch):
    """
    End-to-end validation of the real-Used/Limit seeding path with everything
    mocked except the actual rate_limiter/parsing logic: the very first call
    to classify_finding fails with a real-shaped Groq TPD 429 (the only kind
    of failure this test simulates), and every subsequent finding must be
    deferred without classify_finding ever being invoked again -- proving the
    whole account-already-near-cap scenario is now handled locally after a
    single real 429, instead of every finding in the batch making its own
    doomed real call (as observed live before this fix).
    """
    call_log = []

    def fake_classify_finding(finding, _capture_exception=None):
        call_log.append(finding["id"])
        if finding["id"] == 0:
            exc = _FakeGroqRateLimitError(used=200000, limit=200000, retry_after_seconds=300)
            if _capture_exception is not None:
                _capture_exception.append(exc)
            return {
                "triage_verdict": "NEEDS_MANUAL_REVIEW",
                "triage_confidence": 0.0,
                "triage_reason": "AI triage unavailable: 429 rate_limit_exceeded",
            }
        return {"triage_verdict": "CONFIRMED", "triage_confidence": 0.9, "triage_reason": "ok"}

    monkeypatch.setattr(triage_engine, "classify_finding", fake_classify_finding)

    findings = [{"id": i} for i in range(5)]
    # concurrency_limit=1: strictly sequential, so exactly one real call
    # happens before the rest get deferred -- matches "validates with 1-2
    # real API calls" rather than burning the whole batch.
    results, summary = _run(
        triage_engine.classify_findings_batch(findings, concurrency_limit=1)
    )

    assert call_log == [0]  # classify_finding was never called again after the real 429

    assert results[0]["triage_verdict"] == "NEEDS_MANUAL_REVIEW"
    assert "Daily token quota (TPD) exhausted" in results[0]["triage_reason"]
    for deferred in results[1:]:
        assert deferred["triage_verdict"] == "NEEDS_MANUAL_REVIEW"
        assert deferred["triage_confidence"] == 0.0
        assert "Daily token quota (TPD) exhausted" in deferred["triage_reason"]

    assert summary["succeeded"] == 0
    assert summary["deferred_tpd"] == 5
    assert summary["tpd_reset_time"] is not None
