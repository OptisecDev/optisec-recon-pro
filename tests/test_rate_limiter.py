"""
Tests for modules/ai/rate_limiter.py's TokenBucketLimiter — specifically the
TPD (tokens-per-day) tracking added alongside the pre-existing TPM
(tokens-per-minute) window.

TPM and TPD are exercised very differently on purpose (see the module
docstring): TPM exhaustion is cheap to wait out (resolves in seconds), so
acquire() sleeps dynamically and eventually succeeds. TPD exhaustion can
take hours to resolve, so acquire() must never sleep for it — it raises
TPDExhaustedException immediately instead. These tests assert both halves
of that contract, plus that the pre-existing TPM dynamic-wait path is
unchanged.

Same convention as tests/test_honeypot.py: plain pytest, async functions
driven via asyncio.run() through a small `_run()` helper — no
pytest-asyncio dependency.
"""

import asyncio
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modules.ai.rate_limiter import (
    DailyTokenBudget,
    TokenBucketLimiter,
    TPDExhaustedException,
    estimate_tokens_from_text,
    get_default_daily_budget,
    parse_tpd_state_from_error,
)


def _run(coro):
    return asyncio.run(coro)


class _FakeResponse:
    def __init__(self, headers: dict):
        self.headers = headers


class _FakeGroqError(Exception):
    """Duck-types groq.RateLimitError's shape (status_code/body/response.headers)
    without importing the groq SDK, matching how parse_tpd_state_from_error
    inspects real errors."""

    def __init__(self, status_code, body, headers=None):
        self.status_code = status_code
        self.body = body
        self.response = _FakeResponse(headers or {})


def _tpd_body(message: str) -> dict:
    return {"error": {"message": message, "type": "tokens", "code": "rate_limit_exceeded"}}


_REAL_TPD_MESSAGE = (
    "Rate limit reached for model `openai/gpt-oss-120b` in organization "
    "`org_01khqb3angfebr3xqew9eg055t` service tier `on_demand` on tokens per "
    "day (TPD): Limit 200000, Used 200000, Requested 942. Please try again "
    "in 6m46.943999999s. Need more tokens? Upgrade to Dev Tier today at "
    "https://console.groq.com/settings/billing"
)


def test_tpd_exhaustion_raises_immediately_without_sleeping(monkeypatch):
    def _fail_if_slept(*_args, **_kwargs):
        raise AssertionError("acquire() must not sleep when TPD is the exhausted window")

    monkeypatch.setattr(asyncio, "sleep", _fail_if_slept)

    limiter = TokenBucketLimiter(
        limit=1_000_000, window_seconds=60.0, tpd_limit=100, tpd_window_seconds=86400.0
    )
    _run(limiter.acquire(90))  # first-ever call always granted; fills TPD window to 90/100

    with pytest.raises(TPDExhaustedException):
        _run(limiter.acquire(50))  # 90 + 50 > 100 -> must raise, not sleep


def test_tpd_exhaustion_carries_a_future_reset_time():
    limiter = TokenBucketLimiter(
        limit=1_000_000, window_seconds=60.0, tpd_limit=100, tpd_window_seconds=5.0
    )
    _run(limiter.acquire(90))

    before = datetime.now(timezone.utc)
    with pytest.raises(TPDExhaustedException) as exc_info:
        _run(limiter.acquire(50))

    reset_time = exc_info.value.reset_time
    assert reset_time.tzinfo is not None
    assert reset_time > before
    assert (reset_time - before).total_seconds() <= 6.0  # tpd_window_seconds + slack
    assert exc_info.value.reset_time_iso == reset_time.isoformat()
    assert "Daily token quota (TPD) exhausted" in str(exc_info.value)


def test_tpd_does_not_block_a_single_oversized_first_request():
    # Mirrors the pre-existing TPM behavior: a lone request larger than the
    # limit is still granted (avoids deadlocking a batch on one big finding).
    limiter = TokenBucketLimiter(
        limit=1_000_000, window_seconds=60.0, tpd_limit=100, tpd_window_seconds=86400.0
    )
    _run(limiter.acquire(500))  # no prior TPD events yet -> granted despite exceeding tpd_limit


def test_tpm_only_exhaustion_still_waits_dynamically_and_succeeds():
    # TPD limit set high so only the TPM window is ever tight.
    limiter = TokenBucketLimiter(
        limit=100, window_seconds=0.1, tpd_limit=1_000_000, tpd_window_seconds=86400.0
    )
    _run(limiter.acquire(90))

    start = time.monotonic()
    _run(limiter.acquire(50))  # 90 + 50 > 100 -> must wait for the TPM window to age out
    elapsed = time.monotonic() - start

    assert elapsed >= 0.05  # actually waited, did not raise or return instantly


# ── parse_tpd_state_from_error ──────────────────────────────────────────────


def test_parse_tpd_state_prefers_retry_after_header_over_message_text():
    exc = _FakeGroqError(429, _tpd_body(_REAL_TPD_MESSAGE), headers={"retry-after": "407"})
    state = parse_tpd_state_from_error(exc)
    assert state is not None
    assert state.used == 200000
    assert state.limit == 200000
    assert state.retry_after_seconds == 407.0  # header wins over "6m46.94s" in the message


def test_parse_tpd_state_falls_back_to_message_text_without_header():
    exc = _FakeGroqError(429, _tpd_body(_REAL_TPD_MESSAGE), headers={})
    state = parse_tpd_state_from_error(exc)
    assert state is not None
    assert state.used == 200000
    assert state.limit == 200000
    assert state.retry_after_seconds == pytest.approx(6 * 60 + 46.943999999, abs=0.01)


def test_parse_tpd_state_returns_none_for_non_429():
    exc = _FakeGroqError(400, _tpd_body(_REAL_TPD_MESSAGE))
    assert parse_tpd_state_from_error(exc) is None


def test_parse_tpd_state_returns_none_for_tpm_message():
    tpm_message = (
        "Rate limit reached for model `openai/gpt-oss-120b` on tokens per "
        "minute (TPM): Limit 8000, Used 8000, Requested 950. Please try "
        "again in 3.2s."
    )
    exc = _FakeGroqError(429, _tpd_body(tpm_message), headers={"retry-after": "3.2"})
    assert parse_tpd_state_from_error(exc) is None


def test_parse_tpd_state_returns_none_for_unrelated_exception():
    assert parse_tpd_state_from_error(ValueError("boom")) is None


# ── seed_real_tpd_usage ──────────────────────────────────────────────────────


def test_seed_real_tpd_usage_makes_next_acquire_raise_immediately_without_sleep(monkeypatch):
    def fail_if_slept(*_args, **_kwargs):
        raise AssertionError("must not sleep once TPD has been seeded from a real 429")

    monkeypatch.setattr(asyncio, "sleep", fail_if_slept)

    # Fresh limiter, no local usage tracked yet -- simulates a process that
    # just started but whose real account is already maxed out externally.
    limiter = TokenBucketLimiter(limit=8000, window_seconds=60.0, tpd_limit=200000, tpd_window_seconds=86400.0)

    reset_dt = _run(limiter.seed_real_tpd_usage(used=200000, limit=200000, retry_after_seconds=300.0))

    before = datetime.now(timezone.utc)
    with pytest.raises(TPDExhaustedException) as exc_info:
        _run(limiter.acquire(500))
    assert (exc_info.value.reset_time - reset_dt).total_seconds() == pytest.approx(0.0, abs=1.0)
    assert (reset_dt - before).total_seconds() == pytest.approx(300.0, abs=2.0)


def test_seed_real_tpd_usage_without_retry_after_still_blocks():
    limiter = TokenBucketLimiter(limit=8000, window_seconds=60.0, tpd_limit=200000, tpd_window_seconds=86400.0)
    _run(limiter.seed_real_tpd_usage(used=200000, limit=200000, retry_after_seconds=None))

    with pytest.raises(TPDExhaustedException):
        _run(limiter.acquire(500))


# ── DailyTokenBudget ──────────────────────────────────────────────────────────
# Sync, threading.Lock-based counterpart to TokenBucketLimiter's TPD window,
# for callers (like groq_analyzer.analyze_findings) that run in a worker
# thread rather than the asyncio event loop.


def test_would_exceed_false_when_well_under_the_safe_limit():
    budget = DailyTokenBudget(limit=200000)
    assert budget.would_exceed(1000) is False


def test_safe_limit_is_ninety_percent_of_the_configured_limit():
    budget = DailyTokenBudget(limit=200000)
    assert budget.safe_limit == 180000


def test_would_exceed_true_once_recorded_usage_crosses_the_safety_margin():
    budget = DailyTokenBudget(limit=200000)
    budget.record(179000)
    assert budget.would_exceed(500) is False  # 179500 <= 180000
    assert budget.would_exceed(2000) is True  # 181000 > 180000


def test_record_accumulates_across_multiple_calls():
    budget = DailyTokenBudget(limit=1000, safety_margin=1.0)
    budget.record(300)
    budget.record(300)
    budget.record(300)
    assert budget.would_exceed(50) is False  # 900 + 50 <= 1000
    assert budget.would_exceed(150) is True  # 900 + 150 > 1000


def test_entries_older_than_the_window_are_pruned(monkeypatch):
    budget = DailyTokenBudget(limit=1000, window_seconds=86400.0, safety_margin=1.0)

    now = [1_000_000.0]
    monkeypatch.setattr("modules.ai.rate_limiter.time.monotonic", lambda: now[0])

    budget.record(900)
    assert budget.would_exceed(200) is True  # still within the 24h window

    now[0] += 86400.0 + 1.0  # advance past the window
    assert budget.would_exceed(200) is False  # old usage aged out


def test_would_exceed_never_raises_and_never_blocks():
    budget = DailyTokenBudget(limit=100)
    # A single request far larger than the whole daily limit should just
    # report True, not raise -- this is a preflight check, not an enforcement
    # gate that throws.
    result = budget.would_exceed(10_000)
    assert result is True


def test_get_default_daily_budget_returns_the_same_instance_across_calls():
    first = get_default_daily_budget()
    second = get_default_daily_budget()
    assert first is second


def test_estimate_tokens_from_text_uses_four_chars_per_token_heuristic():
    text = "a" * 800  # 800 chars -> 200 tokens under the 4-chars-per-token rule
    assert estimate_tokens_from_text(text, completion_tokens=50) == 250


def test_estimate_tokens_from_text_respects_minimum_floor():
    tiny = estimate_tokens_from_text("hi", completion_tokens=0)
    assert tiny >= 200  # _MIN_ESTIMATED_TOKENS floor, same as estimate_tokens()
