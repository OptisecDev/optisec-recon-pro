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

from modules.ai.rate_limiter import TokenBucketLimiter, TPDExhaustedException


def _run(coro):
    return asyncio.run(coro)


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
