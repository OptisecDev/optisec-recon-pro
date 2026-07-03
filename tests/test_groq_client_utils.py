"""
Tests for modules/ai/groq_client_utils.py's call_groq_sync_with_retry —
specifically the `retry_on` predicate added so callers can opt out of
retrying certain exceptions (e.g. a daily rate-limit 429, which won't
resolve within a few seconds of backoff).

No real Groq API call is made: `func` is a plain stub that raises/returns
based on a call counter. time.sleep is monkeypatched to a no-op so these
tests run instantly instead of actually waiting out the backoff delays.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modules.ai.groq_client_utils import call_groq_sync_with_retry


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    monkeypatch.setattr("modules.ai.groq_client_utils.time.sleep", lambda _seconds: None)


def test_succeeds_on_first_attempt_without_retrying():
    calls = []

    def func():
        calls.append(1)
        return "ok"

    result = call_groq_sync_with_retry(func)
    assert result == "ok"
    assert len(calls) == 1


def test_default_behavior_retries_every_exception_until_exhausted():
    calls = []

    def func():
        calls.append(1)
        raise ValueError("transient")

    with pytest.raises(ValueError):
        call_groq_sync_with_retry(func, retry_delays=(1, 2))

    assert len(calls) == 3  # 1 initial attempt + 2 retries


def test_succeeds_after_transient_failures_within_retry_budget():
    calls = []

    def func():
        calls.append(1)
        if len(calls) < 3:
            raise ValueError("transient")
        return "recovered"

    result = call_groq_sync_with_retry(func, retry_delays=(1, 2, 4))
    assert result == "recovered"
    assert len(calls) == 3


def test_retry_on_false_stops_retrying_immediately():
    calls = []

    def func():
        calls.append(1)
        raise ValueError("do not retry me")

    with pytest.raises(ValueError):
        call_groq_sync_with_retry(func, retry_delays=(1, 2, 4), retry_on=lambda exc: False)

    assert len(calls) == 1  # no retries attempted at all


def test_retry_on_true_preserves_normal_retry_behavior():
    calls = []

    def func():
        calls.append(1)
        raise ValueError("keep retrying")

    with pytest.raises(ValueError):
        call_groq_sync_with_retry(func, retry_delays=(1, 2), retry_on=lambda exc: True)

    assert len(calls) == 3


def test_retry_on_can_distinguish_exception_types():
    calls = []

    class DailyLimitError(Exception):
        pass

    def func():
        calls.append(1)
        raise DailyLimitError("daily cap hit")

    def retry_on(exc):
        return not isinstance(exc, DailyLimitError)

    with pytest.raises(DailyLimitError):
        call_groq_sync_with_retry(func, retry_delays=(1, 2, 4), retry_on=retry_on)

    assert len(calls) == 1


def test_sleeps_are_called_with_expected_delays(monkeypatch):
    sleeps = []
    monkeypatch.setattr("modules.ai.groq_client_utils.time.sleep", lambda seconds: sleeps.append(seconds))

    def func():
        raise ValueError("always fails")

    with pytest.raises(ValueError):
        call_groq_sync_with_retry(func, retry_delays=(1, 2, 4))

    assert sleeps == [1, 2, 4]
