"""Token-bucket rate limiter for Groq's account-level TPM and TPD caps.

This is a second, independent protection layer from the asyncio.Semaphore
concurrency limit in triage_engine.py: the semaphore caps how many requests
run at once, this caps how many tokens are spent within rolling time
windows. Groq's on-demand tier enforces TPM (tokens-per-minute) and TPD
(tokens-per-day) at the account level regardless of concurrency — live
testing showed 429s even with the semaphore correctly holding
max_concurrent_seen at its configured limit, because 30 findings' worth of
prompt+completion tokens exceeded the 8000 TPM cap within the minute the
batch ran in.

TPM and TPD are handled with deliberately different behavior, not just
different window sizes:

- TPM (60s window) resolves in seconds to a couple of minutes, so it's
  cheap to wait out — acquire() sleeps dynamically until the oldest event
  in the window ages out, then re-checks.
- TPD (24h window) resolves in hours. Groq's own retry-after for a TPD 429
  has been observed at 4-5+ minutes and climbing — waiting it out inside a
  batch would stall the whole triage run for an unacceptable amount of
  time. So when TPD is the constraint blocking a request, acquire() never
  sleeps for it: it raises TPDExhaustedException immediately, carrying the
  computed reset time, so the caller can fail fast instead of blocking.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from config import GROQ_TPD_LIMIT, GROQ_TPM_LIMIT

# Mirrors triage_engine._MAX_BODY_CHARS — the response_body slice that
# actually reaches the prompt after truncation.
_MAX_BODY_CHARS = 1500

# Floor so short findings (empty response_body, short URL) don't estimate a
# near-zero token cost — every call still pays for the fixed prompt template
# text and the completion budget.
_MIN_ESTIMATED_TOKENS = 200

# max_tokens passed to the Groq chat completion call in triage_engine.
_COMPLETION_TOKENS = 300

_TPM_WINDOW_SECONDS = 60.0
_TPD_WINDOW_SECONDS = 24 * 60 * 60.0


class TPDExhaustedException(Exception):
    """Raised when the daily (TPD) token budget is exhausted.

    Unlike TPM exhaustion, this is never worth waiting out inside a batch —
    the reset can be hours away. `reset_time` is the computed UTC wall-clock
    time (timezone-aware datetime) at which enough of the 24h window will
    have aged out for the request to fit; `reset_time_iso` is that same
    value pre-formatted as an ISO 8601 string for direct use in messages.
    """

    def __init__(self, reset_time: datetime):
        self.reset_time = reset_time
        self.reset_time_iso = reset_time.isoformat()
        super().__init__(
            f"Daily token quota (TPD) exhausted. Resets at {self.reset_time_iso}."
        )


class TokenBucketLimiter:
    """Rate-limits token consumption over two independent rolling windows.

    Records (timestamp, tokens) for each granted acquire() call in both a
    60s (TPM) and a 24h (TPD) deque. Before granting a new request, prunes
    entries older than each window and checks which window (if any) blocks
    the request:

    - If TPD would be exceeded, raise TPDExhaustedException immediately —
      no waiting, since TPD resolves in hours.
    - Else if TPM would be exceeded, sleep dynamically until the oldest TPM
      entry ages out (existing behavior, unchanged), then re-check both.
    - Else grant immediately, recording the tokens in both windows.
    """

    def __init__(
        self,
        limit: int | None = None,
        window_seconds: float = _TPM_WINDOW_SECONDS,
        tpd_limit: int | None = None,
        tpd_window_seconds: float = _TPD_WINDOW_SECONDS,
    ):
        self.limit = limit if limit is not None else GROQ_TPM_LIMIT
        self.window_seconds = window_seconds
        self.tpd_limit = tpd_limit if tpd_limit is not None else GROQ_TPD_LIMIT
        self.tpd_window_seconds = tpd_window_seconds
        self._events: deque[tuple[float, int]] = deque()
        self._tpd_events: deque[tuple[float, int]] = deque()
        self._lock = asyncio.Lock()

    def _prune(self, now: float) -> int:
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        return sum(tokens for _, tokens in self._events)

    def _prune_tpd(self, now: float) -> int:
        cutoff = now - self.tpd_window_seconds
        while self._tpd_events and self._tpd_events[0][0] < cutoff:
            self._tpd_events.popleft()
        return sum(tokens for _, tokens in self._tpd_events)

    def _tpd_reset_time(self, now: float) -> datetime:
        oldest_ts, _ = self._tpd_events[0]
        seconds_until_reset = max(0.0, (oldest_ts + self.tpd_window_seconds) - now)
        return datetime.now(timezone.utc) + timedelta(seconds=seconds_until_reset)

    async def acquire(self, estimated_tokens: int) -> None:
        """Grant `estimated_tokens` against both windows, or block/raise.

        Blocks with a dynamic sleep if TPM is the constraint (unchanged
        behavior). Raises TPDExhaustedException immediately, without
        sleeping, if TPD is the constraint.
        """
        estimated_tokens = max(1, estimated_tokens)
        async with self._lock:
            while True:
                now = time.monotonic()
                used_tpd = self._prune_tpd(now)
                if self._tpd_events and used_tpd + estimated_tokens > self.tpd_limit:
                    raise TPDExhaustedException(self._tpd_reset_time(now))

                used_tpm = self._prune(now)
                if not self._events or used_tpm + estimated_tokens <= self.limit:
                    self._events.append((now, estimated_tokens))
                    self._tpd_events.append((now, estimated_tokens))
                    return

                oldest_ts, _ = self._events[0]
                sleep_for = (oldest_ts + self.window_seconds) - now
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)


def estimate_tokens(finding: dict) -> int:
    """Rough token estimate for one classify_finding call (prompt + completion).

    Uses a ~4-chars-per-token heuristic applied to the fields that dominate
    _build_prompt's length (response_body, truncated the same way the prompt
    truncates it, plus url/target, payload, evidence), plus a fixed overhead
    for the prompt template's instructions/criteria/examples text and the
    call's max_tokens completion budget.
    """
    response_body = (finding.get("response_body") or "")[:_MAX_BODY_CHARS]
    url = finding.get("url") or finding.get("target") or ""
    payload = finding.get("payload") or ""
    evidence = finding.get("evidence") or ""

    variable_chars = len(response_body) + len(url) + len(payload) + len(evidence)
    prompt_chars = variable_chars + 900  # fixed prompt template overhead

    estimated_prompt_tokens = prompt_chars // 4

    return max(_MIN_ESTIMATED_TOKENS, estimated_prompt_tokens + _COMPLETION_TOKENS)
