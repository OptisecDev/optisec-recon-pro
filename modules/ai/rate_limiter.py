"""Token-bucket rate limiter for Groq's account-level TPM (tokens-per-minute) cap.

This is a second, independent protection layer from the asyncio.Semaphore
concurrency limit in triage_engine.py: the semaphore caps how many requests
run at once, this caps how many tokens are spent within a rolling time
window. Groq's on-demand tier enforces TPM at the account level regardless
of concurrency — live testing showed 429s even with the semaphore correctly
holding max_concurrent_seen at its configured limit, because 30 findings'
worth of prompt+completion tokens exceeded the 8000 TPM cap within the
minute the batch ran in.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque

from config import GROQ_TPM_LIMIT

# Mirrors triage_engine._MAX_BODY_CHARS — the response_body slice that
# actually reaches the prompt after truncation.
_MAX_BODY_CHARS = 1500

# Floor so short findings (empty response_body, short URL) don't estimate a
# near-zero token cost — every call still pays for the fixed prompt template
# text and the completion budget.
_MIN_ESTIMATED_TOKENS = 200

# max_tokens passed to the Groq chat completion call in triage_engine.
_COMPLETION_TOKENS = 300


class TokenBucketLimiter:
    """Rate-limits token consumption over a rolling time window.

    Records (timestamp, tokens) for each granted acquire() call. Before
    granting a new request, prunes entries older than `window_seconds` and,
    if the pending request would push the window's total over `limit`,
    waits until enough old entries age out of the window to make room.
    """

    def __init__(self, limit: int | None = None, window_seconds: float = 60.0):
        self.limit = limit if limit is not None else GROQ_TPM_LIMIT
        self.window_seconds = window_seconds
        self._events: deque[tuple[float, int]] = deque()
        self._lock = asyncio.Lock()

    def _prune(self, now: float) -> int:
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        return sum(tokens for _, tokens in self._events)

    async def acquire(self, estimated_tokens: int) -> None:
        """Block until consuming `estimated_tokens` fits within the rolling window's limit."""
        estimated_tokens = max(1, estimated_tokens)
        async with self._lock:
            while True:
                now = time.monotonic()
                used = self._prune(now)
                if not self._events or used + estimated_tokens <= self.limit:
                    self._events.append((now, estimated_tokens))
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
