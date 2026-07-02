"""Shared retry/backoff helpers for Groq API calls.

Groq requests can transiently fail on rate limits, dropped connections, or
timeouts; even in response_format="json_object" mode the model can
occasionally emit invalid JSON (Groq's docs note JSON Object Mode guarantees
syntactically valid JSON but not schema conformance, and can "occasionally"
error — confirmed in practice: openai/gpt-oss-120b returns an HTTP 400
json_validate_failed on some prompts at a double-digit percent rate). Each
call gets 3 total attempts with a 1s then 2s backoff by default before the
caller's existing failure handling takes over; pass `retry_delays` to use
more attempts for a call site with a higher observed failure rate. This
logic isn't duplicated across every module that talks to Groq.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable, TypeVar

logger = logging.getLogger("ai.groq_client_utils")

DEFAULT_RETRY_DELAYS = (1, 2)  # seconds to wait after attempt 1 and attempt 2

T = TypeVar("T")


def call_groq_sync_with_retry(
    func: Callable[..., T], *args: Any, retry_delays: tuple[float, ...] = DEFAULT_RETRY_DELAYS, **kwargs: Any
) -> T:
    """Call a synchronous Groq request function, retrying transient failures."""
    max_attempts = len(retry_delays) + 1
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < len(retry_delays):
                logger.warning(
                    "Groq call failed (attempt %d/%d): %s — retrying in %ds",
                    attempt + 1, max_attempts, exc, retry_delays[attempt],
                )
                time.sleep(retry_delays[attempt])
    assert last_exc is not None
    raise last_exc


async def call_groq_async_with_retry(
    func: Callable[..., Awaitable[T]], *args: Any, retry_delays: tuple[float, ...] = DEFAULT_RETRY_DELAYS, **kwargs: Any
) -> T:
    """Call an async Groq request function, retrying transient failures."""
    max_attempts = len(retry_delays) + 1
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return await func(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < len(retry_delays):
                logger.warning(
                    "Groq call failed (attempt %d/%d): %s — retrying in %ds",
                    attempt + 1, max_attempts, exc, retry_delays[attempt],
                )
                await asyncio.sleep(retry_delays[attempt])
    assert last_exc is not None
    raise last_exc
