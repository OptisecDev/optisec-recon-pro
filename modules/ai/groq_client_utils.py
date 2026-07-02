"""Shared retry/backoff helpers for Groq API calls.

Groq requests can transiently fail on rate limits, dropped connections, or
timeouts; even in response_format="json_object" mode the model can
occasionally emit invalid JSON (Groq's docs note JSON Object Mode guarantees
syntactically valid JSON but not schema conformance, and can "occasionally"
error). Each call gets 3 total attempts with a 1s then 2s backoff before the
caller's existing failure handling takes over, so this logic isn't
duplicated across every module that talks to Groq.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable, TypeVar

logger = logging.getLogger("ai.groq_client_utils")

MAX_ATTEMPTS = 3
RETRY_DELAYS = (1, 2)  # seconds to wait after attempt 1 and attempt 2

T = TypeVar("T")


def call_groq_sync_with_retry(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Call a synchronous Groq request function, retrying transient failures."""
    last_exc: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < len(RETRY_DELAYS):
                logger.warning(
                    "Groq call failed (attempt %d/%d): %s — retrying in %ds",
                    attempt + 1, MAX_ATTEMPTS, exc, RETRY_DELAYS[attempt],
                )
                time.sleep(RETRY_DELAYS[attempt])
    assert last_exc is not None
    raise last_exc


async def call_groq_async_with_retry(func: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
    """Call an async Groq request function, retrying transient failures."""
    last_exc: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            return await func(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < len(RETRY_DELAYS):
                logger.warning(
                    "Groq call failed (attempt %d/%d): %s — retrying in %ds",
                    attempt + 1, MAX_ATTEMPTS, exc, RETRY_DELAYS[attempt],
                )
                await asyncio.sleep(RETRY_DELAYS[attempt])
    assert last_exc is not None
    raise last_exc
