"""Generic per-IP sliding-window rate limiter for web/ routes that need a
per-endpoint request cap (not just failed-login gating — see
web/auth.py's check_rate_limit). Same in-memory approach as
app/core/rate_limit.py's Eternal Core limiter, generalized into a factory
so each route can pick its own name/limit/window, and using web/auth.py's
Cloudflare-aware get_client_ip() instead of raw request.client.host so the
Render deployment topology fix (CF-Connecting-IP, see the 2026-09-02 IP
note in this project's memory) applies here too.

No third-party rate-limiting library (slowapi/fastapi-limiter) is used —
this in-memory sliding-window shape is already the established convention
in this codebase (web/auth.py, app/core/rate_limit.py), so a new endpoint
needing a cap reuses it instead of introducing a new dependency.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Callable, Union

from fastapi import HTTPException, Request

from web.auth import get_client_ip

IntOrCallable = Union[int, Callable[[], int]]

_buckets: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))


def _resolve(value: IntOrCallable) -> int:
    return value() if callable(value) else value


def rate_limiter(name: str, max_requests: IntOrCallable, window_seconds: IntOrCallable):
    """Returns a FastAPI dependency enforcing max_requests per window_seconds
    per client IP. `name` isolates this endpoint's counters from any other
    rate_limiter() instance. max_requests/window_seconds may be a plain int
    or a zero-arg callable (e.g. reading an env var), resolved on every
    request — lets the limit be tuned via env var without a process restart
    tying the value to import time.
    """
    def _dependency(request: Request) -> None:
        max_req = _resolve(max_requests)
        window = _resolve(window_seconds)
        ip = get_client_ip(request)
        bucket = _buckets[name]
        now = time.monotonic()
        timestamps = [t for t in bucket[ip] if now - t < window]
        if len(timestamps) >= max_req:
            retry_after = max(int(window - (now - min(timestamps))), 1)
            raise HTTPException(
                status_code=429,
                detail="Too many requests — please try again later.",
                headers={"Retry-After": str(retry_after)},
            )
        timestamps.append(now)
        bucket[ip] = timestamps

    return _dependency
