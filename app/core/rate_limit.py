"""Per-IP sliding-window rate limiter for Eternal Core's API endpoints.

Same in-memory sliding-window approach as web/auth.py's check_rate_limit,
generalized to gate every request to a route (not just failed logins) since
scan/history/simulate/audit have no success/failure distinction worth
gating on individually.
"""
import time
from collections import defaultdict

from fastapi import HTTPException, Request

RATE_LIMIT_MAX = 30
RATE_LIMIT_WINDOW = 60  # seconds

_requests: dict[str, list[float]] = defaultdict(list)


def enforce_rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    timestamps = [t for t in _requests[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(timestamps) >= RATE_LIMIT_MAX:
        retry_after = max(int(RATE_LIMIT_WINDOW - (now - min(timestamps))), 1)
        raise HTTPException(
            status_code=429,
            detail="Too many requests",
            headers={"Retry-After": str(retry_after)},
        )
    timestamps.append(now)
    _requests[ip] = timestamps
