"""Regression test for the OSINT module-timeout hang.

Root cause (see SESSION.md discussion): email_finder.find_emails and
social_media.find_social_profiles used to run over the synchronous `requests`
library inside asyncio.to_thread(). When the orchestration-level
asyncio.wait_for(..., timeout=45) fired, it could only cancel the *asyncio*
wrapper task — concurrent.futures.Future.cancel() returns False once the
underlying thread is actually RUNNING, so the real network calls kept
executing in the background regardless of the timeout the frontend was told
about.

Both modules were converted to native `aiohttp` coroutines so
asyncio.CancelledError (raised by wait_for on timeout) propagates into the
in-flight request itself and actually stops it, instead of being swallowed by
an unstoppable background thread. This test proves that: it stubs
aiohttp.ClientSession.get with a response that hangs far longer than the
wait_for timeout, then confirms cancellation cuts execution off after the
first in-flight request instead of continuing on to the rest of
`urls_to_check`.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modules.osint.email_finder import find_emails
from modules.osint.social_media import find_social_profiles


class _HangingResponse:
    def __init__(self, delay: float):
        self._delay = delay
        self.url = "https://example.com"

    async def __aenter__(self):
        await asyncio.sleep(self._delay)
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def text(self):
        return ""


class _HangingSession:
    def __init__(self, delay: float, calls: list):
        self._delay = delay
        self._calls = calls

    def get(self, url, **kwargs):
        self._calls.append(url)
        return _HangingResponse(self._delay)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


HANG_DELAY = 0.3
CANCEL_TIMEOUT = 0.05


@pytest.mark.parametrize("target_fn", [find_emails, find_social_profiles])
def test_cancellation_stops_the_scan_instead_of_finishing_in_the_background(monkeypatch, target_fn):
    calls: list = []

    def _fake_session(*args, **kwargs):
        return _HangingSession(HANG_DELAY, calls)

    monkeypatch.setattr("aiohttp.ClientSession", _fake_session)

    async def _run():
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(target_fn("example.com"), timeout=CANCEL_TIMEOUT)
        # If cancellation didn't actually reach the request (the old
        # requests-in-a-thread bug), the scan would keep working through
        # urls_to_check in the background during this sleep and `calls`
        # would grow past 1.
        await asyncio.sleep(HANG_DELAY * 2)

    asyncio.run(_run())

    assert calls == ["https://example.com"]
