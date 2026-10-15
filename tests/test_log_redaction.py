"""
Credential-looking query parameters are redacted from uvicorn's access and
WebSocket logs (web/log_redaction.py, installed by importing web.app).

uvicorn logs the raw path + query string of every request, so a client
still sending `?token=<jwt>` (the WebSocket query-token auth that was
removed in favour of headers/cookies) or `?api_key=...` would leave a live
credential in the log drain.
"""

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import web.app  # noqa: F401 -- installs the filter
from web.log_redaction import REDACTED, RedactQueryTokensFilter, install, redact_query

SECRET = "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0.c2lnbmF0dXJl"


@pytest.mark.parametrize("path", [
    f"/ws/scan/abc?token={SECRET}",
    f"/x?access_token={SECRET}",
    f"/x?api_key={SECRET}",
    f"/x?apikey={SECRET}",
    f"/x?a=1&key={SECRET}&b=2",
    f"/x?Token={SECRET}",
    f"/x?csrf_token={SECRET}",
    f"/x?client_secret={SECRET}",
    f"/x?password={SECRET}",
    f"/x?sig={SECRET}#frag",
])
def test_sensitive_values_are_redacted(path):
    out = redact_query(path)
    assert SECRET not in out
    assert REDACTED in out


def test_other_params_and_path_are_kept():
    assert redact_query("/scan?target=example.com&page=2") == "/scan?target=example.com&page=2"
    assert redact_query("/token/abc") == "/token/abc"
    assert redact_query(f"/x?a=1&token={SECRET}&b=2") == f"/x?a=1&token={REDACTED}&b=2"


def _emit(logger_name, msg, args):
    """Run a record through the named logger's filters the way uvicorn
    emits it, and return the final formatted message."""
    logger = logging.getLogger(logger_name)
    record = logger.makeRecord(logger_name, logging.INFO, __file__, 0, msg, args, None)
    for f in logger.filters:
        f.filter(record)
    return record.getMessage()


def test_uvicorn_access_log_line_is_redacted():
    # Same format string and argument order as uvicorn's httptools/h11 protocols.
    line = _emit(
        "uvicorn.access", '%s - "%s %s HTTP/%s" %d',
        ("1.2.3.4:5555", "GET", f"/ws/scan/abc?token={SECRET}", "1.1", 101),
    )
    assert SECRET not in line
    assert f"/ws/scan/abc?token={REDACTED}" in line
    assert '"GET' in line and "101" in line


def test_uvicorn_websocket_log_line_is_redacted():
    line = _emit(
        "uvicorn.error", '%s - "WebSocket %s" [accepted]',
        (("1.2.3.4", 5555), f"/ws/scan/abc?token={SECRET}"),
    )
    assert SECRET not in line


def test_install_is_idempotent():
    install()
    install()
    for name in ("uvicorn.access", "uvicorn.error"):
        filters = [f for f in logging.getLogger(name).filters if isinstance(f, RedactQueryTokensFilter)]
        assert len(filters) == 1


def test_filter_never_drops_records():
    f = RedactQueryTokensFilter()
    record = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "plain %s", ("x",), None)
    assert f.filter(record) is True
    record = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "no args", None, None)
    assert f.filter(record) is True
