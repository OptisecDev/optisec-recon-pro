"""Redact credential-looking query parameters from uvicorn's logs.

uvicorn's access logger ("uvicorn.access") formats every request as
`client - "METHOD /path?query HTTP/1.1" status` with the raw query string,
and WebSocket handshakes are logged the same way under "uvicorn.error".
No route here reads a credential from the query string any more (see
web/auth.get_ws_user), but a client can still send one -- an old
`/ws/scan/<id>?token=<jwt>` caller, a pasted link -- and it would land in
the platform's log drain in clear text.

The filter only rewrites the path argument of matching log records; it
never drops a record or touches the request itself.
"""

import logging
import re

REDACTED = "[REDACTED]"

# token, access_token, csrf_token, ...; api_key/apikey; key; secret;
# password; sig/signature. Matched case-insensitively against the
# parameter name, up to the next & or #.
_SENSITIVE_PARAM = re.compile(
    r"(?i)([?&](?:[^=&#]*token|api_?key|key|[^=&#]*secret|password|passwd|sig|signature)=)[^&#\s\"]*"
)


def redact_query(value: str) -> str:
    if "?" not in value:
        return value
    return _SENSITIVE_PARAM.sub(lambda m: m.group(1) + REDACTED, value)


class RedactQueryTokensFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and any(isinstance(a, str) and "?" in a for a in args):
            record.args = tuple(redact_query(a) if isinstance(a, str) else a for a in args)
        return True


def install(logger_names=("uvicorn.access", "uvicorn.error")) -> None:
    """Attach the filter once per logger (idempotent across re-imports).
    Filters on a logger stay in place when uvicorn later (re)configures its
    handlers, and uvicorn configures logging before importing the app."""
    for name in logger_names:
        logger = logging.getLogger(name)
        if not any(isinstance(f, RedactQueryTokensFilter) for f in logger.filters):
            logger.addFilter(RedactQueryTokensFilter())
