"""
Lightweight honeypot service emulators — SSH, FTP and a fake HTTP admin
panel.

Each listener only ever reads bytes off the wire, records them, and replies
with a static/templated banner or page — it never parses attacker input as
anything executable (no shell, no real auth, no file access), so a
malicious payload can only ever end up as inert bytes in a database column.
That containment, plus the non-standard ports chosen in
modules/honeypot/manager.py, is what keeps this "lightweight" honeypot
sandboxed from the real server it runs alongside.

Every handler takes an `on_event` async callback and calls it once per
connection/session with a plain dict:
    {"service", "source_ip", "source_port", "payload", "session_data"}
The caller (modules/honeypot/manager.py) is responsible for enrichment and
persistence — this module has no DB/network-intel dependencies, which keeps
its protocol logic independently testable over real loopback sockets.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Awaitable, Callable

logger = logging.getLogger("honeypot.listeners")

EventCallback = Callable[[dict], Awaitable[None]]

# Caps so a connection can never force unbounded memory/time use.
MAX_PAYLOAD_BYTES = 2048
READ_TIMEOUT_SECONDS = 5.0
FTP_MAX_COMMANDS = 20

SERVICE_LABELS_AR: dict[str, str] = {
    "ssh": "خدمة SSH وهمية",
    "ftp": "خدمة FTP وهمية",
    "http_admin": "لوحة تحكم HTTP وهمية",
}


# ── Shared helpers ───────────────────────────────────────────────────────

async def _read_with_timeout(reader: asyncio.StreamReader, n: int, timeout: float) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(n), timeout=timeout)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return b""


def _truncate(data: bytes, limit: int = MAX_PAYLOAD_BYTES) -> str:
    return data[:limit].decode("utf-8", errors="replace")


def _peer(writer: asyncio.StreamWriter) -> tuple[str, int]:
    info = writer.get_extra_info("peername") or ("unknown", 0)
    return info[0], info[1]


async def _safe_emit(on_event: EventCallback, event: dict) -> None:
    """Never let a broken/slow on_event callback take down a listener."""
    try:
        await on_event(event)
    except Exception:
        logger.exception("honeypot on_event callback failed for service=%s", event.get("service"))


async def _safe_close(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()


# ── SSH ───────────────────────────────────────────────────────────────────

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"


async def handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      on_event: EventCallback) -> None:
    """Send a real-looking OpenSSH banner and capture whatever the client
    sends back (client version string / key-exchange init) — no actual SSH
    handshake is performed, so no crypto or auth logic ever runs."""
    ip, port = _peer(writer)
    writer.write(SSH_BANNER)
    await writer.drain()
    data = await _read_with_timeout(reader, MAX_PAYLOAD_BYTES, READ_TIMEOUT_SECONDS)

    payload = _truncate(data)
    await _safe_emit(on_event, {
        "service": "ssh",
        "source_ip": ip,
        "source_port": port,
        "payload": payload,
        "session_data": {"banner_sent": SSH_BANNER.decode(), "client_hello": payload},
    })
    await _safe_close(writer)


# ── FTP ───────────────────────────────────────────────────────────────────

FTP_BANNER = b"220 (vsFTPd 3.0.3)\r\n"

FTP_RESPONSES: dict[str, str] = {
    "USER": "331 Please specify the password.\r\n",
    "PASS": "530 Login incorrect.\r\n",
    "SYST": "215 UNIX Type: L8\r\n",
    "PWD": "257 \"/\" is the current directory\r\n",
    "QUIT": "221 Goodbye.\r\n",
}
FTP_DEFAULT_RESPONSE = "502 Command not implemented.\r\n"


def parse_ftp_command(line: str) -> dict:
    """Split a raw FTP command line into {command, arg}. Never raises —
    an empty/malformed line just yields an empty command."""
    line = line.strip("\r\n").strip()
    if not line:
        return {"command": "", "arg": ""}
    parts = line.split(" ", 1)
    return {"command": parts[0].upper(), "arg": parts[1] if len(parts) > 1 else ""}


async def handle_ftp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      on_event: EventCallback) -> None:
    """Send a vsFTPd-style banner, then play along with plausible response
    codes for up to FTP_MAX_COMMANDS commands (typically USER/PASS
    credential-stuffing attempts), logging every command verbatim."""
    ip, port = _peer(writer)
    commands: list[dict] = []

    writer.write(FTP_BANNER)
    await writer.drain()

    for _ in range(FTP_MAX_COMMANDS):
        raw = await _read_with_timeout(reader, 1024, READ_TIMEOUT_SECONDS)
        if not raw:
            break
        parsed = parse_ftp_command(raw.decode("utf-8", errors="replace"))
        if not parsed["command"]:
            break
        commands.append(parsed)

        response = FTP_RESPONSES.get(parsed["command"], FTP_DEFAULT_RESPONSE)
        try:
            writer.write(response.encode())
            await writer.drain()
        except (ConnectionError, OSError):
            break
        if parsed["command"] == "QUIT":
            break

    payload = "\n".join(f"{c['command']} {c['arg']}".strip() for c in commands)
    await _safe_emit(on_event, {
        "service": "ftp",
        "source_ip": ip,
        "source_port": port,
        "payload": _truncate(payload.encode()),
        "session_data": {"commands": commands},
    })
    await _safe_close(writer)


# ── HTTP admin panel ────────────────────────────────────────────────────

HTTP_MAX_BYTES = 8192
FAKE_LOGIN_PAGE = (
    "<html><head><title>Admin Login</title></head><body>"
    "<h2>Administration Panel</h2>"
    "<form method='post' action='/login'>"
    "<input name='username' placeholder='Username'><br>"
    "<input name='password' type='password' placeholder='Password'><br>"
    "<button type='submit'>Login</button></form></body></html>"
)
# Header names worth keeping — everything else is discarded to bound
# session_data size regardless of how many headers a client sends.
_HEADERS_OF_INTEREST = ("user-agent", "host", "content-type", "authorization", "cookie")


def parse_http_request(raw: bytes) -> dict:
    """Best-effort parse of a raw HTTP request into
    {method, path, headers, body}. Never raises — malformed or partial
    input just yields empty fields, since a honeypot must swallow whatever
    an attacker throws at it."""
    try:
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.decode("utf-8", errors="replace").split("\r\n")
        request_line = lines[0] if lines else ""
        parts = request_line.split(" ")
        method = parts[0] if len(parts) > 0 else ""
        path = parts[1] if len(parts) > 1 else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return {"method": method, "path": path, "headers": headers,
                "body": body.decode("utf-8", errors="replace")}
    except Exception:
        return {"method": "", "path": "", "headers": {}, "body": ""}


async def handle_http_admin(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                             on_event: EventCallback) -> None:
    """Read one HTTP request, reply with a static fake admin login page
    (matching the trap style already used by
    modules.threat_intel.honeypot.deploy_honeypot_endpoint), and log the
    request method/path/headers/body."""
    ip, port = _peer(writer)
    raw = await _read_with_timeout(reader, HTTP_MAX_BYTES, READ_TIMEOUT_SECONDS)
    parsed = parse_http_request(raw)

    body_bytes = FAKE_LOGIN_PAGE.encode()
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(body_bytes)).encode() + b"\r\n"
        b"Server: Apache/2.4.41 (Ubuntu)\r\n"
        b"Connection: close\r\n\r\n" + body_bytes
    )
    with contextlib.suppress(ConnectionError, OSError):
        writer.write(response)
        await writer.drain()

    notable_payload = parsed["body"] or parsed["path"]
    await _safe_emit(on_event, {
        "service": "http_admin",
        "source_ip": ip,
        "source_port": port,
        "payload": _truncate(notable_payload.encode()),
        "session_data": {
            "method": parsed["method"],
            "path": parsed["path"],
            "headers": {k: v for k, v in parsed["headers"].items() if k in _HEADERS_OF_INTEREST},
        },
    })
    await _safe_close(writer)


# ── Generic server bootstrap ─────────────────────────────────────────────

HANDLERS: dict[str, Callable] = {
    "ssh": handle_ssh,
    "ftp": handle_ftp,
    "http_admin": handle_http_admin,
}


async def start_listener(service: str, host: str, port: int, on_event: EventCallback) -> asyncio.base_events.Server:
    """Bind an asyncio TCP server for `service` (ssh|ftp|http_admin) that
    hands every connection to its protocol handler. A crashing handler is
    caught and logged, never taking the listener itself down."""
    handler = HANDLERS[service]

    async def _on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await handler(reader, writer, on_event)
        except Exception:
            logger.exception("honeypot %s connection handler crashed", service)
            await _safe_close(writer)

    return await asyncio.start_server(_on_connect, host=host, port=port)
