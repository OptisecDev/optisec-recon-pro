"""
Honeypot manager — lifecycle + DB persistence for the lightweight
service-emulating listeners in modules/honeypot/listeners.py.

╔══════════════════════════ SAFETY / ISOLATION ══════════════════════════╗
The honeypot listeners never execute, evaluate or forward attacker input —
they only read bytes off the wire, log them, and reply with a static or
templated banner/page (see listeners.py's module docstring). Every
listener:
  - binds an *unprivileged, non-standard* port that never overlaps a port
    any real OPTISEC service uses. Defaults below (2222/2121/8081) are
    deliberately far from 22/21/80/443/8000 — the real SSH/FTP/HTTP admin
    ports this app or its host might otherwise run. Do NOT repoint
    HONEYPOT_*_PORT at a real service's port: a honeypot sharing a port
    with production traffic defeats the entire point of isolating it;
  - is entirely opt-in via HONEYPOT_ENABLED (default: disabled) — it must
    be turned on deliberately per deployment, and each of the three
    services can also be disabled individually via
    HONEYPOT_<SERVICE>_ENABLED;
  - caps how much it reads per connection/session
    (listeners.MAX_PAYLOAD_BYTES, listeners.FTP_MAX_COMMANDS) so a
    malicious peer can never force unbounded memory or CPU use;
  - runs its accept loop as plain asyncio tasks inside the same event loop
    as the rest of the app (no subprocess, no elevated privileges, no
    filesystem/shell access) — a hung or crashing handler is caught and
    logged (listeners.start_listener), never taking the app down.
╚══════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import logging
import os
from datetime import datetime

from modules.honeypot import listeners

logger = logging.getLogger("honeypot.manager")

DEFAULT_PORTS = {"ssh": 2222, "ftp": 2121, "http_admin": 8081}

_servers: dict[str, "object"] = {}


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _port_env(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        logger.warning("invalid %s=%r, using default %d", name, raw, default)
        return default
    return value if 0 < value < 65536 else default


def is_enabled() -> bool:
    return _bool_env("HONEYPOT_ENABLED", False)


def get_bind_host() -> str:
    return os.environ.get("HONEYPOT_BIND_HOST", "0.0.0.0")


def service_config() -> dict[str, dict]:
    """Per-service {enabled, port}, read fresh from env every call so tests
    can monkeypatch env vars without reload tricks."""
    return {
        "ssh": {"enabled": _bool_env("HONEYPOT_SSH_ENABLED", True),
                "port": _port_env("HONEYPOT_SSH_PORT", DEFAULT_PORTS["ssh"])},
        "ftp": {"enabled": _bool_env("HONEYPOT_FTP_ENABLED", True),
                "port": _port_env("HONEYPOT_FTP_PORT", DEFAULT_PORTS["ftp"])},
        "http_admin": {"enabled": _bool_env("HONEYPOT_HTTP_ENABLED", True),
                        "port": _port_env("HONEYPOT_HTTP_PORT", DEFAULT_PORTS["http_admin"])},
    }


# ── Persistence ──────────────────────────────────────────────────────────

async def record_event(event: dict) -> None:
    """The on_event callback wired into every listener: enrich the source
    IP (geolocation + AbuseIPDB) and persist a HoneypotEvent row. Never
    raises — a storage or enrichment failure must never crash a listener's
    connection handler."""
    from modules.honeypot.enrichment import enrich_ip
    from web.database import SessionLocal
    from web.models import HoneypotEvent

    ip = event.get("source_ip", "unknown")
    try:
        enrichment = await enrich_ip(ip)
    except Exception:
        logger.exception("honeypot enrichment failed for ip=%s", ip)
        enrichment = {"country": None, "country_code": None, "city": None, "isp": None,
                       "abuse_score": 0, "risk_level": "UNKNOWN"}

    try:
        async with SessionLocal() as db:
            db.add(HoneypotEvent(
                service=event.get("service", "unknown"),
                source_ip=ip,
                source_port=event.get("source_port"),
                dest_port=event.get("dest_port"),
                payload=event.get("payload", ""),
                session_data=event.get("session_data") or {},
                country=enrichment.get("country"),
                country_code=enrichment.get("country_code"),
                city=enrichment.get("city"),
                isp=enrichment.get("isp"),
                abuse_score=enrichment.get("abuse_score", 0),
                risk_level=enrichment.get("risk_level", "UNKNOWN"),
                enrichment=enrichment,
                created_at=datetime.utcnow(),
            ))
            await db.commit()
        logger.info(
            "honeypot hit service=%s ip=%s risk=%s abuse_score=%s",
            event.get("service"), ip, enrichment.get("risk_level"), enrichment.get("abuse_score"),
        )
    except Exception:
        logger.exception("failed to persist honeypot event service=%s ip=%s", event.get("service"), ip)


# ── Lifecycle ────────────────────────────────────────────────────────────

async def start_honeypots() -> dict:
    """Start every enabled listener. No-op (returns disabled status) unless
    HONEYPOT_ENABLED=true. Safe to call more than once — already-running
    services are left untouched. Must be called from within a running
    asyncio event loop (e.g. FastAPI's startup event)."""
    if not is_enabled():
        logger.info("honeypot disabled (HONEYPOT_ENABLED not set) — not starting listeners")
        return get_status()

    host = get_bind_host()
    for service, cfg in service_config().items():
        if not cfg["enabled"]:
            continue
        if service in _servers:
            continue
        try:
            server = await listeners.start_listener(service, host, cfg["port"], record_event)
            _servers[service] = server
            logger.info("honeypot listener started service=%s host=%s port=%d", service, host, cfg["port"])
        except OSError:
            logger.exception("honeypot listener failed to bind service=%s host=%s port=%d", service, host, cfg["port"])

    return get_status()


async def stop_honeypots() -> None:
    """Stop every running listener. Safe to call even if never started."""
    for service, server in list(_servers.items()):
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            logger.exception("error while stopping honeypot listener service=%s", service)
        logger.info("honeypot listener stopped service=%s", service)
    _servers.clear()


def get_status() -> dict:
    """Snapshot for GET /api/honeypot/status — whether the honeypot subsystem
    is enabled and which listeners are actually bound right now."""
    cfg = service_config()
    return {
        "enabled": is_enabled(),
        "bind_host": get_bind_host(),
        "services": {
            service: {
                "enabled": settings["enabled"],
                "port": settings["port"],
                "listening": service in _servers,
                "label_ar": listeners.SERVICE_LABELS_AR.get(service, service),
            }
            for service, settings in cfg.items()
        },
    }
