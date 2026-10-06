"""Domain ownership verification -- the I/O side of scan authorization.

web/scan_authz.py decides what may run; this module proves the inputs it
trusts. Two methods:

  dns_txt    TXT record at  _optisec-verify.<domain>  with value
             optisec-verify=<token>. Covers the domain and all subdomains.
  http_file  https://<host>/.well-known/optisec-verify.txt (http:// as a
             fallback when https can't connect) whose body is exactly the
             token. Covers only that exact host.

The file fetch is SSRF-hardened: the host must not resolve to any internal
address, redirects are followed one hop at a time and only to the same host
on a default port, and at most _MAX_FILE_BYTES are read. The response body
is never echoed back to the user -- only "matched" or a fixed error string --
so a DNS-rebinding race between the resolve check and the fetch can at most
answer "token not found" about an internal URL, not leak its contents.

authorize_scan() is the DB-backed entry point endpoint gates call. Verified
records whose last check is older than SCAN_VERIFICATION_TTL_DAYS are
re-checked first, so removing the TXT record or file revokes access.
"""

import asyncio
import ipaddress
import logging
import os
import secrets
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from web.models import DomainVerification, User
from web.scan_authz import (
    ACTIVE_CHECKS, VERIFY_METHOD_DNS_TXT, VERIFY_METHOD_HTTP_FILE,
    AuthzDecision, VerifiedScope, decide, expand_checks, host_in_verified_scope,
    is_ip_literal, normalize_host,
)
from web.schemas import _is_ssrf_blocked_host

logger = logging.getLogger("optisec.scan_authz")

VERIFY_METHODS = (VERIFY_METHOD_DNS_TXT, VERIFY_METHOD_HTTP_FILE)
DNS_RECORD_PREFIX = "_optisec-verify"
DNS_VALUE_PREFIX = "optisec-verify="
FILE_PATH = "/.well-known/optisec-verify.txt"

STATUS_PENDING = "pending"
STATUS_VERIFIED = "verified"
STATUS_FAILED = "failed"
STATUS_REVOKED = "revoked"

_DNS_TIMEOUT = 10.0
_HTTP_TIMEOUT = 10.0
_MAX_FILE_BYTES = 4096
_MAX_REDIRECTS = 3


def verification_ttl() -> timedelta:
    return timedelta(days=float(os.environ.get("SCAN_VERIFICATION_TTL_DAYS", "7")))


def new_token() -> str:
    return secrets.token_urlsafe(32)


def validate_domain(raw: str) -> str:
    """Normalize a user-submitted domain for a new verification, or raise
    ValueError. Rejects IPs (nothing to verify against), single-label names
    and internal hosts."""
    domain = normalize_host(raw)
    if not domain:
        raise ValueError("Invalid domain")
    if is_ip_literal(domain):
        raise ValueError("IP addresses can't be verified; verify a domain name instead")
    if "." not in domain or len(domain) > 253:
        raise ValueError("Invalid domain")
    if _is_ssrf_blocked_host(domain):
        raise ValueError("Local/internal hosts can't be verified")
    return domain


def instructions(record: DomainVerification) -> dict:
    if record.method == VERIFY_METHOD_DNS_TXT:
        return {
            "type": "TXT",
            "name": f"{DNS_RECORD_PREFIX}.{record.domain}",
            "value": f"{DNS_VALUE_PREFIX}{record.token}",
            "covers": f"{record.domain} and all of its subdomains",
        }
    return {
        "url": f"https://{record.domain}{FILE_PATH}",
        "content": record.token,
        "covers": f"{record.domain} only",
    }


# ── Checks ────────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    verified: bool
    error: Optional[str] = None
    # True when the check couldn't reach a verdict (timeout, connection
    # failure, 5xx). A transient failure never revokes an existing
    # verification, but it doesn't grant anything either.
    transient: bool = False


async def _resolve_txt(name: str) -> list:
    """TXT strings at `name`. Separate seam so tests don't touch the network."""
    answer = await dns.asyncresolver.resolve(name, "TXT", lifetime=_DNS_TIMEOUT)
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


async def check_dns_txt(domain: str, token: str) -> CheckResult:
    try:
        values = await _resolve_txt(f"{DNS_RECORD_PREFIX}.{domain}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return CheckResult(False, "TXT record not found")
    except dns.exception.DNSException:  # timeout, SERVFAIL/no nameservers, ...
        return CheckResult(False, "DNS lookup failed; try again later", transient=True)
    expected = f"{DNS_VALUE_PREFIX}{token}"
    if any(v.strip() == expected for v in values):
        return CheckResult(True)
    return CheckResult(False, "TXT record found but the token does not match")


async def _resolve_addresses(host: str) -> list:
    infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
    return [info[4][0] for info in infos]


def _is_internal_address(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%", 1)[0])
    return (
        ip.is_loopback or ip.is_link_local or ip.is_private
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _http_client() -> httpx.AsyncClient:
    """Separate seam so tests can inject an httpx.MockTransport."""
    return httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False)


class _Definitive(Exception):
    pass


async def _fetch_token_file(client: httpx.AsyncClient, host: str, url: str) -> bytes:
    for _ in range(_MAX_REDIRECTS + 1):
        async with client.stream("GET", url) as r:
            if r.is_redirect and "location" in r.headers:
                nxt = urlparse(urljoin(url, r.headers["location"]))
                if nxt.scheme not in ("http", "https") or nxt.hostname != host or nxt.port is not None:
                    raise _Definitive("Verification file redirects to a different host")
                url = nxt.geturl()
                continue
            if r.status_code >= 500:
                raise httpx.HTTPError(f"server error {r.status_code}")
            if r.status_code != 200:
                raise _Definitive("Verification file not found")
            body = b""
            async for chunk in r.aiter_bytes():
                body += chunk
                if len(body) > _MAX_FILE_BYTES:
                    raise _Definitive("Verification file is too large")
            return body
    raise _Definitive("Too many redirects")


async def check_http_file(host: str, token: str) -> CheckResult:
    if _is_ssrf_blocked_host(host):
        return CheckResult(False, "Local/internal hosts can't be verified")
    try:
        addrs = await _resolve_addresses(host)
    except (socket.gaierror, UnicodeError):
        return CheckResult(False, "Host does not resolve; try again later", transient=True)
    if not addrs or any(_is_internal_address(a) for a in addrs):
        return CheckResult(False, "Host resolves to an internal address")

    async with _http_client() as client:
        for scheme in ("https", "http"):
            try:
                body = await _fetch_token_file(client, host, f"{scheme}://{host}{FILE_PATH}")
            except _Definitive as e:
                return CheckResult(False, str(e))
            except httpx.ConnectError:
                continue  # https not served -- fall back to http
            except httpx.HTTPError:
                return CheckResult(False, "Could not fetch the verification file; try again later", transient=True)
            if body.decode("utf-8", "replace").strip() == token:
                return CheckResult(True)
            return CheckResult(False, "Verification file found but the token does not match")
    return CheckResult(False, "Could not connect to the host; try again later", transient=True)


async def run_check(record: DomainVerification, now: Optional[datetime] = None) -> CheckResult:
    """Run the record's check and update its status in place (caller commits).

    pending/failed/revoked -> verified on success
    verified -> revoked, pending -> failed on a definitive failure
    transient failures only record last_error
    """
    now = now or datetime.utcnow()
    if record.method == VERIFY_METHOD_DNS_TXT:
        result = await check_dns_txt(record.domain, record.token)
    else:
        result = await check_http_file(record.domain, record.token)

    if result.verified:
        if record.status != STATUS_VERIFIED:
            record.verified_at = now
        record.status = STATUS_VERIFIED
        record.last_checked_at = now
        record.last_error = None
    elif result.transient:
        record.last_error = result.error
        if record.status == STATUS_PENDING:
            record.status = STATUS_FAILED
    else:
        record.status = STATUS_REVOKED if record.status == STATUS_VERIFIED else STATUS_FAILED
        record.last_checked_at = now
        record.last_error = result.error
    return result


# ── DB-backed authorization ───────────────────────────────────────────────────

async def authorize_scan(
    db: AsyncSession,
    user: User,
    target: str,
    scan_types: Optional[Iterable[str]],
    now: Optional[datetime] = None,
) -> AuthzDecision:
    """decide() fed with the user's own currently-verified domains. Only
    records that actually cover the target are looked at, and any of those
    past the TTL are re-checked (and committed) before being trusted."""
    checks = expand_checks(scan_types)
    host = normalize_host(target)
    if not (set(checks) & ACTIVE_CHECKS) or not host or is_ip_literal(host):
        return decide(target, checks)

    now = now or datetime.utcnow()
    records = (await db.execute(
        select(DomainVerification).where(
            DomainVerification.user_id == user.id,
            DomainVerification.status == STATUS_VERIFIED,
        )
    )).scalars().all()

    scopes = []
    changed = False
    for rec in records:
        scope = VerifiedScope(rec.domain, rec.method)
        if host_in_verified_scope(host, [scope]) is None:
            continue
        if rec.last_checked_at is None or now - rec.last_checked_at > verification_ttl():
            result = await run_check(rec, now)
            changed = True
            if not result.verified:
                continue
        scopes.append(scope)
    if changed:
        await db.commit()

    return decide(target, checks, scopes)


# ── Endpoint gate ─────────────────────────────────────────────────────────────

def scan_authz_enforced() -> bool:
    """SCAN_AUTHZ_ENFORCE=false is a one-deploy, log-only rollout switch:
    denials are still logged, but active checks run anyway. Defaults to
    enforcing; anything other than an explicit false value enforces."""
    return os.environ.get("SCAN_AUTHZ_ENFORCE", "true").strip().lower() not in ("false", "0", "no", "off")


async def check_scan_authorization(
    db: AsyncSession,
    user: User,
    target: str,
    scan_types: Optional[Iterable[str]],
    *,
    source: str,
) -> AuthzDecision:
    """What every scan-launching endpoint calls. Logs each denial with the
    calling `source`, and in log-only mode (see scan_authz_enforced) turns
    denied active checks into allowed ones -- unknown check names stay
    denied either way, since nothing could run them."""
    decision = await authorize_scan(db, user, target, scan_types)
    if not decision.denied:
        return decision

    enforced = scan_authz_enforced()
    logger.warning(
        "scan_authz denied source=%s user_id=%s target=%r denied=%s basis=%s enforced=%s",
        source, user.id, target, sorted(decision.denied), decision.basis, enforced,
    )
    if enforced:
        return decision

    bypassed = decision.denied & ACTIVE_CHECKS
    decision.allowed |= bypassed
    decision.denied -= bypassed
    decision.basis = f"unenforced:{decision.basis}"
    if not decision.denied:
        decision.reason = None
    return decision


def denial_response(decision: AuthzDecision) -> JSONResponse:
    return JSONResponse({
        "error": decision.reason or "Scan not authorized",
        "denied_checks": sorted(decision.denied),
        "allowed_checks": sorted(decision.allowed),
        "verify_endpoint": "/api/domains/verify",
    }, status_code=403)
