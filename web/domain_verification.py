"""Domain ownership verification -- the I/O side of scan authorization.

web/scan_authz.py decides what may run; this module proves the inputs it
trusts. The only method is DNS TXT:

  dns_txt    TXT record at  _optisec-verify.<domain>  with value
             optisec-verify=<token>. Covers the domain and all subdomains.

The token is generated here (secrets.token_urlsafe), stored on the user's
own DomainVerification row, and only ever returned to that user.

authorize_scan() is the DB-backed entry point endpoint gates call. Every
verified record covering the target is re-checked against live DNS before
each active scan, and anything short of a matching TXT answer -- record
gone, wrong token, timeout, resolver error, unexpected exception -- denies
the active checks (fail-closed). There is no switch that relaxes this.
"""

import asyncio
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional

import dns.asyncresolver
import dns.exception
import dns.resolver
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from modules.scan_scope import ScanScope, build_scope
from web.models import DomainVerification, User
from web.scan_authz import (
    ACTIVE_CHECKS, VERIFY_METHOD_DNS_TXT,
    AuthzDecision, VerifiedScope, decide, expand_checks, host_in_verified_scope,
    is_ip_literal, normalize_host, scope_targets,
)
from web.schemas import _is_ssrf_blocked_host

logger = logging.getLogger("optisec.scan_authz")

VERIFY_METHODS = (VERIFY_METHOD_DNS_TXT,)
DNS_RECORD_PREFIX = "_optisec-verify"
DNS_VALUE_PREFIX = "optisec-verify="

STATUS_PENDING = "pending"
STATUS_VERIFIED = "verified"
STATUS_FAILED = "failed"
STATUS_REVOKED = "revoked"

_DNS_TIMEOUT = 10.0


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
    if record.method != VERIFY_METHOD_DNS_TXT:
        return {"error": "Only DNS TXT verification is supported; create a dns_txt verification instead"}
    return {
        "type": "TXT",
        "name": f"{DNS_RECORD_PREFIX}.{record.domain}",
        "value": f"{DNS_VALUE_PREFIX}{record.token}",
        "covers": f"{record.domain} and all of its subdomains",
    }


# ── Checks ────────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    verified: bool
    error: Optional[str] = None
    # True when the check couldn't reach a verdict (timeout, resolver
    # failure). A transient failure never revokes an existing verification,
    # but it doesn't grant anything either.
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
        result = CheckResult(False, "Only DNS TXT verification is supported")

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
    """decide() fed with the user's own domains whose TXT record matches
    right now. Only dns_txt records that actually cover the target are
    looked at, and each is re-checked against live DNS (and the result
    committed) before being trusted -- no cached verdict grants anything.
    A check that fails for any reason, including an unexpected exception,
    leaves the record out, so the active checks are denied."""
    checks = expand_checks(scan_types)
    host = normalize_host(target)
    if not (set(checks) & ACTIVE_CHECKS) or not host or is_ip_literal(host):
        return decide(target, checks)

    now = now or datetime.utcnow()
    records = (await db.execute(
        select(DomainVerification).where(
            DomainVerification.user_id == user.id,
            DomainVerification.status == STATUS_VERIFIED,
            DomainVerification.method == VERIFY_METHOD_DNS_TXT,
        )
    )).scalars().all()

    scopes = []
    changed = False
    for rec in records:
        scope = VerifiedScope(rec.domain, rec.method)
        if host_in_verified_scope(host, [scope]) is None:
            continue
        try:
            result = await run_check(rec, now)
        except Exception:
            logger.exception("scan_authz dns check crashed user_id=%s domain=%r", user.id, rec.domain)
            continue
        changed = True
        if result.verified:
            scopes.append(scope)
    if changed:
        await db.commit()

    return decide(target, checks, scopes)


# ── Endpoint gate ─────────────────────────────────────────────────────────────

async def check_scan_authorization(
    db: AsyncSession,
    user: User,
    target: str,
    scan_types: Optional[Iterable[str]],
    *,
    source: str,
) -> AuthzDecision:
    """What every scan-launching endpoint calls, right before it runs
    anything. Logs each denial with the calling `source`; a denied decision
    always means the caller must return denial_response() -- there is no
    log-only or override mode."""
    decision = await authorize_scan(db, user, target, scan_types)
    if decision.denied:
        logger.warning(
            "scan_authz denied source=%s user_id=%s target=%r denied=%s basis=%s",
            source, user.id, target, sorted(decision.denied), decision.basis,
        )
    return decision


async def load_verified_scopes(db: AsyncSession, user: User) -> list:
    rows = (await db.execute(
        select(DomainVerification.domain, DomainVerification.method).where(
            DomainVerification.user_id == user.id,
            DomainVerification.status == STATUS_VERIFIED,
            DomainVerification.method == VERIFY_METHOD_DNS_TXT,
        )
    )).all()
    return [VerifiedScope(domain, method) for domain, method in rows]


async def preview_authorization(
    db: AsyncSession, user: User, target: str, scopes: Optional[list] = None,
) -> AuthzDecision:
    """What the UI shows before a scan: the decision for every check, with
    no network I/O and no logging. Verified records are taken at face value
    here -- check_scan_authorization() re-checks DNS when a scan is actually
    launched, so the preview can only be more permissive than the real gate,
    never let anything run by itself. Pass `scopes` (from
    load_verified_scopes) to preview many targets with one query."""
    if scopes is None:
        scopes = await load_verified_scopes(db, user)
    return decide(target, None, scopes)


async def network_scope_for(decision: AuthzDecision, target: str) -> Optional[ScanScope]:
    """The ScanScope active checks under `decision` must stay inside (see
    modules/scan_scope.py), or None for a passive-only decision, which runs
    no active step. Resolves DNS, off the event loop."""
    targets = scope_targets(decision)
    if targets is None:
        return None
    hosts, suffixes = targets
    return await asyncio.to_thread(build_scope, hosts, suffixes, [normalize_host(target)])


def denial_response(decision: AuthzDecision) -> JSONResponse:
    return JSONResponse({
        "error": decision.reason or "Scan not authorized",
        "denied_checks": sorted(decision.denied),
        "allowed_checks": sorted(decision.allowed),
        "verify_endpoint": "/api/domains/verify",
    }, status_code=403)
