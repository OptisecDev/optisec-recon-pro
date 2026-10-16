"""Scan authorization policy (decision "Option B").

Passive checks may run against any target. Active checks -- anything that
sends attack or probe traffic to the target's own infrastructure -- run only
when the target host is either:

  * covered by a domain the requesting user has verified ownership of
    (DNS TXT record, or a token file served from the host), or
  * on the hardcoded TRAINING_TARGETS allowlist, and then only for the
    checks that site's own published terms permit.

This module is the pure policy layer: classification, host normalization,
the training allowlist, and decide(). It does no I/O. The verification
records themselves (and the DB-backed wrapper that feeds them into decide())
come with the DomainVerification model; the endpoint gates come after that.
Every gate is meant to call through here so the rules live in one place.

Classification notes:
  * ssl / headers are passive: one TLS handshake or one GET, the same traffic
    an ordinary visitor's browser generates.
  * subdomain is active: modules/recon/subdomains.py brute-forces a wordlist
    and then opens TLS + HTTP HEAD connections to every name that resolves.
  * Any check name not in either set is denied, so a new scan module has to
    be classified here before it can run at all.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, Optional
from urllib.parse import urlparse

PASSIVE_CHECKS = frozenset({"dns", "whois", "osint", "ssl", "headers"})
ACTIVE_CHECKS = frozenset({
    "nmap", "ports", "subdomain", "xss", "sqli", "ssrf", "lfi", "redirect",
})
ALL_CHECKS = PASSIVE_CHECKS | ACTIVE_CHECKS

# Order _run_scan_task (web/app.py) runs its steps in -- what an empty
# `scan_types` ("run all modules") expands to before authorization, so
# "run everything" can never skip the check.
SCAN_STEP_ORDER = (
    "subdomain", "dns", "whois", "nmap", "ssl", "headers", "ports",
    "xss", "sqli", "ssrf", "lfi", "redirect", "osint",
)

_WEB_VULN_CHECKS = frozenset({"xss", "sqli", "ssrf", "lfi", "redirect"})

# Public, intentionally-vulnerable training hosts. Exact-host match only (no
# wildcards, no subdomains), and hardcoded rather than env-configurable, same
# as ALLOWED_TARGETS in scripts/bounty_scan*.py. Each entry is limited to what
# that site's own published text permits; quotes below were checked against
# the live pages on 2026-10-06.
TRAINING_TARGETS: dict = {
    # http://scanme.nmap.org/ -- "You are authorized to scan this machine with
    # Nmap or other port scanners. Try not to hammer on the server too hard."
    # Port scanning only: no web attacks, no brute force.
    "scanme.nmap.org": frozenset({"nmap", "ports"}),
    # https://public-firing-range.appspot.com/ -- "Firing Range is a test bed
    # for automated web application security scanners." Its test cases are
    # XSS and redirect variants.
    "public-firing-range.appspot.com": frozenset({"xss", "redirect"}),
    # http://testasp.vulnweb.com/ -- "TEST and Demonstration site for Acunetix
    # Web Vulnerability Scanner".
    "testasp.vulnweb.com": _WEB_VULN_CHECKS,
    # http://testaspnet.vulnweb.com/ -- "Test Website for Acunetix Web
    # Vulnerability Scanner".
    "testaspnet.vulnweb.com": _WEB_VULN_CHECKS,
    # http://demo.testfire.net/ -- "published by HCL Technologies, Ltd. for the
    # sole purpose of demonstrating the effectiveness of HCL products in
    # detecting web application vulnerabilities ... This site is not a real
    # banking site."
    "demo.testfire.net": _WEB_VULN_CHECKS,
    # http://zero.webappsecurity.com/ -- "published by Micro Focus Fortify for
    # the sole purpose of demonstrating the functionality and effectiveness of
    # Micro Focus Fortify's WebInspect products in detecting and reporting Web
    # application vulnerabilities. This site is not a real banking site".
    "zero.webappsecurity.com": _WEB_VULN_CHECKS,
}

VERIFY_METHOD_DNS_TXT = "dns_txt"
VERIFY_METHOD_HTTP_FILE = "http_file"


@dataclass(frozen=True)
class VerifiedScope:
    """One verified domain, as decide() needs it. A dns_txt verification
    covers the domain and every subdomain of it; an http_file verification
    covers only that exact host."""
    domain: str
    method: str


@dataclass
class AuthzDecision:
    allowed: set = field(default_factory=set)
    denied: set = field(default_factory=set)
    # "passive_only" | "verified:<method>:<domain>" | "training:<host>"
    basis: str = "passive_only"
    reason: Optional[str] = None

    @property
    def ok(self) -> bool:
        return not self.denied


def normalize_host(target: str) -> str:
    """Reduce a user-supplied URL or bare host to a comparable hostname:
    lowercase, no scheme/userinfo/port/path, no trailing dot, IDNA-encoded.
    Returns "" if no hostname can be extracted."""
    target = (target or "").strip()
    if not target:
        return ""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    try:
        host = parsed.hostname or ""
    except ValueError:
        return ""
    host = host.rstrip(".").lower()
    if not host:
        return ""
    if is_ip_literal(host):
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def expand_checks(scan_types: Optional[Iterable[str]]) -> list:
    """An empty/None `scan_types` means "run all modules" -- expand it to the
    full step list so the authorization decision sees every check."""
    requested = list(scan_types or [])
    if not requested:
        return list(SCAN_STEP_ORDER)
    seen = set()
    out = []
    for c in requested:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def host_in_verified_scope(host: str, scopes: Iterable[VerifiedScope]) -> Optional[VerifiedScope]:
    """The first scope covering `host`, or None. IP literals are never
    covered: there is no DNS name to put a TXT record on, and a file served
    from an IP proves nothing about who else answers on it."""
    if not host or is_ip_literal(host):
        return None
    for s in scopes:
        domain = normalize_host(s.domain)
        if not domain:
            continue
        if s.method == VERIFY_METHOD_DNS_TXT:
            if host == domain or host.endswith("." + domain):
                return s
        elif s.method == VERIFY_METHOD_HTTP_FILE:
            if host == domain:
                return s
    return None


def decide(
    target: str,
    scan_types: Optional[Iterable[str]],
    verified_scopes: Iterable[VerifiedScope] = (),
) -> AuthzDecision:
    """Pure authorization decision for running `scan_types` against `target`.

    `verified_scopes` must already be filtered to the requesting user's own,
    currently-verified records -- this function trusts them as given.
    """
    checks = expand_checks(scan_types)
    host = normalize_host(target)
    decision = AuthzDecision()

    unknown = {c for c in checks if c not in ALL_CHECKS}
    active = {c for c in checks if c in ACTIVE_CHECKS}
    decision.allowed = {c for c in checks if c in PASSIVE_CHECKS}
    decision.denied = set(unknown)

    if not host:
        decision.allowed = set()
        decision.denied = set(checks)
        decision.reason = "Invalid target"
        return decision

    if active:
        scope = host_in_verified_scope(host, verified_scopes)
        training = TRAINING_TARGETS.get(host)
        if scope is not None:
            decision.allowed |= active
            decision.basis = f"verified:{scope.method}:{normalize_host(scope.domain)}"
        elif training is not None:
            decision.allowed |= active & training
            decision.denied |= active - training
            decision.basis = f"training:{host}"
        else:
            decision.denied |= active

    if decision.denied:
        parts = []
        if decision.denied & ACTIVE_CHECKS:
            if decision.basis.startswith("training:"):
                parts.append(
                    f"{host} is a training target that only permits: "
                    f"{', '.join(sorted(TRAINING_TARGETS[host]))}"
                )
            else:
                parts.append(
                    "Active checks require verifying ownership of this domain "
                    "(DNS TXT record or verification file)"
                )
        if unknown:
            parts.append(f"Unknown scan type(s): {', '.join(sorted(unknown))}")
        decision.reason = ". ".join(parts)

    return decision


def scope_targets(decision: AuthzDecision) -> Optional[tuple]:
    """(exact_hosts, domain_suffixes) an active scan under `decision` may
    contact -- the input to modules/scan_scope.build_scope(). None only when
    nothing active was allowed (passive_only), so no network scope applies.

    A dns_txt verification covers the domain and its subdomains (suffix); a
    file verification or a training target covers only that exact host. Any
    other basis or verification method yields an empty scope -- nothing
    reachable -- rather than an unrestricted one (fail-closed).
    """
    kind, _, rest = decision.basis.partition(":")
    if kind == "verified":
        method, _, domain = rest.partition(":")
        if method == VERIFY_METHOD_DNS_TXT:
            return frozenset(), frozenset({domain})
        if method == VERIFY_METHOD_HTTP_FILE:
            return frozenset({domain}), frozenset()
        return frozenset(), frozenset()
    if kind == "training":
        return frozenset({rest}), frozenset()
    if kind == "passive_only":
        return None
    return frozenset(), frozenset()
