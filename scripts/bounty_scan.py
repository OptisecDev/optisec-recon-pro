"""Scoped bounty-engagement scan for the Verisign Tier-2 web scope.

Intended engagement targets (SCAN_TARGETS below):
    - blog.verisign.com        (WordPress + MySQL — scanned first; see
                                 PRIORITY_TARGET below)
    - www.verisign.com
    - namestudio.com
    - namestudioforsocial.com
    - youcouldbe.com

Authorization is NOT self-granted by this script. Before any connection to
a target, every active check goes through
web.domain_verification.check_scan_authorization() — the same gate
/api/scan uses — which permits active checks only against a domain the
running user (BOUNTY_SCAN_USERNAME) has verified with a DNS TXT token, or a
listed training target (web.scan_authz). Any denial, or any error during
the check, stops the run with a non-zero exit (fail-closed). The scan's own
traffic is then confined to that authorization's network scope
(web.domain_verification.network_scope_for / modules.scan_scope), which
replaces the former hardcoded ALLOWED_TARGETS allowlist.

Reuses the project's existing scan engine:
    - DNS analysis        modules/recon/dns_lookup.py
    - WHOIS analysis       modules/recon/whois_lookup.py
    - Network Intelligence modules/osint/network_intelligence.py
                           (Shodan/Censys/BGP passive lookups ONLY — see
                           "Explicitly excluded" below for why the module's
                           bundled TLS probe and deep_scan fingerprinting are
                           skipped)
    - XSS / SSRF / LFI     modules/vuln/xss.py, ssrf.py, lfi.py
    - Confidence scoring   modules/osint/confidence_engine.py
    - MITRE ATT&CK mapping modules/osint/mitre_mapping.py

Priority — blog.verisign.com first: it's WordPress + MySQL, a stack with a
much larger historical vulnerability surface than the other targets in this
scope. SCAN_TARGETS lists it first and main() scans hosts strictly in that
order (no cross-host concurrency), so every available check
(XSS/SSRF/LFI — and auth/authz, once a scanner for it exists; see
NOT_IMPLEMENTED) runs to completion against blog.verisign.com before the
rest of the scope is touched.

Responsible Disclosure — proof-of-concept evidence only, per Verisign's
Responsible Disclosure Policy: this scanner gathers a single confirming
payload/response per finding and does not keep probing a target for deeper
impact or additional issues once a vulnerability is confirmed.
modules/vuln/{xss,ssrf,lfi}.py already stop trying further payloads for a
given parameter the moment one confirms (their per-parameter `break` on
`result.should_report`); _run_vuln_scans() below extends the same rule to
the whole host — once any scan call returns a CONFIRMED finding, no further
scan calls run against that host for the rest of this process.

Explicitly excluded from this run, even though the underlying module exists
in the codebase:
    - Denial-of-service testing              — never in scope; nothing here
      floods, force-multiplies, or load-tests any target.
    - Username/email enumeration             — modules/osint/unified_engine.py's
      holehe/maigret/theHarvester/email_finder sources are never imported.
    - Open redirect testing                  — modules/vuln/open_redirect.py
      is never imported.
    - Clickjacking testing                   — modules/recon/security_headers.py
      is never imported (its X-Frame-Options check exists specifically to
      flag clickjacking exposure).
    - Fingerprinting / banner disclosure      — modules/recon/security_headers.py
      is never imported (its DANGEROUS_HEADERS check — Server, X-Powered-By,
      etc. — is the only such logic in this codebase).
    - Accessible-file checks (robots.txt, README, etc.) — no such scanner
      exists anywhere in this codebase; nothing to import or skip.
    - Cookie-flag checks (Secure/HttpOnly/SameSite)      — no such scanner
      exists anywhere in this codebase; nothing to import or skip.
    - TLS/SSL configuration checks           — modules/osint/network_intelligence.py's
      gather_network_intelligence() unconditionally opens a direct TLS
      handshake to the target (see its own docstring: "SSL/TLS analysis
      opens its own raw socket... directly at the target") and its
      deep_scan=True path does active port/service fingerprinting. Neither
      is used here: this script calls the passive Shodan/Censys/BGP
      sub-functions directly instead of the bundled orchestrator, so no TLS
      probe or active fingerprint ever reaches the target.

Not implemented (no corresponding scanner exists anywhere in this codebase
today — see "not_implemented" in each target's report section rather than
a silent gap):
    - CSRF detection
    - Authentication/authorization flaw detection
    - XXE detection
    - Server-side code execution / command injection checks

Scope enforcement: every request modules/vuln/xss.py, ssrf.py, and lfi.py
issue goes through Python's `requests` library. xss.py's form scanner in
particular can resolve a form's `action` attribute to an absolute,
off-target URL via urljoin() — so rather than trusting scanner-constructed
URLs to stay in scope, this script reuses the project's shared network
guard (modules/scan_scope.py): install_scope_guard() patches the same two
choke points the /api/scan path uses — requests' HTTPAdapter.send (the
original request and every redirect hop) and socket.create_connection (any
raw TCP connection, including _tcp_reachable()'s preflight probe) — and
run_in_scope() runs each active step inside the ScanScope returned by
network_scope_for() for this host's authorization decision. A connection to
anything outside that scope is blocked and recorded on the scope; the
report's "scope_enforcement" section surfaces those blocked attempts. The
scope is derived from the authorization decision, not from a hardcoded
in-script allowlist.

Passive OSINT lookups (Shodan InternetDB/API, Censys, BGPView/RIPEstat,
system DNS resolver, domain WHOIS registries) are not subject to this
guard — they query third-party infrastructure about the targets rather
than sending traffic to the targets themselves, which is the intended,
narrower scope of the guard.

Usage:
    BOUNTY_SCAN_USERNAME=<user> python scripts/bounty_scan.py

BOUNTY_SCAN_USERNAME names the user whose DNS-TXT-verified domains authorize
the active checks; the run refuses (non-zero exit) if it is unset, names no
existing user, or does not authorize a target.

Output: a timestamped JSON report under REPORTS_DIR (config.py), containing
confidence scores and MITRE ATT&CK mapping per finding. Nothing sensitive
(WHOIS registrant data, raw HTTP response bodies) is printed to stdout —
only a summary. The full report file may still contain such data, so treat
it with the same care as any other engagement artifact.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from config import REPORTS_DIR  # noqa: E402
from modules.osint.confidence_engine import calculate_confidence, classify_severity  # noqa: E402
from modules.osint.mitre_mapping import finding_type_from_scan_results, generate_attack_path  # noqa: E402
# Passive sub-functions of modules/osint/network_intelligence.py, called
# directly instead of gather_network_intelligence() to avoid its bundled TLS
# probe (see module docstring). These are private (underscore-prefixed)
# names not meant as public API outside this module — imported deliberately
# here, in preference to re-probing the target's TLS ourselves.
from modules.osint.network_intelligence import _query_bgp, _query_censys, _query_shodan  # noqa: E402
from modules.recon.dns_lookup import dns_lookup, reverse_lookup  # noqa: E402
from modules.recon.whois_lookup import whois_lookup  # noqa: E402
from modules.scan_scope import ScanScope, install_scope_guard, run_in_scope  # noqa: E402
from modules.vuln.lfi import scan_lfi  # noqa: E402
from modules.vuln.ssrf import scan_ssrf  # noqa: E402
from modules.vuln.xss import scan_xss  # noqa: E402
from web.database import SessionLocal  # noqa: E402
from web.domain_verification import check_scan_authorization, network_scope_for  # noqa: E402
from web.models import User  # noqa: E402

# Active checks this script sends at a target, named as web/scan_authz.py
# classifies them: the XSS/SSRF/LFI payload matrix plus the _tcp_reachable()
# port preflight. These are passed to check_scan_authorization() — the same
# gate /api/scan uses — so the run is authorized for exactly what it does.
AUTHZ_CHECKS: tuple[str, ...] = ("ports", "xss", "ssrf", "lfi")
AUTHZ_SOURCE = "bounty_scan"

# blog.verisign.com is WordPress + MySQL — a much larger historical
# vulnerability surface than the other targets in this scope — so it is
# scanned first, ahead of the rest.
PRIORITY_TARGET = "blog.verisign.com"
SCAN_TARGETS: tuple[str, ...] = (
    PRIORITY_TARGET,
    "www.verisign.com",
    "namestudio.com",
    "namestudioforsocial.com",
    "youcouldbe.com",
)

# modules/vuln/*.py report a categorical WAF-aware verdict, not a numeric
# confidence — this maps that verdict onto a 0-1 score for the unified
# report, per waf_aware_classifier.py's own verdict semantics (only
# CONFIRMED is a should_report=True signal).
VERDICT_CONFIDENCE: dict[str, float] = {
    "CONFIRMED": 0.95,
    "INCONCLUSIVE": 0.4,
    "WAF_BLOCKED": 0.15,
    "ENCODED_SAFE": 0.05,
    "ENDPOINT_INVALID": 0.0,
}

NOT_IMPLEMENTED = {
    "csrf": "No CSRF-testing module exists in this codebase "
            "(modules/vuln/ only has xss.py, sqli.py, ssrf.py, lfi.py, open_redirect.py).",
    "authentication_authorization": "No authentication/authorization flaw scanner "
            "exists in this codebase.",
    "xxe": "No XXE-testing module exists in this codebase.",
    "server_side_code_execution": "No RCE/command-injection scanner exists in this codebase.",
}


async def authorize_host(db, user: User, host: str) -> ScanScope:
    """Run the same authorization gate /api/scan uses before any connection
    to `host`, and return the network ScanScope the active checks must stay
    inside.

    Fail-closed: a denied decision — or any error raised while performing the
    check (DB error, DNS resolver failure, unexpected exception) — stops the
    whole run with a non-zero exit. There is no path that reaches an active
    scan without a positive authorization decision for its target; the
    former hardcoded ALLOWED_TARGETS allowlist is gone.
    """
    try:
        decision = await check_scan_authorization(
            db, user, host, AUTHZ_CHECKS, source=AUTHZ_SOURCE,
        )
    except Exception as exc:  # noqa: BLE001 — fail closed on any check failure
        print(
            f"[{AUTHZ_SOURCE}] REFUSED: authorization check for {host!r} failed "
            f"({exc.__class__.__name__}); refusing active scan (fail-closed).",
            file=sys.stderr,
        )
        raise SystemExit(1)

    if not decision.ok:
        print(
            f"[{AUTHZ_SOURCE}] REFUSED: {host!r} is not an authorized target. "
            f"Active checks require a DNS-TXT-verified domain the running user "
            f"owns (or a listed training target). {decision.reason or ''}".rstrip(),
            file=sys.stderr,
        )
        raise SystemExit(1)

    return await network_scope_for(decision, host)


async def _gather_dns(host: str) -> dict:
    records = await asyncio.to_thread(dns_lookup, host)
    resolved_ips = (records.get("A") or []) + (records.get("AAAA") or [])
    reverse_dns = {}
    for ip in resolved_ips:
        ptr = await asyncio.to_thread(reverse_lookup, ip)
        if ptr:
            reverse_dns[ip] = ptr

    finding = {"type": "dns_record", "source": "dns_full", "value": host}
    return {
        "records": records,
        "reverse_dns": reverse_dns,
        "confidence": calculate_confidence(finding, []),
        "severity": classify_severity(finding),
    }


async def _gather_whois(host: str) -> dict:
    record = await asyncio.to_thread(whois_lookup, host)
    if record.get("error"):
        return {"record": record, "confidence": 0, "severity": "info"}

    finding = {
        "type": "whois_record", "source": "whois",
        "expiration_date": record.get("expiration_date"),
        "creation_date": record.get("creation_date"),
    }
    return {
        "record": record,
        "confidence": calculate_confidence(finding, []),
        "severity": classify_severity(finding),
    }


async def _gather_network_intelligence(host: str) -> dict:
    shodan_res, censys_res, bgp_res = await asyncio.gather(
        _query_shodan(host), _query_censys(host), _query_bgp(host),
    )
    return {
        "shodan": shodan_res,
        "censys": censys_res,
        "bgp": bgp_res,
        "note": (
            "Passive third-party lookups only (Shodan InternetDB/API, Censys, "
            "BGPView/RIPEstat). No TLS handshake or active service "
            "fingerprinting was performed against the target — this run "
            "bypasses gather_network_intelligence()'s bundled SSL probe and "
            "deep_scan fingerprinting entirely (see module docstring)."
        ),
    }


_PREFLIGHT_TIMEOUT = 4.0


def _tcp_reachable(host: str, port: int, timeout: float = _PREFLIGHT_TIMEOUT) -> bool:
    """Cheap TCP-connect probe, used only to decide whether it's worth running
    the full XSS/SSRF/LFI payload matrix (dozens of requests at
    DEFAULT_TIMEOUT=5s each) against a scheme/port. If the port doesn't even
    accept a TCP handshake, no payload will ever get a response either — this
    just avoids burning the full timeout on every single one of them.

    Calls socket.create_connection() directly (not a local `import socket`
    alias) so that, when run via run_in_scope(), it goes through the shared
    modules/scan_scope.py guard just like every other caller in this process.
    A connection to a host outside the active scan scope is blocked there
    (recorded on the scope) and surfaces as an OSError, so it is treated as
    "not reachable" — the scan simply does not proceed against it.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


async def _run_vuln_scans(host: str, scope: ScanScope) -> dict:
    """Run the XSS/SSRF/LFI matrix against `host`, inside `scope`.

    Responsible Disclosure — PoC only, no deeper-impact probing: per
    Verisign's Responsible Disclosure Policy, this function stops running
    further scan calls against `host` the moment any of them returns a
    CONFIRMED finding. That finding's single confirming payload/response is
    the evidence gathered for this host; we deliberately do not go on to
    check the remaining scan types/schemes for additional issues once one
    is already confirmed. (Within a single scan call, modules/vuln/*.py
    already stop trying further payloads for a given parameter the moment
    one confirms — this is that same rule applied at the host level.)
    """
    findings: list[dict] = []
    reachability: dict[str, bool] = {}
    for scheme, port in (("https", 443), ("http", 80)):
        reachable = await asyncio.to_thread(run_in_scope, scope, _tcp_reachable, host, port)
        reachability[scheme] = reachable
        if not reachable:
            continue

        base = f"{scheme}://{host}/"
        scan_calls = (
            (scan_xss, base),
            (scan_ssrf, f"{base}?url=test&redirect=test"),
            (scan_lfi, f"{base}?file=test&page=test"),
        )
        for scan_fn, url in scan_calls:
            results = await asyncio.to_thread(run_in_scope, scope, scan_fn, url)
            for finding in results:
                finding["confidence"] = VERDICT_CONFIDENCE.get(finding.get("verdict"), 0.3)
            findings.extend(results)
            if any(f.get("verdict") == "CONFIRMED" for f in results):
                return {"port_reachability": reachability, "findings": findings}

    return {"port_reachability": reachability, "findings": findings}


async def scan_target(host: str, scope: ScanScope) -> dict:
    dns_result, whois_result, network_intel = await asyncio.gather(
        _gather_dns(host), _gather_whois(host), _gather_network_intelligence(host),
    )
    vuln_scan = await _run_vuln_scans(host, scope)
    vulnerabilities = vuln_scan["findings"]

    confirmed_only = [v for v in vulnerabilities if v.get("verdict") == "CONFIRMED"]
    mitre_findings = finding_type_from_scan_results({"vulnerabilities": confirmed_only})
    attack_path = await generate_attack_path(mitre_findings)

    return {
        "target": host,
        "dns": dns_result,
        "whois": whois_result,
        "network_intelligence": network_intel,
        "port_reachability": vuln_scan["port_reachability"],
        "vulnerabilities": vulnerabilities,
        "not_implemented": NOT_IMPLEMENTED,
        "mitre_attack_path": attack_path,
    }


def _build_report(started_at: str, results: dict[str, dict], blocked: list[str]) -> dict:
    return {
        "engagement": {
            "targets": list(SCAN_TARGETS),
            "authorization": (
                "Per-target: web.domain_verification.check_scan_authorization "
                f"(source={AUTHZ_SOURCE!r}, checks={list(AUTHZ_CHECKS)}). Active "
                "checks run only against a DNS-TXT-verified domain the running "
                "user owns; network scope from network_scope_for()."
            ),
            "priority_target": {
                "host": PRIORITY_TARGET,
                "reason": "WordPress + MySQL — much larger historical vulnerability "
                          "surface than the rest of this scope; scanned first.",
            },
            "in_scope_checks": [
                "dns_analysis", "whois_analysis", "network_intelligence_passive",
                "xss", "ssrf", "lfi",
            ],
            "explicitly_excluded_checks": [
                "denial_of_service", "username_email_enumeration",
                "open_redirect", "clickjacking", "fingerprinting_banner_disclosure",
                "accessible_file_checks", "cookie_flag_checks", "tls_ssl_configuration",
            ],
            "not_implemented_checks": list(NOT_IMPLEMENTED),
            "responsible_disclosure": "PoC-only: scanning for a given host stops as "
                "soon as any CONFIRMED finding is produced; no further scan calls "
                "run against that host afterward (see _run_vuln_scans docstring).",
        },
        "scan_started_at": started_at,
        "scan_completed_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "scope_enforcement": {
            "blocked_out_of_scope_request_count": len(blocked),
            "blocked_out_of_scope_requests": blocked,
        },
    }


async def run(db, user: User) -> None:
    started_at = datetime.now(timezone.utc).isoformat()
    blocked: list[str] = []
    results: dict[str, dict] = {}

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = REPORTS_DIR / f"bounty_scan_{timestamp}.json"

    for host in SCAN_TARGETS:
        # Authorize BEFORE any connection to the target. A denial (or any
        # error in the check) stops the whole run with a non-zero exit.
        scope = await authorize_host(db, user, host)
        print(f"[bounty_scan] scanning {host} ...", flush=True)
        results[host] = await scan_target(host, scope)
        blocked.extend(scope.blocked)
        # Checkpoint after each target so a kill/timeout doesn't lose
        # already-completed work — this report is overwritten in place
        # as each target finishes, not just once at the very end.
        out_path.write_text(json.dumps(
            _build_report(started_at, results, blocked), indent=2,
            default=str, ensure_ascii=False,
        ))
        print(f"[bounty_scan] checkpoint written to {out_path}", flush=True)

    print(flush=True)
    print(f"[bounty_scan] report written to {out_path}", flush=True)
    for host, data in results.items():
        confirmed = [v for v in data["vulnerabilities"] if v.get("verdict") == "CONFIRMED"]
        print(
            f"[bounty_scan] {host}: {len(data['vulnerabilities'])} vuln checks run, "
            f"{len(confirmed)} CONFIRMED, "
            f"{len(data['mitre_attack_path']['attack_path'])} ATT&CK kill-chain steps mapped",
            flush=True,
        )
    if blocked:
        print(f"[bounty_scan] WARNING: {len(blocked)} out-of-scope request(s) were blocked — see report.")


async def main() -> None:
    username = os.environ.get("BOUNTY_SCAN_USERNAME")
    if not username:
        print(
            "[bounty_scan] Error: BOUNTY_SCAN_USERNAME environment variable is not set",
            file=sys.stderr,
        )
        raise SystemExit(1)

    # Install the shared network-scope guard once for this process, exactly
    # as web/app.py does, so every active step's traffic is confined to its
    # authorized scope.
    install_scope_guard()

    async with SessionLocal() as db:
        user = (await db.execute(
            select(User).where(User.username == username)
        )).scalar_one_or_none()
        if user is None:
            print(f"[bounty_scan] Error: no user found with username: {username}", file=sys.stderr)
            raise SystemExit(1)
        await run(db, user)


if __name__ == "__main__":
    asyncio.run(main())
