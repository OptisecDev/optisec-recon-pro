"""Scoped bounty-engagement scan for the Chime Bugcrowd web scope.

Intended engagement targets (SCAN_TARGETS below):
    - member-qa.chime.com
    - app-qa.chime.com
    - www.chime.com
    - app.chime.com

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

Reuses the project's existing scan engine, the same way bounty_scan.py does:
    - DNS analysis          modules/recon/dns_lookup.py
    - WHOIS analysis        modules/recon/whois_lookup.py
    - Network Intelligence  modules/osint/network_intelligence.py
                            (Shodan/Censys/BGP passive lookups ONLY — see
                            "Explicitly excluded" below for why the module's
                            bundled TLS probe and deep_scan fingerprinting
                            are skipped)
    - XSS / SSRF / LFI      modules/vuln/xss.py, ssrf.py, lfi.py
    - GraphQL introspection modules/vuln/graphql_probe.py (Phase 1 — see
                            "GraphQL introspection testing" section below)
    - Confidence scoring    modules/osint/confidence_engine.py
    - MITRE ATT&CK mapping  modules/osint/mitre_mapping.py

No per-target priority ordering: all four hosts are QA/prod pairs of the
same two applications (member-qa/app-qa are the QA counterparts of
www/app), so SCAN_TARGETS just lists them in the order given by the
engagement brief and main() scans strictly in that order (no cross-host
concurrency).

Responsible Disclosure / PoC-only — per Chime's Bugcrowd Engagement Rules,
this scanner gathers a single confirming payload/response per finding and
enforces two stopping rules, both stricter than bounty_scan.py's Verisign
equivalent:
  1. Host-level stop: the moment any scan call returns a CONFIRMED finding
     for a host, no further scan calls run against that host for the rest
     of this process (same rule as bounty_scan.py).
  2. One-primary-finding-per-class: Chime's rules also require "one primary
     vulnerability per report" — so even within a single scan call (e.g.
     scan_xss() testing several parameters in one pass), only the FIRST
     CONFIRMED result is kept; any additional CONFIRMED results for other
     parameters of that same call are discarded before being added to the
     findings list. See _run_vuln_scans() below.
modules/vuln/{xss,ssrf,lfi}.py already stop trying further payloads for a
given parameter the moment one confirms (their per-parameter `break` on
`result.should_report`); the two rules above extend that same principle to
the whole scan call and the whole host.

Explicitly excluded from this run, even though the underlying module exists
in the codebase — same categories agreed out of scope for the Verisign
engagement, carried over here because nothing in Chime's Bugcrowd brief
available to this session explicitly re-authorizes them. If Chime's actual
program brief is later found to explicitly permit any of these, that
specific exclusion should be revisited and this comment updated accordingly
— until then, default to the narrower Verisign-equivalent scope:
    - TLS/SSL configuration checks            — modules/osint/network_intelligence.py's
      gather_network_intelligence() unconditionally opens a direct TLS
      handshake to the target (see its own docstring). Not used here: this
      script calls the passive Shodan/Censys/BGP sub-functions directly
      instead of the bundled orchestrator, so no TLS probe or active
      fingerprint ever reaches the target.
    - Clickjacking testing                    — modules/recon/security_headers.py
      is never imported (its X-Frame-Options check exists specifically to
      flag clickjacking exposure).
    - Denial-of-service / brute-force enumeration — never in scope; nothing
      here floods, force-multiplies, or load-tests any target, and
      modules/osint/unified_engine.py's holehe/maigret/theHarvester/
      email_finder enumeration sources are never imported.
    - Accessible-file / fingerprinting checks — modules/recon/security_headers.py
      is never imported (its DANGEROUS_HEADERS banner-disclosure check is
      the only such logic in this codebase); no robots.txt/README-style
      accessible-file scanner exists anywhere in this codebase either.

GraphQL introspection testing (Phase 1 of Chime's encouraged GraphQL
methodology): modules/vuln/graphql_probe.py's scan_graphql() sends only
standard `__schema`/`__type` introspection queries (POST first, GET
fallback) against a small fixed list of common GraphQL paths
(GRAPHQL_CANDIDATE_PATHS) — no path brute-forcing, no mutations, no
batching/aliasing/query-depth abuse. Wired into _run_vuln_scans() alongside
xss/ssrf/lfi, subject to the same CONFIRMED-stops-the-host and
one-primary-finding-per-class rules below.

Remaining GraphQL methodology gap: batching abuse, query-depth/complexity-
limit probing, and mutation testing are NOT attempted by this script —
those are later phases, deliberately deferred rather than silently
omitted. See GRAPHQL_METHODOLOGY_GAP below and the report's
engagement.methodology_gaps section.

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
    BOUNTY_SCAN_USERNAME=<user> python scripts/bounty_scan_chime.py

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
from modules.vuln.graphql_probe import scan_graphql  # noqa: E402
from modules.vuln.lfi import scan_lfi  # noqa: E402
from modules.vuln.ssrf import scan_ssrf  # noqa: E402
from modules.vuln.xss import scan_xss  # noqa: E402
from web.database import SessionLocal  # noqa: E402
from web.domain_verification import check_scan_authorization, network_scope_for  # noqa: E402
from web.models import User  # noqa: E402

SCAN_TARGETS: tuple[str, ...] = (
    "member-qa.chime.com",
    "app-qa.chime.com",
    "www.chime.com",
    "app.chime.com",
)

# Active checks this script sends at a target, named as web/scan_authz.py
# classifies them: the XSS/SSRF/LFI payload matrix plus the _tcp_reachable()
# port preflight. GraphQL introspection (scan_graphql) is active too but has
# no scan_authz check name; it runs only under the same positive decision
# these checks require, so it is never reached for an unauthorized host.
AUTHZ_CHECKS: tuple[str, ...] = ("ports", "xss", "ssrf", "lfi")
AUTHZ_SOURCE = "bounty_scan_chime"

# modules/vuln/*.py report a categorical WAF-aware verdict, not a numeric
# confidence — this maps that verdict onto a 0-1 score for the unified
# report, per waf_aware_classifier.py's own verdict semantics (only
# CONFIRMED is a should_report=True signal). waf_aware_classifier.py's
# _reflected_raw() here is the fixed version (commit 7454912): it flags a
# reflection only on an exact payload match, not on generic tag fragments
# (<script, <img, onload=, etc.) that can legitimately appear in a target's
# own markup — the fix that removed a false-positive CONFIRMED class seen
# during the Verisign engagement.
VERDICT_CONFIDENCE: dict[str, float] = {
    "CONFIRMED": 0.95,
    "INCONCLUSIVE": 0.4,
    "WAF_BLOCKED": 0.15,
    "ENCODED_SAFE": 0.05,
    # graphql_probe.py-only verdict: endpoint confirmed to be real GraphQL,
    # but it rejected the introspection query — informative negative
    # result, so slightly above ENCODED_SAFE rather than 0.0.
    "INTROSPECTION_DISABLED": 0.1,
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

# Chime's program brief explicitly encourages GraphQL-endpoint testing.
# Phase 1 (introspection-only, via modules/vuln/graphql_probe.py) IS run as
# part of this scan now — see "GraphQL introspection testing" in the module
# docstring. The remaining phases below are a conscious, documented
# methodology gap, not a silent omission.
GRAPHQL_METHODOLOGY_GAP = (
    "Chime's Bugcrowd program brief encourages GraphQL-endpoint testing "
    "including introspection, batching abuse, and query-depth/complexity "
    "limits. This run covers introspection only (modules/vuln/"
    "graphql_probe.py: standard __schema/__type queries against a small "
    "fixed candidate-path list, no mutations, no batching/aliasing/"
    "depth abuse). Batching-abuse and query-depth/complexity-limit testing "
    "were NOT attempted — flagged here as an explicit methodology gap "
    "rather than left out silently."
)


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
    """Run the XSS/SSRF/LFI/GraphQL-introspection matrix against `host`, inside `scope`.

    Responsible Disclosure — PoC only, no deeper-impact probing, per
    Chime's Bugcrowd Engagement Rules. Two stopping rules, both enforced
    here:

    1. Host-level stop: the moment any scan call returns a CONFIRMED
       finding, no further scan calls run against `host` for the rest of
       this process (same rule as bounty_scan.py's Verisign engagement).
    2. One-primary-finding-per-class: Chime's rules also require "one
       primary vulnerability per report". A single scan call can test
       several parameters/payloads in one pass and, in principle, return
       more than one CONFIRMED result in its own results list (e.g. two
       different query parameters both reflecting an XSS payload). Only
       the FIRST CONFIRMED result from any one scan call is kept; any
       further CONFIRMED entries from that same call are discarded before
       being added to `findings` — so each vulnerability class (xss/ssrf/
       lfi/graphql) can contribute at most one CONFIRMED finding to the
       report.

    Within a single scan call, modules/vuln/*.py already stop trying
    further payloads (or, for graphql_probe.py, further candidate paths)
    the moment one confirms (their per-parameter/per-path `break` on
    `result.should_report`/verdict) — rule 2 above extends that same
    principle across parameters within one call, and rule 1 extends it
    across calls for the whole host.
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
            # No query string: scan_graphql() derives the origin itself and
            # probes its own fixed candidate-path list (GRAPHQL_CANDIDATE_PATHS).
            (scan_graphql, base),
        )
        for scan_fn, url in scan_calls:
            results = await asyncio.to_thread(run_in_scope, scope, scan_fn, url)

            confirmed_seen = False
            kept: list[dict] = []
            for finding in results:
                finding["confidence"] = VERDICT_CONFIDENCE.get(finding.get("verdict"), 0.3)
                if finding.get("verdict") == "CONFIRMED":
                    if confirmed_seen:
                        # One primary vulnerability per class/report — drop
                        # any further CONFIRMED result from this same call.
                        continue
                    confirmed_seen = True
                kept.append(finding)
            findings.extend(kept)

            if confirmed_seen:
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
            "program": "Chime (Bugcrowd)",
            "targets": list(SCAN_TARGETS),
            "authorization": (
                "Per-target: web.domain_verification.check_scan_authorization "
                f"(source={AUTHZ_SOURCE!r}, checks={list(AUTHZ_CHECKS)}). Active "
                "checks run only against a DNS-TXT-verified domain the running "
                "user owns; network scope from network_scope_for()."
            ),
            "in_scope_checks": [
                "dns_analysis", "whois_analysis", "network_intelligence_passive",
                "xss", "ssrf", "lfi", "graphql_introspection",
            ],
            "explicitly_excluded_checks": [
                "tls_ssl_configuration", "clickjacking",
                "denial_of_service_brute_force_enumeration",
                "accessible_file_fingerprinting_checks",
            ],
            "explicitly_excluded_reason": (
                "Same categories agreed out of scope for the Verisign engagement, "
                "carried over here because nothing in Chime's Bugcrowd brief "
                "available to this session explicitly re-authorizes them. "
                "Revisit only if Chime's actual program brief is confirmed to "
                "permit one of these specifically."
            ),
            "methodology_gaps": {
                "graphql": GRAPHQL_METHODOLOGY_GAP,
            },
            "not_implemented_checks": list(NOT_IMPLEMENTED),
            "responsible_disclosure": (
                "PoC-only, per Chime's Bugcrowd Engagement Rules: (1) scanning for "
                "a given host stops as soon as any CONFIRMED finding is produced; "
                "no further scan calls run against that host afterward. (2) "
                "one-primary-vulnerability-per-report — even within a single scan "
                "call, only the first CONFIRMED result is kept, so at most one "
                "CONFIRMED finding per vulnerability class (xss/ssrf/lfi/graphql) "
                "is ever captured. See _run_vuln_scans docstring."
            ),
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
    out_path = REPORTS_DIR / f"bounty_scan_chime_{timestamp}.json"

    for host in SCAN_TARGETS:
        # Authorize BEFORE any connection to the target. A denial (or any
        # error in the check) stops the whole run with a non-zero exit.
        scope = await authorize_host(db, user, host)
        print(f"[bounty_scan_chime] scanning {host} ...", flush=True)
        results[host] = await scan_target(host, scope)
        blocked.extend(scope.blocked)
        # Checkpoint after each target so a kill/timeout doesn't lose
        # already-completed work — this report is overwritten in place
        # as each target finishes, not just once at the very end.
        out_path.write_text(json.dumps(
            _build_report(started_at, results, blocked), indent=2,
            default=str, ensure_ascii=False,
        ))
        print(f"[bounty_scan_chime] checkpoint written to {out_path}", flush=True)

    print(flush=True)
    print(f"[bounty_scan_chime] report written to {out_path}", flush=True)
    for host, data in results.items():
        confirmed = [v for v in data["vulnerabilities"] if v.get("verdict") == "CONFIRMED"]
        print(
            f"[bounty_scan_chime] {host}: {len(data['vulnerabilities'])} vuln checks run, "
            f"{len(confirmed)} CONFIRMED, "
            f"{len(data['mitre_attack_path']['attack_path'])} ATT&CK kill-chain steps mapped",
            flush=True,
        )
    if blocked:
        print(f"[bounty_scan_chime] WARNING: {len(blocked)} out-of-scope request(s) were blocked — see report.")


async def main() -> None:
    username = os.environ.get("BOUNTY_SCAN_USERNAME")
    if not username:
        print(
            "[bounty_scan_chime] Error: BOUNTY_SCAN_USERNAME environment variable is not set",
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
            print(f"[bounty_scan_chime] Error: no user found with username: {username}", file=sys.stderr)
            raise SystemExit(1)
        await run(db, user)


if __name__ == "__main__":
    asyncio.run(main())
