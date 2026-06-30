"""
Advanced Network Intelligence — Phase 2A
Passive Shodan/Censys/BGP recon plus a direct TLS handshake and optional
active service fingerprinting, folded into a single 0-100 attack-surface
score the way professional recon platforms (Shodan's "Vulns" tab, testssl.sh,
SpiderFoot) summarize exposure for a human reader.

Design notes:
  - Shodan: uses the paid host API if SHODAN_API_KEY is set, otherwise falls
    back to the free, keyless Shodan InternetDB (https://internetdb.shodan.io)
    which only covers IPs Shodan has already scanned.
  - Censys: needs both CENSYS_API_ID and CENSYS_API_SECRET — skipped (not an
    error) if either is missing.
  - BGP/ASN data comes from the free public bgpview.io API — no key needed.
  - SSL/TLS analysis opens its own raw socket (stdlib `ssl` + `socket`); no
    external service is queried, so it works for hosts Shodan hasn't indexed.
  - Active service fingerprinting (_fingerprint_services / banner grabs) is
    opt-in via `deep_scan=True` in gather_network_intelligence() — unlike the
    passive sources above, it sends real TCP/HTTP probes at the target, so
    it's reserved for explicit network-scan requests rather than running on
    every passive OSINT lookup (see web/routers/osint.py's
    /api/osint/network-scan and the project's Ethical Use Policy).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

logger = logging.getLogger("osint.network_intel")

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"
BGPVIEW_IP_URL = "https://api.bgpview.io/ip/{ip}"
BGPVIEW_ASN_PEERS_URL = "https://api.bgpview.io/asn/{asn}/peers"
BGPVIEW_ASN_PREFIXES_URL = "https://api.bgpview.io/asn/{asn}/prefixes"
# Fallback BGP/ASN source (RIPE NCC, free & keyless) — used if bgpview.io is
# unreachable, since it's a single third-party service with no uptime SLA.
RIPESTAT_NETWORK_INFO_URL = "https://stat.ripe.net/data/network-info/data.json?resource={ip}"
RIPESTAT_AS_OVERVIEW_URL = "https://stat.ripe.net/data/as-overview/data.json?resource={asn}"
RIPESTAT_ASN_NEIGHBOURS_URL = "https://stat.ripe.net/data/asn-neighbours/data.json?resource={asn}"
RIPESTAT_ANNOUNCED_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"

_HTTP_TIMEOUT = 15.0
_SSL_TIMEOUT = 8.0

_RE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ── Target resolution ─────────────────────────────────────────────────────────

def _resolve_ip(target: str) -> str | None:
    """Resolve a domain/URL/IP string to a bare IPv4 address, or None."""
    target = target.strip()
    if _RE_IP.match(target):
        return target
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0].split(":")[0]
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


def _exc_to_error(value: Any, source_name: str) -> dict:
    if isinstance(value, Exception):
        logger.error("[%s] unexpected error: %s", source_name, value)
        return {"source": source_name, "available": False, "error": str(value)}
    return value


# ── 1. Shodan / Censys integration ─────────────────────────────────────────────

def _empty_recon_result(source: str, ip: str | None, **extra) -> dict:
    base = {
        "source": source, "available": False, "ip": ip,
        "open_ports": [], "services": [], "vulnerabilities": [],
        "tags": [], "hostnames": [], "country": None,
    }
    base.update(extra)
    return base


def _shodan_severity(cve: str, cvss: float | None) -> str:
    if cvss is not None:
        if cvss >= 9:
            return "critical"
        if cvss >= 7:
            return "high"
        if cvss >= 4:
            return "medium"
        return "low"
    # No CVSS data (e.g. free InternetDB only lists bare CVE IDs) — a known
    # CVE on an internet-facing host is still notable, so default to "high"
    # rather than silently dropping it to "info".
    return "high"


async def _query_shodan(target: str) -> dict:
    """
    Look up `target` in Shodan: paid host API (SHODAN_API_KEY) if configured,
    otherwise the free, keyless Shodan InternetDB.

    Returns {source, available, ip, open_ports, services, vulnerabilities,
    tags, hostnames, country}. Never raises.
    """
    ip = _resolve_ip(target)
    if not ip:
        return _empty_recon_result("shodan", None, error=f"could not resolve '{target}' to an IP")

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            if SHODAN_API_KEY:
                resp = await client.get(SHODAN_HOST_URL.format(ip=ip), params={"key": SHODAN_API_KEY})
                if resp.status_code == 404:
                    return _empty_recon_result("shodan", ip, available=True, via="shodan_api",
                                                error="no Shodan data for this host")
                resp.raise_for_status()
                d = resp.json()
                vulns_raw = d.get("vulns") or {}
                vulnerabilities = [
                    {"cve": cve, "severity": _shodan_severity(cve, (info or {}).get("cvss"))}
                    for cve, info in (
                        vulns_raw.items() if isinstance(vulns_raw, dict)
                        else ((v, {}) for v in vulns_raw)
                    )
                ]
                services = [
                    {
                        "port": entry.get("port"),
                        "transport": entry.get("transport"),
                        "product": entry.get("product"),
                        "version": entry.get("version"),
                        "banner": (entry.get("data") or "")[:200].strip(),
                    }
                    for entry in d.get("data", []) or []
                ]
                return {
                    "source": "shodan", "available": True, "ip": ip, "via": "shodan_api",
                    "open_ports": sorted(set(d.get("ports", []) or [])),
                    "services": services,
                    "vulnerabilities": vulnerabilities,
                    "tags": d.get("tags", []) or [],
                    "hostnames": d.get("hostnames", []) or [],
                    "country": d.get("country_name"),
                    "org": d.get("org"),
                }

            # No API key — free Shodan InternetDB (IP-only, no banners).
            resp = await client.get(SHODAN_INTERNETDB_URL.format(ip=ip))
            if resp.status_code == 404:
                return _empty_recon_result("shodan", ip, available=True, via="internetdb",
                                            error="no InternetDB data for this host")
            resp.raise_for_status()
            d = resp.json()
            return {
                "source": "shodan", "available": True, "ip": ip, "via": "internetdb",
                "open_ports": sorted(d.get("ports", []) or []),
                "services": [],
                "vulnerabilities": [
                    {"cve": cve, "severity": _shodan_severity(cve, None)}
                    for cve in (d.get("vulns", []) or [])
                ],
                "tags": d.get("tags", []) or [],
                "hostnames": d.get("hostnames", []) or [],
                "country": None,
            }
    except httpx.HTTPError as exc:
        return _empty_recon_result("shodan", ip, available=True, error=str(exc))


async def _query_censys(target: str) -> dict:
    """
    Look up `target` in Censys (API v2 Hosts). Requires both CENSYS_API_ID
    and CENSYS_API_SECRET — returns available=False (not an error) if either
    is missing, the same way unconfigured sources degrade elsewhere in this
    codebase. Never raises.
    """
    if not (CENSYS_API_ID and CENSYS_API_SECRET):
        return _empty_recon_result("censys", None, error="CENSYS_API_ID/CENSYS_API_SECRET not configured")

    ip = _resolve_ip(target)
    if not ip:
        return _empty_recon_result("censys", None, error=f"could not resolve '{target}' to an IP")

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, auth=(CENSYS_API_ID, CENSYS_API_SECRET)) as client:
            resp = await client.get(CENSYS_HOST_URL.format(ip=ip))
            if resp.status_code == 404:
                return _empty_recon_result("censys", ip, available=True, error="no Censys data for this host")
            if resp.status_code == 401:
                return _empty_recon_result("censys", ip, available=True, error="invalid Censys credentials")
            resp.raise_for_status()
            d = resp.json().get("result", {}) or {}
            services = d.get("services", []) or []
            location = d.get("location") or {}
            autonomous_system = d.get("autonomous_system") or {}
            dns_block = d.get("dns") or {}
            reverse_dns = (dns_block.get("reverse_dns") or {}).get("names", []) if isinstance(dns_block, dict) else []
            return {
                "source": "censys", "available": True, "ip": ip,
                "open_ports": sorted({s.get("port") for s in services if s.get("port") is not None}),
                "services": [
                    {
                        "port": s.get("port"),
                        "protocol": s.get("service_name"),
                        "banner": (s.get("banner") or "")[:200].strip(),
                    }
                    for s in services
                ],
                "vulnerabilities": [],  # not exposed by this lightweight v2 hosts call
                "tags": d.get("labels", []) or [],
                "hostnames": reverse_dns,
                "country": location.get("country"),
                "asn": autonomous_system.get("asn"),
            }
    except httpx.HTTPError as exc:
        return _empty_recon_result("censys", ip, available=True, error=str(exc))


# ── 2. BGP / ASN intelligence ──────────────────────────────────────────────────

async def _query_bgp(target: str) -> dict:
    """
    Resolve `target`'s announced BGP prefix and originating ASN via bgpview.io.

    Returns {source, available, ip, asn, asn_name, asn_description, prefix,
    country, rir, peer_asns}. Never raises.
    """
    ip = _resolve_ip(target)
    if not ip:
        return _empty_bgp_result(None, error=f"could not resolve '{target}' to an IP")

    try:
        primary = await _query_bgp_bgpview(ip)
    except httpx.HTTPError as exc:
        # bgpview.io is a single free third-party service with no SLA — if
        # it's unreachable (seen in practice: DNS outages), fall back to
        # RIPEstat rather than returning no BGP data at all.
        logger.warning("[bgp] bgpview.io unreachable, trying RIPEstat fallback: %s", exc)
        primary = _empty_bgp_result(ip, via="bgpview", error=str(exc))

    if primary.get("asn"):
        return primary

    try:
        fallback = await _query_bgp_ripestat(ip)
    except httpx.HTTPError as exc:
        logger.warning("[bgp] RIPEstat also unreachable: %s", exc)
        return primary

    return fallback if fallback.get("asn") else primary


def _empty_bgp_result(ip: str | None, via: str | None = None, **extra) -> dict:
    base = {
        "source": "bgp", "available": ip is not None, "ip": ip, "via": via,
        "asn": None, "asn_name": None, "asn_description": None,
        "prefix": None, "country": None, "rir": None, "peer_asns": [],
    }
    base.update(extra)
    return base


async def _query_bgp_bgpview(ip: str) -> dict:
    base = _empty_bgp_result(ip, via="bgpview")
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        resp = await client.get(BGPVIEW_IP_URL.format(ip=ip))
        resp.raise_for_status()
        data = resp.json().get("data", {}) or {}
        prefixes = data.get("prefixes", []) or []
        if not prefixes:
            base["error"] = "no announced BGP prefix found for this IP"
            return base

        p = prefixes[0]
        asn_info = p.get("asn", {}) or {}
        asn_num = asn_info.get("asn")
        base.update({
            "asn": asn_num,
            "asn_name": asn_info.get("name"),
            "asn_description": asn_info.get("description"),
            "prefix": p.get("prefix"),
            "country": asn_info.get("country_code"),
            "rir": (p.get("rir_allocation") or {}).get("rir_name"),
        })

        if asn_num:
            peers_resp = await client.get(BGPVIEW_ASN_PEERS_URL.format(asn=asn_num))
            if peers_resp.status_code == 200:
                peers_data = peers_resp.json().get("data", {}) or {}
                ipv4_peers = peers_data.get("ipv4_peers", []) or []
                base["peer_asns"] = sorted({pe.get("asn") for pe in ipv4_peers if pe.get("asn")})[:50]
        return base


async def _query_bgp_ripestat(ip: str) -> dict:
    """Fallback BGP/ASN source — RIPE NCC's free, keyless RIPEstat Data API."""
    base = _empty_bgp_result(ip, via="ripestat")
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        resp = await client.get(RIPESTAT_NETWORK_INFO_URL.format(ip=ip))
        resp.raise_for_status()
        data = resp.json().get("data", {}) or {}
        asns = data.get("asns") or []
        if not asns:
            base["error"] = "no announced BGP prefix found for this IP"
            return base

        asn_num = int(asns[0])
        base["asn"] = asn_num
        base["prefix"] = data.get("prefix")

        overview_resp = await client.get(RIPESTAT_AS_OVERVIEW_URL.format(asn=asn_num))
        if overview_resp.status_code == 200:
            overview = overview_resp.json().get("data", {}) or {}
            base["asn_name"] = overview.get("holder")
            block_desc = (overview.get("block") or {}).get("desc", "") or ""
            m = re.search(r"Assigned by (\w+)", block_desc)
            if m:
                base["rir"] = m.group(1)

        neighbours_resp = await client.get(RIPESTAT_ASN_NEIGHBOURS_URL.format(asn=asn_num))
        if neighbours_resp.status_code == 200:
            neighbours = neighbours_resp.json().get("data", {}) or {}
            peer_asns = {n.get("asn") for n in neighbours.get("neighbours", []) or [] if n.get("asn")}
            base["peer_asns"] = sorted(peer_asns)[:50]

        return base


async def _get_ip_ranges(asn: int | str) -> dict:
    """
    List every IPv4/IPv6 prefix registered to `asn`: bgpview.io first, with
    an automatic RIPEstat fallback if bgpview.io is unreachable.

    Returns {source, available, asn, ipv4_prefixes, ipv6_prefixes}. Never raises.
    """
    try:
        asn_num = int(str(asn).upper().lstrip("AS"))
    except ValueError:
        return {"source": "bgp", "available": False, "asn": asn,
                "error": f"invalid ASN: {asn!r}", "ipv4_prefixes": [], "ipv6_prefixes": []}

    try:
        return await _get_ip_ranges_bgpview(asn_num)
    except httpx.HTTPError as exc:
        logger.warning("[bgp] bgpview.io unreachable for prefix lookup, trying RIPEstat: %s", exc)
        try:
            return await _get_ip_ranges_ripestat(asn_num)
        except httpx.HTTPError as exc2:
            return {
                "source": "bgp", "available": False, "asn": asn_num,
                "error": f"bgpview.io: {exc}; ripestat: {exc2}",
                "ipv4_prefixes": [], "ipv6_prefixes": [],
            }


async def _get_ip_ranges_bgpview(asn_num: int) -> dict:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        resp = await client.get(BGPVIEW_ASN_PREFIXES_URL.format(asn=asn_num))
        resp.raise_for_status()
        d = resp.json().get("data", {}) or {}

        def _fmt(prefixes: list[dict]) -> list[dict]:
            return [
                {
                    "prefix": p.get("prefix"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "country": p.get("country_code"),
                }
                for p in prefixes or []
            ]

        return {
            "source": "bgp", "available": True, "asn": asn_num, "via": "bgpview",
            "ipv4_prefixes": _fmt(d.get("ipv4_prefixes")),
            "ipv6_prefixes": _fmt(d.get("ipv6_prefixes")),
        }


async def _get_ip_ranges_ripestat(asn_num: int) -> dict:
    """Fallback prefix listing — RIPEstat doesn't report name/description/country per prefix."""
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        resp = await client.get(RIPESTAT_ANNOUNCED_PREFIXES_URL.format(asn=asn_num))
        resp.raise_for_status()
        d = resp.json().get("data", {}) or {}
        ipv4_prefixes: list[dict] = []
        ipv6_prefixes: list[dict] = []
        for entry in d.get("prefixes") or []:
            prefix = entry.get("prefix")
            if not prefix:
                continue
            item = {"prefix": prefix, "name": None, "description": None, "country": None}
            (ipv6_prefixes if ":" in prefix else ipv4_prefixes).append(item)

        return {
            "source": "bgp", "available": True, "asn": asn_num, "via": "ripestat",
            "ipv4_prefixes": ipv4_prefixes,
            "ipv6_prefixes": ipv6_prefixes,
        }


# ── 3. SSL/TLS deep analysis ───────────────────────────────────────────────────

_WEAK_CIPHER_PATTERNS = ("RC4", "MD5", "DES", "EXPORT", "NULL", "ANON")
_DEPRECATED_TLS_VERSIONS = ("TLSv1.0", "TLSv1.1")
_PROBED_TLS_VERSIONS = (
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)


def _probe_tls_version(host: str, port: int, version: "ssl.TLSVersion", timeout: float) -> str:
    """Force a handshake at exactly `version`; return supported/not_supported/untestable."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, ssl.SSLError):
        # OpenSSL build disables this version client-side (common for
        # TLSv1.0/1.1 on modern distros) — we genuinely can't test it.
        return "untestable"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return "supported"
    except ssl.SSLError:
        return "not_supported"
    except (socket.timeout, OSError):
        return "untestable"


def _parse_certificate(der_cert: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der_cert, default_backend())
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_left = (not_after - datetime.now(timezone.utc)).days

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    ocsp_url = None
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in aia.value:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_url = desc.access_location.value
                break
    except x509.ExtensionNotFound:
        pass

    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_left,
        "is_expired": days_left < 0,
        "is_self_signed": subject == issuer,
        "subject_alt_names": sans,
        "serial_number": str(cert.serial_number),
        "ocsp_responder_url": ocsp_url,
    }


def _detect_ssl_vulnerabilities(ssl_result: dict) -> list[dict]:
    """
    Rule-based vulnerability detection over an _analyze_ssl_sync() result.
    Never performs network I/O — pure reasoning over already-collected data.
    """
    issues: list[dict] = []
    protocol_support = ssl_result.get("protocol_support") or {}
    for version in _DEPRECATED_TLS_VERSIONS:
        if protocol_support.get(version) == "supported":
            issues.append({
                "id": f"deprecated-{version.lower()}",
                "title": f"{version} is enabled (deprecated)",
                "severity": "high",
            })

    cipher = ssl_result.get("cipher_suite") or {}
    cipher_name = (cipher.get("name") or "").upper()
    if any(pattern in cipher_name for pattern in _WEAK_CIPHER_PATTERNS):
        issues.append({
            "id": "weak-cipher",
            "title": f"Weak cipher suite negotiated: {cipher_name}",
            "severity": "high",
        })

    cert = ssl_result.get("certificate") or {}
    if cert.get("is_self_signed"):
        issues.append({"id": "self-signed-cert", "title": "Certificate is self-signed", "severity": "medium"})

    if cert.get("is_expired"):
        issues.append({"id": "cert-expired", "title": "Certificate has expired", "severity": "critical"})
    elif isinstance(cert.get("days_until_expiry"), int) and cert["days_until_expiry"] < 30:
        issues.append({
            "id": "cert-expiring-soon",
            "title": f"Certificate expires in {cert['days_until_expiry']} days",
            "severity": "medium",
        })

    if ssl_result.get("chain_trusted") is False:
        issues.append({
            "id": "untrusted-chain",
            "title": "Certificate chain is not trusted by the system CA store",
            "severity": "high",
        })

    return issues


def _analyze_ssl_sync(host: str, port: int = 443, timeout: float = _SSL_TIMEOUT) -> dict:
    result: dict = {
        "source": "ssl", "available": True, "host": host, "port": port,
        "negotiated_version": None, "cipher_suite": None,
        "protocol_support": {}, "certificate": {}, "chain_length": None,
        "chain_trusted": None, "vulnerabilities": [],
    }

    der_cert: bytes | None = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["negotiated_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["cipher_suite"] = {
                        "name": cipher[0], "protocol": cipher[1], "secret_bits": cipher[2],
                    }
                der_cert = ssock.getpeercert(binary_form=True)
                chain_fn = getattr(ssock, "get_unverified_chain", None)
                if callable(chain_fn):
                    try:
                        chain = chain_fn()
                        result["chain_length"] = len(chain) if chain else 1
                    except Exception:
                        result["chain_length"] = 1
                else:
                    # Python <3.13's ssl module only exposes the leaf cert
                    # from a client connection — full chain needs pyOpenSSL.
                    result["chain_length"] = 1
    except ssl.SSLError as exc:
        result["available"] = False
        result["error"] = f"TLS handshake failed: {exc}"
        return result
    except (socket.timeout, OSError) as exc:
        result["available"] = False
        result["error"] = f"could not connect to {host}:{port}: {exc}"
        return result

    if der_cert:
        try:
            result["certificate"] = _parse_certificate(der_cert)
        except Exception as exc:
            result["certificate"] = {"error": f"could not parse certificate: {exc}"}

    try:
        verify_ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with verify_ctx.wrap_socket(sock, server_hostname=host):
                result["chain_trusted"] = True
    except ssl.SSLCertVerificationError as exc:
        result["chain_trusted"] = False
        result["chain_trust_error"] = str(exc)
    except (socket.timeout, OSError):
        pass  # connection itself failed this time — leave chain_trusted unknown

    for label, version in _PROBED_TLS_VERSIONS:
        result["protocol_support"][label] = _probe_tls_version(host, port, version, timeout)

    result["vulnerabilities"] = _detect_ssl_vulnerabilities(result)
    return result


async def _analyze_ssl(host: str, port: int = 443) -> dict:
    """Async wrapper — the actual handshakes are blocking socket calls."""
    return await asyncio.to_thread(_analyze_ssl_sync, host, port)


# ── 4. Service fingerprinting ──────────────────────────────────────────────────

_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
)
_HTTPS_PORTS = {443, 8443}
_HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000}

_FRAMEWORK_HINTS = (
    ("nginx", "Nginx"),
    ("apache", "Apache"),
    ("iis", "Microsoft IIS"),
    ("express", "Express (Node.js)"),
    ("gunicorn", "Gunicorn (Python)"),
    ("werkzeug", "Werkzeug/Flask (Python)"),
    ("cloudflare", "Cloudflare"),
    ("php", "PHP"),
    ("asp.net", "ASP.NET"),
)


def _guess_framework(headers: dict[str, str]) -> str | None:
    haystack = " ".join(headers.values()).lower()
    for needle, label in _FRAMEWORK_HINTS:
        if needle in haystack:
            return label
    return None


async def _fingerprint_http(host: str, port: int, use_tls: bool) -> dict:
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=False) as client:
            resp = await client.get(url)
            headers = dict(resp.headers)
            present_lower = {k.lower() for k in headers}
            missing = [h for h in _SECURITY_HEADERS if h.lower() not in present_lower]
            return {
                "port": port, "protocol": scheme, "service": "http",
                "status_code": resp.status_code,
                "server": headers.get("server") or headers.get("Server"),
                "x_powered_by": headers.get("x-powered-by") or headers.get("X-Powered-By"),
                "framework_hint": _guess_framework(headers),
                "missing_security_headers": missing,
                "headers": headers,
            }
    except httpx.HTTPError as exc:
        return {"port": port, "protocol": scheme, "service": "http", "error": str(exc)}


def _grab_banner_sync(host: str, port: int, timeout: float = 4.0) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(2048)
            except socket.timeout:
                banner = b""
            return {"port": port, "open": True, "banner": banner.decode(errors="replace").strip()}
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {"port": port, "open": False, "error": str(exc)}


def _classify_banner(port: int, info: dict) -> dict:
    banner = info.get("banner", "") or ""
    low = banner.lower()
    if banner.startswith("SSH-"):
        service = "ssh"
    elif banner.startswith("220") and "ftp" in low:
        service = "ftp"
    elif banner.startswith("220") and ("smtp" in low or "esmtp" in low):
        service = "smtp"
    elif "http/" in low:
        service = "http"
    else:
        service = "unknown"
    return {**info, "port": port, "service": service}


async def _fingerprint_banner(host: str, port: int) -> dict:
    info = await asyncio.to_thread(_grab_banner_sync, host, port)
    return _classify_banner(port, info)


async def _fingerprint_services(ip: str, ports: list[int]) -> dict:
    """
    Active banner-grab / HTTP-header fingerprint of `ports` on `ip`.

    HTTP(S)-shaped ports get a real HTTP request (Server/X-Powered-By/
    security-header inspection); everything else gets a raw TCP banner read
    classified by its first bytes (SSH-/220 .../etc).
    """
    if not ports:
        return {"source": "fingerprint", "available": True, "ip": ip, "services": []}

    tasks = []
    for port in ports:
        if port in _HTTPS_PORTS:
            tasks.append(_fingerprint_http(ip, port, use_tls=True))
        elif port in _HTTP_PORTS:
            tasks.append(_fingerprint_http(ip, port, use_tls=False))
        else:
            tasks.append(_fingerprint_banner(ip, port))

    raw = await asyncio.gather(*tasks, return_exceptions=True)
    services = [
        r if not isinstance(r, Exception) else {"port": p, "error": str(r)}
        for p, r in zip(ports, raw)
    ]
    return {"source": "fingerprint", "available": True, "ip": ip, "services": services}


# ── 5. Attack surface score ────────────────────────────────────────────────────

_EXPECTED_PORTS = {80, 443, 22, 25, 53, 587, 993, 995}


def _severity_for_score(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"


def _build_recommendations(network_results: dict, breakdown: list[dict]) -> list[str]:
    recs: list[str] = []
    reasons = " ".join(b["reason"] for b in breakdown)
    if "open port" in reasons:
        recs.append("Restrict or close non-essential open ports via firewall rules; expose only what's required.")
    if "TLS" in reasons:
        recs.append("Disable TLS 1.0/1.1 and weak cipher suites; enforce TLS 1.2+ with modern ciphers.")
    if "CVE" in reasons:
        recs.append("Patch or upgrade services with known CVEs; prioritize critical-rated vulnerabilities first.")
    if "security header" in reasons:
        recs.append("Add missing HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).")

    cert = (network_results.get("ssl") or {}).get("certificate") or {}
    if cert.get("is_self_signed"):
        recs.append("Replace the self-signed certificate with one issued by a trusted CA.")
    if cert.get("is_expired") or (isinstance(cert.get("days_until_expiry"), int) and cert["days_until_expiry"] < 30):
        recs.append("Renew the TLS certificate before it expires to avoid trust/availability failures.")

    if not recs:
        recs.append("No significant attack-surface issues detected from passive recon.")
    return recs


def calculate_attack_surface_score(network_results: dict) -> dict:
    """
    Score a gather_network_intelligence()-shaped dict from 0 (minimal
    exposure) to 100 (severe exposure):

      - +5 per open port outside the common/expected set (80/443/22/25/53/
        587/993/995)
      - +15 flat if any deprecated TLS version (1.0/1.1) is enabled
      - +20 per CVE rated critical, +10 per CVE rated high, +5 per CVE
        rated medium/low/unrated (so any known CVE moves the score, but
        critical ones dominate it)
      - +5 per missing HTTP security header

    0-30 = Low, 31-60 = Medium, 61-80 = High, 81-100 = Critical.

    Accepts a partial dict (any source missing/failed) — every field is
    read defensively so a host with only BGP data still scores cleanly.
    """
    score = 0
    breakdown: list[dict] = []

    open_ports: set[int] = set()
    for key in ("shodan", "censys"):
        src = network_results.get(key) or {}
        open_ports.update(src.get("open_ports") or [])
    unnecessary = sorted(p for p in open_ports if p not in _EXPECTED_PORTS)
    if unnecessary:
        points = len(unnecessary) * 5
        score += points
        breakdown.append({"reason": f"{len(unnecessary)} non-essential open port(s): {unnecessary}", "points": points})

    ssl_result = network_results.get("ssl") or {}
    protocol_support = ssl_result.get("protocol_support") or {}
    if any(protocol_support.get(v) == "supported" for v in _DEPRECATED_TLS_VERSIONS):
        score += 15
        breakdown.append({"reason": "Deprecated TLS version (1.0/1.1) enabled", "points": 15})

    vulns: list[Any] = []
    for key in ("shodan", "censys"):
        src = network_results.get(key) or {}
        vulns.extend(src.get("vulnerabilities") or [])
    critical_n = sum(1 for v in vulns if isinstance(v, dict) and v.get("severity") == "critical")
    high_n = sum(1 for v in vulns if isinstance(v, dict) and v.get("severity") == "high")
    other_n = len(vulns) - critical_n - high_n
    if critical_n:
        points = critical_n * 20
        score += points
        breakdown.append({"reason": f"{critical_n} critical CVE(s) present", "points": points})
    if high_n:
        points = high_n * 10
        score += points
        breakdown.append({"reason": f"{high_n} high-severity CVE(s) present", "points": points})
    if other_n:
        points = other_n * 5
        score += points
        breakdown.append({"reason": f"{other_n} other CVE(s) present", "points": points})

    missing_headers: set[str] = set()
    fingerprint = network_results.get("services") or {}
    for svc in fingerprint.get("services") or []:
        missing_headers.update(svc.get("missing_security_headers") or [])
    if missing_headers:
        points = len(missing_headers) * 5
        score += points
        breakdown.append({
            "reason": f"{len(missing_headers)} missing security header(s): {sorted(missing_headers)}",
            "points": points,
        })

    score = max(0, min(100, score))
    return {
        "score": score,
        "severity": _severity_for_score(score),
        "breakdown": breakdown,
        "recommendations": _build_recommendations(network_results, breakdown),
    }


# ── Orchestrator ────────────────────────────────────────────────────────────────

async def gather_network_intelligence(target: str, deep_scan: bool = False) -> dict:
    """
    Run every passive network-intel source for `target` in parallel, score
    the combined attack surface, and optionally (deep_scan=True) actively
    fingerprint the ports Shodan/Censys reported open.

    Returns: {target, ip, shodan, censys, bgp, ssl, services, ip_ranges,
    attack_surface}. `services`/`ip_ranges` stay None unless deep_scan=True.
    """
    ip = _resolve_ip(target)
    if not ip:
        empty = {
            "target": target, "ip": None,
            "error": f"could not resolve '{target}' to an IP address",
            "shodan": None, "censys": None, "bgp": None, "ssl": None,
            "services": None, "ip_ranges": None,
        }
        empty["attack_surface"] = calculate_attack_surface_score({})
        return empty

    sni_host = target if not _RE_IP.match(target.strip()) else ip

    shodan_res, censys_res, bgp_res, ssl_res = await asyncio.gather(
        _query_shodan(target), _query_censys(target), _query_bgp(target),
        _analyze_ssl(sni_host, 443),
        return_exceptions=True,
    )

    result: dict = {
        "target": target, "ip": ip,
        "shodan": _exc_to_error(shodan_res, "shodan"),
        "censys": _exc_to_error(censys_res, "censys"),
        "bgp": _exc_to_error(bgp_res, "bgp"),
        "ssl": _exc_to_error(ssl_res, "ssl"),
        "services": None, "ip_ranges": None,
    }

    if deep_scan:
        ports = sorted(
            set((result["shodan"] or {}).get("open_ports") or [])
            | set((result["censys"] or {}).get("open_ports") or [])
        )
        if ports:
            result["services"] = await _fingerprint_services(ip, ports[:25])
        asn = (result["bgp"] or {}).get("asn")
        if asn:
            result["ip_ranges"] = await _get_ip_ranges(asn)

    result["attack_surface"] = calculate_attack_surface_score(result)
    return result
