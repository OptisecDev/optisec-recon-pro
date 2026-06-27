"""SSL/TLS Certificate Analysis."""

import ssl
import socket
from datetime import datetime, timezone


def analyze_ssl(domain: str, port: int = 443) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
                der = ssock.getpeercert(binary_form=True)
    except Exception as e:
        return {"domain": domain, "error": str(e), "valid": False}

    # Parse dates
    not_before = _parse_cert_date(cert.get("notBefore", ""))
    not_after = _parse_cert_date(cert.get("notAfter", ""))
    now = datetime.now(timezone.utc)

    expired = not_after and not_after < now
    days_left = (not_after - now).days if not_after else None
    expiring_soon = days_left is not None and 0 < days_left <= 30

    # Subject / Issuer
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))

    # SANs
    san_list = []
    for ext_type, val in cert.get("subjectAltName", []):
        if ext_type == "DNS":
            san_list.append(val)

    # Wildcard detection
    wildcards = [s for s in san_list if s.startswith("*")]

    risk_score = _calc_risk(expired, expiring_soon, tls_version, wildcards, issuer)

    return {
        "domain": domain,
        "valid": not expired,
        "expired": expired,
        "expiring_soon": expiring_soon,
        "days_remaining": days_left,
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "subject": subject,
        "issuer": issuer,
        "common_name": subject.get("commonName", ""),
        "issuer_name": issuer.get("organizationName", issuer.get("commonName", "")),
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
        "key_bits": cipher[2] if cipher else None,
        "sans": san_list,
        "wildcard_count": len(wildcards),
        "wildcards": wildcards,
        "serial_number": cert.get("serialNumber", ""),
        "risk_score": risk_score,
        "risk_label": "HIGH" if risk_score > 60 else "MEDIUM" if risk_score > 30 else "LOW",
        "notes": _build_notes(expired, expiring_soon, tls_version, wildcards, days_left, issuer),
    }


def _parse_cert_date(date_str: str):
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def _calc_risk(expired, expiring_soon, tls_version, wildcards, issuer) -> int:
    score = 0
    if expired:
        score += 60
    elif expiring_soon:
        score += 30
    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        score += 40
    if len(wildcards) > 3:
        score += 10
    org = issuer.get("organizationName", "")
    if not org or "self" in org.lower():
        score += 20
    return min(score, 100)


def _build_notes(expired, expiring_soon, tls_version, wildcards, days_left, issuer) -> list:
    notes = []
    if expired:
        notes.append("Certificate has EXPIRED — visitors will see security warnings")
    elif expiring_soon:
        notes.append(f"Certificate expires in {days_left} days — renew immediately")
    else:
        notes.append(f"Certificate valid ({days_left} days remaining)")

    if tls_version in ("TLSv1", "TLSv1.1"):
        notes.append(f"Outdated TLS version: {tls_version} — upgrade to TLS 1.3")
    elif tls_version == "TLSv1.3":
        notes.append("Using TLS 1.3 — excellent")
    elif tls_version == "TLSv1.2":
        notes.append("Using TLS 1.2 — acceptable, consider upgrading to 1.3")

    if wildcards:
        notes.append(f"Wildcard certificate covers {len(wildcards)} domain patterns")

    org = issuer.get("organizationName", "")
    if not org:
        notes.append("Self-signed certificate — not trusted by browsers")
    return notes
