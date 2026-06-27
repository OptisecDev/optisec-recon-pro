"""SSL/TLS Certificate Analysis."""

import ssl
import socket
from datetime import datetime, timezone


def _parse_cert_der(der: bytes) -> dict:
    """Parse DER certificate using cryptography library (available via cryptography>=41)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert_obj = x509.load_der_x509_certificate(der, default_backend())
        subject = {attr.oid._name: attr.value for attr in cert_obj.subject}
        issuer = {attr.oid._name: attr.value for attr in cert_obj.issuer}
        not_before = cert_obj.not_valid_before_utc if hasattr(cert_obj, "not_valid_before_utc") else cert_obj.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert_obj.not_valid_after_utc if hasattr(cert_obj, "not_valid_after_utc") else cert_obj.not_valid_after.replace(tzinfo=timezone.utc)
        serial = format(cert_obj.serial_number, "X")
        sans = []
        try:
            san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        return {"subject": subject, "issuer": issuer,
                "not_before": not_before, "not_after": not_after,
                "serial": serial, "sans": sans}
    except Exception:
        return {}


def analyze_ssl(domain: str, port: int = 443) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                tls_version = ssock.version()
        cert_data = _parse_cert_der(der) if der else {}
    except Exception as e:
        return {"domain": domain, "error": str(e), "valid": False}

    # Use parsed cert data
    not_before = cert_data.get("not_before")
    not_after = cert_data.get("not_after")
    subject = cert_data.get("subject", {})
    issuer = cert_data.get("issuer", {})
    san_list = list(cert_data.get("sans", []))

    now = datetime.now(timezone.utc)
    expired = bool(not_after and not_after < now)
    days_left = (not_after - now).days if not_after else None
    expiring_soon = days_left is not None and 0 < days_left <= 30
    wildcards = [s for s in san_list if s.startswith("*")]

    # Normalize subject/issuer keys from cryptography OID names
    cn = (subject.get("commonName") or subject.get("common_name") or
          subject.get("CN") or "")
    issuer_org = (issuer.get("organizationName") or issuer.get("organization_name") or
                  issuer.get("O") or issuer.get("commonName") or "")

    risk_score = _calc_risk(expired, expiring_soon, tls_version, wildcards, {"organizationName": issuer_org})

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
        "common_name": cn,
        "issuer_name": issuer_org,
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
        "key_bits": cipher[2] if cipher else None,
        "sans": san_list,
        "wildcard_count": len(wildcards),
        "wildcards": wildcards,
        "serial_number": cert_data.get("serial", ""),
        "risk_score": risk_score,
        "risk_label": "HIGH" if risk_score > 60 else "MEDIUM" if risk_score > 30 else "LOW",
        "notes": _build_notes(expired, expiring_soon, tls_version, wildcards, days_left,
                              {"organizationName": issuer_org}),
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
