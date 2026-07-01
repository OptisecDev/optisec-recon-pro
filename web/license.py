"""OPTISEC License Engine — generation, validation, and feature gating."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

# ─── Config ───────────────────────────────────────────────────────────────────

_LICENSE_SECRET = os.environ.get(
    "OPTISEC_LICENSE_SECRET",
    "optisec-license-engine-v4-singularity-2026",
)
_LICENSE_FILE = Path(__file__).parent.parent / "data" / "license.json"

# ─── Feature Definitions ──────────────────────────────────────────────────────

TIER_FEATURES: dict[str, list[str]] = {
    "free": [
        "scan_xss", "scan_sqli", "scan_dns", "scan_whois",
        "osint_basic", "pdf_report",
    ],
    "pro": [
        "scan_xss", "scan_sqli", "scan_dns", "scan_whois",
        "scan_ssrf", "scan_lfi", "scan_nmap", "scan_ssl",
        "scan_headers", "scan_ports", "scan_subdomain", "scan_redirect",
        "osint_basic", "osint_advanced",
        "ai_analyze", "nlp_command",
        "bug_bounty", "compliance",
        "pdf_report", "api_access",
        "behavioral_ueba", "zero_day_predict", "attack_patterns",
        "ngfw", "firewall", "vpn", "quantum", "honeypot",
    ],
    "enterprise": [
        "*",  # all features
        "scan_xss", "scan_sqli", "scan_dns", "scan_whois",
        "scan_ssrf", "scan_lfi", "scan_nmap", "scan_ssl",
        "scan_headers", "scan_ports", "scan_subdomain", "scan_redirect",
        "osint_basic", "osint_advanced", "osint_darkweb",
        "ai_analyze", "nlp_command",
        "bug_bounty", "compliance",
        "pdf_report", "api_access",
        "behavioral_ueba", "zero_day_predict", "attack_patterns", "ai_red_team",
        "autonomous_redteam", "attack_navigator",
        "ngfw", "firewall", "vpn", "quantum", "honeypot",
        "federation", "threat_feed", "ioc_correlations",
        "darkweb_intel", "user_management", "multi_node",
    ],
}

TIER_LIMITS: dict[str, dict] = {
    "free":       {"max_targets": 3,   "max_scans_day": 10,  "max_users": 1},
    "pro":        {"max_targets": 50,  "max_scans_day": 500, "max_users": 5},
    "enterprise": {"max_targets": -1,  "max_scans_day": -1,  "max_users": -1},
}

TIER_LABELS = {
    "free":       ("FREE",       "#8b949e"),
    "pro":        ("PRO",        "#00ff88"),
    "enterprise": ("ENTERPRISE", "#bc8cff"),
}

FEATURE_LABELS: dict[str, str] = {
    "scan_xss":          "XSS Scanner",
    "scan_sqli":         "SQL Injection",
    "scan_ssrf":         "SSRF Scanner",
    "scan_lfi":          "LFI Scanner",
    "scan_nmap":         "Nmap Port Scan",
    "scan_ssl":          "SSL/TLS Analysis",
    "scan_headers":      "Security Headers",
    "scan_subdomain":    "Subdomain Enum",
    "osint_basic":       "OSINT Basic",
    "osint_advanced":    "OSINT Advanced",
    "osint_darkweb":     "Dark Web OSINT",
    "ai_analyze":        "AI Analysis (Groq)",
    "nlp_command":       "Arabic/EN NLP",
    "bug_bounty":        "Bug Bounty Platform",
    "compliance":        "Compliance Checker",
    "pdf_report":        "PDF Reports",
    "api_access":        "REST API Access",
    "behavioral_ueba":   "Behavioral UEBA",
    "zero_day_predict":  "Zero-Day Prediction",
    "attack_patterns":   "Attack Patterns",
    "ai_red_team":       "AI Red Team",
    "autonomous_redteam":"Autonomous RedTeam",
    "attack_navigator":  "ATT&CK Navigator",
    "ngfw":              "NGFW v2 ML/DPI",
    "firewall":          "AI Firewall",
    "honeypot":          "Honeypot Deception",
    "vpn":               "WireGuard VPN",
    "quantum":           "Quantum Crypto",
    "federation":        "Federated Scan",
    "threat_feed":       "Global Threat Feed",
    "ioc_correlations":  "IOC Correlations",
    "darkweb_intel":     "Dark Web Intel",
    "user_management":   "User Management",
    "multi_node":        "Multi-Node Deploy",
}

# ─── License Data ─────────────────────────────────────────────────────────────

@dataclass
class License:
    tier: str                    # free | pro | enterprise
    issued_to: str               # company / person name
    email: str
    issued_at: str               # ISO datetime
    expires_at: str              # ISO datetime
    key: str                     # the full license key string
    features: list[str] = field(default_factory=list)
    max_targets: int = 3
    max_scans_day: int = 10
    max_users: int = 1

    # ── computed helpers ──────────────────────────────────────────
    @property
    def expired(self) -> bool:
        try:
            return datetime.utcnow() > datetime.fromisoformat(self.expires_at)
        except Exception:
            return True

    @property
    def days_left(self) -> int:
        try:
            delta = datetime.fromisoformat(self.expires_at) - datetime.utcnow()
            return max(0, delta.days)
        except Exception:
            return 0

    @property
    def tier_label(self) -> str:
        return TIER_LABELS.get(self.tier, ("UNKNOWN", "#ff4444"))[0]

    @property
    def tier_color(self) -> str:
        return TIER_LABELS.get(self.tier, ("UNKNOWN", "#ff4444"))[1]

    def has_feature(self, feature: str) -> bool:
        if self.expired:
            # Expired — fall back to free features
            return feature in TIER_FEATURES["free"]
        return "*" in self.features or feature in self.features

    def to_dict(self) -> dict:
        return asdict(self)


# ─── Free (default) License ───────────────────────────────────────────────────

def _free_license() -> License:
    now = datetime.utcnow()
    return License(
        tier="free",
        issued_to="Trial User",
        email="",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(days=36500)).isoformat(),  # never expires for free
        key="FREE",
        features=TIER_FEATURES["free"],
        max_targets=TIER_LIMITS["free"]["max_targets"],
        max_scans_day=TIER_LIMITS["free"]["max_scans_day"],
        max_users=TIER_LIMITS["free"]["max_users"],
    )


# ─── Key Generation ───────────────────────────────────────────────────────────

def generate_license_key(
    tier: str,
    issued_to: str,
    email: str,
    days: int = 365,
) -> str:
    """Generate a signed OPTISEC license key."""
    if tier not in TIER_FEATURES:
        raise ValueError(f"Unknown tier: {tier}")

    now = datetime.utcnow()
    limits = TIER_LIMITS[tier]
    payload = {
        "tier": tier,
        "issued_to": issued_to,
        "email": email,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=days)).isoformat(),
        "features": TIER_FEATURES[tier],
        "max_targets": limits["max_targets"],
        "max_scans_day": limits["max_scans_day"],
        "max_users": limits["max_users"],
        "version": "4.0",
    }
    data_bytes = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(_LICENSE_SECRET.encode(), data_bytes, hashlib.sha256).hexdigest()
    encoded = base64.urlsafe_b64encode(data_bytes).decode().rstrip("=")
    return f"OPS4-{tier.upper()}-{encoded}.{sig[:16]}"


# ─── Key Verification ─────────────────────────────────────────────────────────

def verify_license_key(key: str) -> tuple[bool, str, Optional[License]]:
    """
    Returns (valid, error_message, license_object).
    error_message is empty on success.
    """
    key = key.strip()
    if not key or key == "FREE":
        return False, "No license key provided", None

    try:
        # Expected format: OPS4-TIER-{b64}.{sig16}
        parts = key.split("-", 2)
        if len(parts) < 3 or parts[0] != "OPS4":
            return False, "Invalid key format (must start with OPS4-)", None

        rest = parts[2]  # {b64}.{sig16}
        if "." not in rest:
            return False, "Invalid key format (missing signature separator)", None

        b64_part, sig_part = rest.rsplit(".", 1)

        # Restore base64 padding
        pad = 4 - len(b64_part) % 4
        if pad != 4:
            b64_part += "=" * pad

        data_bytes = base64.urlsafe_b64decode(b64_part)
        expected_sig = hmac.new(
            _LICENSE_SECRET.encode(), data_bytes, hashlib.sha256
        ).hexdigest()[:16]

        if not hmac.compare_digest(expected_sig, sig_part.lower()):
            return False, "License signature invalid — key may be tampered or forged", None

        payload = json.loads(data_bytes)
        lic = License(
            tier=payload["tier"],
            issued_to=payload["issued_to"],
            email=payload["email"],
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            key=key,
            features=payload["features"],
            max_targets=payload["max_targets"],
            max_scans_day=payload["max_scans_day"],
            max_users=payload.get("max_users", 1),
        )
        if lic.expired:
            return False, f"License expired on {lic.expires_at[:10]}", lic

        return True, "", lic

    except (json.JSONDecodeError, KeyError) as e:
        return False, f"Malformed license payload: {e}", None
    except Exception as e:
        return False, f"Verification error: {e}", None


# ─── Persistence ──────────────────────────────────────────────────────────────

def save_license(lic: License) -> None:
    _LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LICENSE_FILE.write_text(json.dumps(lic.to_dict(), indent=2))


def load_license() -> License:
    if not _LICENSE_FILE.exists():
        return _free_license()
    try:
        data = json.loads(_LICENSE_FILE.read_text())
        lic = License(**{k: v for k, v in data.items() if k in License.__dataclass_fields__})
        # Re-verify signature each load
        valid, _, verified = verify_license_key(lic.key)
        if not valid and lic.key != "FREE":
            return _free_license()
        return lic
    except Exception:
        return _free_license()


# ─── Global Instance ──────────────────────────────────────────────────────────

_current_license: Optional[License] = None


def get_license() -> License:
    global _current_license
    if _current_license is None:
        _current_license = load_license()
    return _current_license


def reload_license() -> License:
    global _current_license
    _current_license = load_license()
    return _current_license


def activate_license(key: str) -> tuple[bool, str, Optional[License]]:
    """Activate a key globally. Returns (success, message, license)."""
    valid, err, lic = verify_license_key(key)
    if not valid:
        return False, err, None
    save_license(lic)
    global _current_license
    _current_license = lic
    return True, f"License activated — {lic.tier_label} tier for {lic.issued_to}", lic


def deactivate_license() -> None:
    global _current_license
    free = _free_license()
    save_license(free)
    _current_license = free


# ─── Feature Gate Helper ──────────────────────────────────────────────────────

def require_feature(feature: str) -> tuple[bool, str]:
    """Return (allowed, upgrade_message). Use in route handlers."""
    lic = get_license()
    if lic.has_feature(feature):
        return True, ""
    label = FEATURE_LABELS.get(feature, feature)
    if lic.tier == "free":
        return False, f'"{label}" requires PRO or ENTERPRISE license.'
    if lic.tier == "pro":
        return False, f'"{label}" requires ENTERPRISE license.'
    return False, f'"{label}" is not available in your plan.'
