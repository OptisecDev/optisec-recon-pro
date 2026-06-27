"""Compliance Checker — ISO 27001, NIST CSF, GDPR, PCI-DSS frameworks."""

import asyncio
import httpx
from datetime import datetime
from typing import Optional


FRAMEWORKS = {
    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "short": "ISO 27001",
        "color": "#0080ff",
        "controls": [
            {"id": "A.5.1", "domain": "Information Security Policies",
             "control": "Policies for information security",
             "check": "security_policy_documented"},
            {"id": "A.5.15", "domain": "Access Control",
             "control": "Access control policy",
             "check": "access_control_policy"},
            {"id": "A.5.16", "domain": "Access Control",
             "control": "Identity management",
             "check": "identity_management"},
            {"id": "A.5.17", "domain": "Access Control",
             "control": "Authentication information",
             "check": "strong_authentication"},
            {"id": "A.8.7", "domain": "Protection Against Malware",
             "control": "Protection against malware",
             "check": "malware_protection"},
            {"id": "A.8.8", "domain": "Vulnerability Management",
             "control": "Management of technical vulnerabilities",
             "check": "vuln_management"},
            {"id": "A.8.9", "domain": "Configuration Management",
             "control": "Configuration management",
             "check": "config_management"},
            {"id": "A.8.12", "domain": "Data Leakage Prevention",
             "control": "Data leakage prevention",
             "check": "dlp_controls"},
            {"id": "A.8.16", "domain": "Monitoring Activities",
             "control": "Monitoring activities",
             "check": "security_monitoring"},
            {"id": "A.8.24", "domain": "Cryptography",
             "control": "Use of cryptography",
             "check": "encryption_in_use"},
            {"id": "A.8.25", "domain": "Secure Development",
             "control": "Secure development life cycle",
             "check": "sdlc_security"},
            {"id": "A.8.29", "domain": "Secure Development",
             "control": "Security testing in development and acceptance",
             "check": "security_testing"},
        ],
    },
    "nist": {
        "name": "NIST Cybersecurity Framework 2.0",
        "short": "NIST CSF",
        "color": "#00ff88",
        "controls": [
            {"id": "GV.OC-01", "domain": "GOVERN — Organizational Context",
             "control": "Mission and stakeholder expectations documented",
             "check": "governance_documented"},
            {"id": "GV.RM-01", "domain": "GOVERN — Risk Management",
             "control": "Risk management objectives established",
             "check": "risk_management"},
            {"id": "ID.AM-01", "domain": "IDENTIFY — Asset Management",
             "control": "Inventory of hardware assets maintained",
             "check": "asset_inventory"},
            {"id": "ID.AM-02", "domain": "IDENTIFY — Asset Management",
             "control": "Inventory of software assets maintained",
             "check": "software_inventory"},
            {"id": "ID.RA-01", "domain": "IDENTIFY — Risk Assessment",
             "control": "Vulnerabilities identified and documented",
             "check": "vuln_identification"},
            {"id": "PR.AA-01", "domain": "PROTECT — Identity Management",
             "control": "Identities and credentials managed",
             "check": "identity_credentials"},
            {"id": "PR.AA-05", "domain": "PROTECT — Access Control",
             "control": "Access permissions are granted with least privilege",
             "check": "least_privilege"},
            {"id": "PR.DS-01", "domain": "PROTECT — Data Security",
             "control": "Data-at-rest are protected",
             "check": "data_at_rest_encryption"},
            {"id": "PR.DS-02", "domain": "PROTECT — Data Security",
             "control": "Data-in-transit are protected",
             "check": "data_in_transit_encryption"},
            {"id": "DE.CM-01", "domain": "DETECT — Continuous Monitoring",
             "control": "Networks and network services are monitored",
             "check": "network_monitoring"},
            {"id": "RS.MA-01", "domain": "RESPOND — Incident Management",
             "control": "Incident response plan executed",
             "check": "incident_response_plan"},
            {"id": "RC.RP-01", "domain": "RECOVER — Incident Recovery",
             "control": "Recovery plan executed during/after an incident",
             "check": "recovery_plan"},
        ],
    },
    "gdpr": {
        "name": "General Data Protection Regulation",
        "short": "GDPR",
        "color": "#ff6b35",
        "controls": [
            {"id": "Art.5", "domain": "Principles",
             "control": "Lawfulness, fairness and transparency in data processing",
             "check": "lawful_processing"},
            {"id": "Art.6", "domain": "Lawfulness",
             "control": "Legal basis for processing personal data",
             "check": "legal_basis"},
            {"id": "Art.13", "domain": "Transparency",
             "control": "Privacy notice provided at data collection",
             "check": "privacy_notice"},
            {"id": "Art.17", "domain": "Data Subject Rights",
             "control": "Right to erasure (right to be forgotten) implemented",
             "check": "right_to_erasure"},
            {"id": "Art.20", "domain": "Data Subject Rights",
             "control": "Right to data portability implemented",
             "check": "data_portability"},
            {"id": "Art.25", "domain": "Privacy by Design",
             "control": "Data protection by design and by default",
             "check": "privacy_by_design"},
            {"id": "Art.30", "domain": "Accountability",
             "control": "Records of processing activities maintained",
             "check": "processing_records"},
            {"id": "Art.32", "domain": "Security",
             "control": "Security of processing — appropriate technical measures",
             "check": "technical_security_measures"},
            {"id": "Art.33", "domain": "Breach Notification",
             "control": "Personal data breach notification within 72 hours",
             "check": "breach_notification_72h"},
            {"id": "Art.35", "domain": "DPIA",
             "control": "Data Protection Impact Assessment conducted",
             "check": "dpia_conducted"},
            {"id": "Art.37", "domain": "DPO",
             "control": "Data Protection Officer appointed where required",
             "check": "dpo_appointed"},
            {"id": "Art.44", "domain": "International Transfers",
             "control": "Transfers to third countries compliant",
             "check": "international_transfers"},
        ],
    },
    "pci_dss": {
        "name": "PCI DSS v4.0",
        "short": "PCI DSS",
        "color": "#ff3366",
        "controls": [
            {"id": "Req 1", "domain": "Network Security",
             "control": "Install and maintain network security controls",
             "check": "network_security_controls"},
            {"id": "Req 2", "domain": "System Configuration",
             "control": "Apply secure configurations to all system components",
             "check": "secure_configurations"},
            {"id": "Req 3", "domain": "Account Data Protection",
             "control": "Protect stored account data",
             "check": "stored_data_protection"},
            {"id": "Req 4", "domain": "Encryption",
             "control": "Protect cardholder data with strong cryptography",
             "check": "strong_cryptography"},
            {"id": "Req 6", "domain": "Vulnerability Management",
             "control": "Develop and maintain secure systems and software",
             "check": "secure_development"},
            {"id": "Req 7", "domain": "Access Control",
             "control": "Restrict access to system components by business need",
             "check": "need_to_know_access"},
            {"id": "Req 8", "domain": "Authentication",
             "control": "Identify users and authenticate access",
             "check": "user_authentication"},
            {"id": "Req 10", "domain": "Logging",
             "control": "Log and monitor all access to system components",
             "check": "audit_logging"},
            {"id": "Req 11", "domain": "Testing",
             "control": "Test security of systems and networks regularly",
             "check": "regular_testing"},
            {"id": "Req 12", "domain": "Policy",
             "control": "Support information security with organizational policies",
             "check": "security_policies"},
        ],
    },
}


async def assess_target(target_url: str, framework: str, answers: dict) -> dict:
    framework_data = FRAMEWORKS.get(framework)
    if not framework_data:
        return {"error": f"Unknown framework: {framework}"}

    controls = framework_data["controls"]
    assessed = []
    passed = 0
    failed = 0
    na = 0

    for ctrl in controls:
        check_key = ctrl["check"]
        answer = answers.get(check_key, "unknown")

        if answer in ("yes", "true", "1", True):
            status = "compliant"
            passed += 1
        elif answer in ("no", "false", "0", False):
            status = "non_compliant"
            failed += 1
        elif answer in ("na", "n/a"):
            status = "not_applicable"
            na += 1
        else:
            status = "unknown"

        assessed.append({
            **ctrl,
            "status": status,
            "answer": answer,
            "risk": _risk_level(status),
        })

    total_checkable = passed + failed
    score = round((passed / total_checkable * 100) if total_checkable > 0 else 0, 1)

    return {
        "framework": framework,
        "framework_name": framework_data["name"],
        "target": target_url,
        "assessed_at": datetime.utcnow().isoformat(),
        "score": score,
        "passed": passed,
        "failed": failed,
        "not_applicable": na,
        "total": len(controls),
        "grade": _grade(score),
        "controls": assessed,
        "recommendations": _recommendations(assessed, framework),
        "risk_level": _overall_risk(score),
    }


async def auto_probe_target(target_url: str) -> dict:
    """Probe target to auto-detect some compliance signals."""
    signals = {}
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        try:
            r = await client.get(target_url)
            headers = {k.lower(): v for k, v in r.headers.items()}

            signals["https_in_use"] = target_url.startswith("https://")
            signals["hsts"] = "strict-transport-security" in headers
            signals["csp"] = "content-security-policy" in headers
            signals["x_frame_options"] = "x-frame-options" in headers
            signals["x_content_type"] = "x-content-type-options" in headers
            signals["referrer_policy"] = "referrer-policy" in headers
            signals["server_exposed"] = "server" in headers
            signals["status_code"] = r.status_code
            signals["cookies"] = [
                {
                    "name": c.name,
                    "secure": c.get_nonstandard_attr("Secure") is not None or "secure" in str(c).lower(),
                    "httponly": "httponly" in str(c).lower(),
                    "samesite": c.get_nonstandard_attr("SameSite"),
                }
                for c in r.cookies.jar
            ]
        except Exception as e:
            signals["probe_error"] = str(e)

    return signals


def get_frameworks() -> dict:
    return {k: {"name": v["name"], "short": v["short"], "color": v["color"],
                 "control_count": len(v["controls"])} for k, v in FRAMEWORKS.items()}


def get_framework_controls(framework: str) -> list:
    return FRAMEWORKS.get(framework, {}).get("controls", [])


def _risk_level(status: str) -> str:
    return {"compliant": "low", "non_compliant": "high",
            "not_applicable": "none", "unknown": "medium"}.get(status, "medium")


def _grade(score: float) -> str:
    if score >= 95: return "A+"
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def _overall_risk(score: float) -> str:
    if score >= 90: return "low"
    if score >= 70: return "medium"
    if score >= 50: return "high"
    return "critical"


def _recommendations(controls: list, framework: str) -> list:
    recs = []
    for ctrl in controls:
        if ctrl["status"] == "non_compliant":
            recs.append({
                "control_id": ctrl["id"],
                "domain": ctrl["domain"],
                "action": f"Implement: {ctrl['control']}",
                "priority": "high",
            })
    return recs[:10]
