"""MITRE ATT&CK Framework integration — maps findings to techniques/tactics."""
from typing import Dict, List, Any

VULN_TO_MITRE: Dict[str, List[Dict]] = {
    "XSS": [
        {"technique_id": "T1059.007", "technique_name": "JavaScript", "tactic": "Execution",
         "tactic_id": "TA0002", "severity": "High",
         "description": "Adversaries abuse JavaScript via XSS to execute malicious code in victim browsers.",
         "mitigations": ["M1021 - Restrict Web-Based Content", "M1048 - Application Isolation"]},
        {"technique_id": "T1185", "technique_name": "Browser Session Hijacking", "tactic": "Collection",
         "tactic_id": "TA0009", "severity": "Critical",
         "description": "XSS steals session cookies enabling full account takeover.",
         "mitigations": ["M1054 - Software Configuration", "Set HttpOnly + Secure cookie flags"]},
        {"technique_id": "T1556", "technique_name": "Modify Authentication Process", "tactic": "Credential Access",
         "tactic_id": "TA0006", "severity": "High",
         "description": "Stored XSS can rewrite login forms to harvest credentials.",
         "mitigations": ["M1032 - Multi-factor Authentication", "CSP headers"]},
    ],
    "SQLi": [
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access",
         "tactic_id": "TA0001", "severity": "Critical",
         "description": "SQL injection exploits web application input handling to access databases.",
         "mitigations": ["M1016 - Vulnerability Scanning", "Parameterized queries / ORM"]},
        {"technique_id": "T1213", "technique_name": "Data from Information Repositories", "tactic": "Collection",
         "tactic_id": "TA0009", "severity": "Critical",
         "description": "Attackers dump entire database contents via UNION or error-based SQLi.",
         "mitigations": ["M1041 - Encrypt Sensitive Information", "Least-privilege DB accounts"]},
        {"technique_id": "T1565.001", "technique_name": "Stored Data Manipulation", "tactic": "Impact",
         "tactic_id": "TA0040", "severity": "High",
         "description": "SQLi enables INSERT/UPDATE/DELETE on production data.",
         "mitigations": ["M1022 - Restrict File and Directory Permissions"]},
    ],
    "SSRF": [
        {"technique_id": "T1090.002", "technique_name": "External Proxy", "tactic": "Command and Control",
         "tactic_id": "TA0011", "severity": "High",
         "description": "SSRF turns the vulnerable server into a proxy for reaching cloud metadata services and internal APIs.",
         "mitigations": ["M1037 - Filter Network Traffic", "Block 169.254.169.254"]},
        {"technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactic": "Discovery",
         "tactic_id": "TA0007", "severity": "High",
         "description": "SSRF can be used to enumerate internal services and retrieve sensitive files via file:// URIs.",
         "mitigations": ["M1030 - Network Segmentation"]},
    ],
    "LFI": [
        {"technique_id": "T1005", "technique_name": "Data from Local System", "tactic": "Collection",
         "tactic_id": "TA0009", "severity": "High",
         "description": "LFI reads arbitrary files from the server filesystem.",
         "mitigations": ["M1022 - Restrict File and Directory Permissions", "Chroot / containers"]},
        {"technique_id": "T1552.001", "technique_name": "Credentials in Files", "tactic": "Credential Access",
         "tactic_id": "TA0006", "severity": "Critical",
         "description": "LFI can expose /etc/passwd, .env files, or SSH keys.",
         "mitigations": ["M1027 - Password Policies", "Secrets management (Vault)"]},
    ],
    "Open Redirect": [
        {"technique_id": "T1566.002", "technique_name": "Spearphishing Link", "tactic": "Initial Access",
         "tactic_id": "TA0001", "severity": "Medium",
         "description": "Open redirects allow phishing via trusted domain URLs, bypassing email filters.",
         "mitigations": ["M1017 - User Training", "Allowlist redirect destinations"]},
    ],
    "RCE": [
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution",
         "tactic_id": "TA0002", "severity": "Critical",
         "description": "Remote code execution allows arbitrary OS commands on the server.",
         "mitigations": ["M1038 - Execution Prevention", "Disable shell_exec, system, etc."]},
        {"technique_id": "T1053", "technique_name": "Scheduled Task/Job", "tactic": "Persistence",
         "tactic_id": "TA0003", "severity": "Critical",
         "description": "RCE can establish persistence via cron jobs or startup tasks.",
         "mitigations": ["M1018 - User Account Management"]},
        {"technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
         "tactic_id": "TA0010", "severity": "Critical",
         "description": "Full server compromise via RCE enables data exfiltration.",
         "mitigations": ["M1037 - Filter Network Traffic", "Egress filtering"]},
    ],
    "Subdomain Takeover": [
        {"technique_id": "T1584.001", "technique_name": "Domains", "tactic": "Resource Development",
         "tactic_id": "TA0042", "severity": "High",
         "description": "Unclaimed subdomains (dangling DNS) can be registered by attackers for phishing/malware hosting.",
         "mitigations": ["M1056 - Pre-compromise", "Remove dangling CNAME records"]},
    ],
    "Information Disclosure": [
        {"technique_id": "T1213", "technique_name": "Data from Information Repositories", "tactic": "Collection",
         "tactic_id": "TA0009", "severity": "Medium",
         "description": "Misconfigured headers, debug pages, or error messages leak sensitive info.",
         "mitigations": ["M1041 - Encrypt Sensitive Information", "Disable debug mode"]},
    ],
    "IDOR": [
        {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access",
         "tactic_id": "TA0001", "severity": "High",
         "description": "IDOR allows accessing resources belonging to other users by manipulating IDs.",
         "mitigations": ["M1026 - Privileged Account Management", "Server-side authorization checks"]},
    ],
    "CSRF": [
        {"technique_id": "T1185", "technique_name": "Browser Session Hijacking", "tactic": "Collection",
         "tactic_id": "TA0009", "severity": "High",
         "description": "CSRF forces authenticated users to execute unauthorized actions.",
         "mitigations": ["M1054 - Software Configuration", "CSRF tokens, SameSite cookies"]},
    ],
    "XXE": [
        {"technique_id": "T1005", "technique_name": "Data from Local System", "tactic": "Collection",
         "tactic_id": "TA0009", "severity": "High",
         "description": "XXE injection reads local files via XML external entity references.",
         "mitigations": ["Disable external entities in XML parsers"]},
    ],
}

MITRE_TACTICS = {
    "TA0001": {"name": "Initial Access", "color": "#FF6B6B", "icon": "🚪"},
    "TA0002": {"name": "Execution", "color": "#FF8E53", "icon": "⚡"},
    "TA0003": {"name": "Persistence", "color": "#FFA726", "icon": "🔒"},
    "TA0004": {"name": "Privilege Escalation", "color": "#FFCA28", "icon": "⬆️"},
    "TA0005": {"name": "Defense Evasion", "color": "#D4E157", "icon": "🥷"},
    "TA0006": {"name": "Credential Access", "color": "#66BB6A", "icon": "🔑"},
    "TA0007": {"name": "Discovery", "color": "#26C6DA", "icon": "🔍"},
    "TA0008": {"name": "Lateral Movement", "color": "#42A5F5", "icon": "➡️"},
    "TA0009": {"name": "Collection", "color": "#7E57C2", "icon": "📦"},
    "TA0010": {"name": "Exfiltration", "color": "#AB47BC", "icon": "📤"},
    "TA0011": {"name": "Command and Control", "color": "#EC407A", "icon": "📡"},
    "TA0040": {"name": "Impact", "color": "#EF5350", "icon": "💥"},
    "TA0042": {"name": "Resource Development", "color": "#78909C", "icon": "🛠️"},
    "TA0043": {"name": "Reconnaissance", "color": "#8D6E63", "icon": "🕵️"},
}

TACTIC_ORDER = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004",
    "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0010",
    "TA0011", "TA0040",
]


def _normalize(vuln_type: str) -> str:
    v = vuln_type.upper()
    if "XSS" in v or "CROSS-SITE SCRIPT" in v:
        return "XSS"
    if "SQL" in v:
        return "SQLi"
    if "SSRF" in v:
        return "SSRF"
    if "LFI" in v or "LOCAL FILE" in v or "PATH TRAV" in v:
        return "LFI"
    if "REDIRECT" in v or "OPEN REDIR" in v:
        return "Open Redirect"
    if "RCE" in v or "COMMAND INJ" in v or "CODE EXEC" in v:
        return "RCE"
    if "SUBDOMAIN" in v or "TAKEOVER" in v:
        return "Subdomain Takeover"
    if "IDOR" in v or "BROKEN OBJ" in v:
        return "IDOR"
    if "CSRF" in v:
        return "CSRF"
    if "XXE" in v:
        return "XXE"
    if "INFO" in v or "DISCLOS" in v or "EXPOSURE" in v:
        return "Information Disclosure"
    return vuln_type


def map_findings_to_mitre(findings: list) -> dict:
    """Map vulnerability findings to MITRE ATT&CK techniques and build kill-chain coverage."""
    techniques: Dict[str, dict] = {}
    tactic_coverage: Dict[str, dict] = {}

    for finding in findings:
        normalized = _normalize(finding.get("type", "Unknown"))
        for tech in VULN_TO_MITRE.get(normalized, []):
            tid = tech["technique_id"]
            if tid not in techniques:
                techniques[tid] = {**tech, "affected_findings": []}
            techniques[tid]["affected_findings"].append({
                "url": finding.get("url", ""),
                "parameter": finding.get("parameter", ""),
                "severity": finding.get("severity", "Medium"),
            })
            tac_id = tech["tactic_id"]
            if tac_id not in tactic_coverage:
                info = MITRE_TACTICS.get(tac_id, {"name": tac_id, "color": "#888", "icon": "?"})
                tactic_coverage[tac_id] = {**info, "tactic_id": tac_id, "technique_count": 0}
            tactic_coverage[tac_id]["technique_count"] += 1

    kill_chain = [
        tactic_coverage[t] for t in TACTIC_ORDER if t in tactic_coverage
    ]

    severity_scores = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    risk_score = sum(
        severity_scores.get(t.get("severity", "Low"), 1) * len(t["affected_findings"])
        for t in techniques.values()
    )

    return {
        "techniques": list(techniques.values()),
        "tactic_coverage": tactic_coverage,
        "kill_chain": kill_chain,
        "total_techniques": len(techniques),
        "tactics_hit": len(tactic_coverage),
        "risk_score": min(risk_score, 100),
        "attack_surface": _assess_attack_surface(tactic_coverage),
    }


def _assess_attack_surface(tactic_coverage: dict) -> str:
    n = len(tactic_coverage)
    if n >= 6:
        return "CRITICAL — Full kill chain coverage detected"
    if n >= 4:
        return "HIGH — Multi-stage attack path identified"
    if n >= 2:
        return "MEDIUM — Partial kill chain exposure"
    if n >= 1:
        return "LOW — Limited attack surface"
    return "MINIMAL — No mapped techniques"


def get_all_techniques() -> List[dict]:
    """Return the full embedded ATT&CK technique library."""
    seen = {}
    for techniques in VULN_TO_MITRE.values():
        for t in techniques:
            seen[t["technique_id"]] = t
    return list(seen.values())
