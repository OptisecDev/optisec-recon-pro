"""AI Red Team — automated adversarial simulation using LLM + vulnerability data."""

import os
import json
import asyncio
import httpx
from datetime import datetime
from pathlib import Path
from typing import Optional

ENGAGEMENTS_FILE = Path("data/red_team_engagements.json")

ATTACK_CATEGORIES = [
    "reconnaissance", "social_engineering", "web_application",
    "network_exploitation", "privilege_escalation", "lateral_movement",
    "data_exfiltration", "persistence", "defense_evasion",
]

TECHNIQUE_LIBRARY = {
    "reconnaissance": [
        {"id": "T1595", "name": "Active Scanning", "steps": ["Port scan (nmap -sV)", "Service fingerprinting", "OS detection"]},
        {"id": "T1592", "name": "Gather Victim Host Info", "steps": ["Shodan/Censys lookup", "Certificate transparency", "OSINT aggregation"]},
        {"id": "T1596", "name": "Search Open Tech Databases", "steps": ["NVD CVE search", "GitHub exposure search", "Pastebin monitoring"]},
    ],
    "web_application": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "steps": ["XSS testing", "SQLi fuzzing", "SSRF probing", "LFI/RFI testing"]},
        {"id": "T1059.007", "name": "JavaScript Execution", "steps": ["DOM-based XSS", "Prototype pollution", "JSONP hijacking"]},
        {"id": "T1552.001", "name": "Credentials in Files", "steps": ["robots.txt enumeration", "Backup file discovery", "Git exposure (.git)"]},
    ],
    "privilege_escalation": [
        {"id": "T1548", "name": "Abuse Elevation Control", "steps": ["SUID/SGID enumeration", "Sudo misconfigurations", "Capabilities abuse"]},
        {"id": "T1574", "name": "Hijack Execution Flow", "steps": ["DLL hijacking", "PATH manipulation", "LD_PRELOAD abuse"]},
    ],
    "lateral_movement": [
        {"id": "T1021.001", "name": "Remote Desktop Protocol", "steps": ["RDP credential spray", "BlueKeep check", "Restricted admin mode"]},
        {"id": "T1021.006", "name": "Windows Remote Management", "steps": ["WinRM enumeration", "Evil-WinRM", "Pass-the-hash via WinRM"]},
    ],
    "persistence": [
        {"id": "T1505.003", "name": "Web Shell", "steps": ["Upload PHP/ASP webshell", "Establish C2 via shell", "Scheduled task creation"]},
        {"id": "T1136", "name": "Create Account", "steps": ["Create backdoor user", "Add to sudoers", "SSH key injection"]},
    ],
}


def _load_engagements() -> list:
    ENGAGEMENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if ENGAGEMENTS_FILE.exists():
        return json.loads(ENGAGEMENTS_FILE.read_text())
    return []


def _save_engagements(engagements: list) -> None:
    ENGAGEMENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ENGAGEMENTS_FILE.write_text(json.dumps(engagements, indent=2, default=str))


async def create_engagement(
    target: str,
    scope: list[str],
    objectives: list[str],
    categories: list[str],
    rules_of_engagement: str = "",
) -> dict:
    groq_key = os.environ.get("GROQ_API_KEY", "")

    if groq_key:
        plan = await _ai_generate_plan(target, scope, objectives, categories, groq_key)
    else:
        plan = _template_plan(target, scope, objectives, categories)

    engagement = {
        "id": f"RT-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        "target": target,
        "scope": scope,
        "objectives": objectives,
        "categories": categories,
        "rules_of_engagement": rules_of_engagement,
        "status": "planned",
        "created_at": datetime.utcnow().isoformat(),
        "plan": plan,
        "findings": [],
        "risk_rating": plan.get("estimated_risk", "high"),
    }

    engagements = _load_engagements()
    engagements.insert(0, engagement)
    _save_engagements(engagements[:50])

    return engagement


async def _ai_generate_plan(
    target: str, scope: list, objectives: list, categories: list, api_key: str
) -> dict:
    techniques = []
    for cat in categories:
        techniques.extend(TECHNIQUE_LIBRARY.get(cat, []))

    prompt = f"""You are an elite red team operator planning a penetration test engagement.

Target: {target}
Scope: {', '.join(scope)}
Objectives: {', '.join(objectives)}
Attack Categories: {', '.join(categories)}

Available MITRE techniques for this engagement:
{json.dumps([{'id': t['id'], 'name': t['name']} for t in techniques], indent=2)}

Generate a detailed red team plan in JSON:
{{
  "phases": [
    {{
      "phase_name": "<name>",
      "duration_days": <int>,
      "techniques": ["<T-ID>"],
      "tools": ["<tool1>", "<tool2>"],
      "success_criteria": "<what defines success>",
      "deliverables": ["<deliverable1>"]
    }}
  ],
  "estimated_risk": "<low|medium|high|critical>",
  "estimated_duration_days": <int>,
  "key_attack_vectors": ["<vector1>", "<vector2>"],
  "detection_evasion": ["<technique1>"],
  "pivot_points": ["<pivot1>"],
  "executive_summary": "<2-3 sentences>"
}}"""

    async with httpx.AsyncClient(timeout=45) as client:
        try:
            r = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.4,
                    "max_tokens": 1200,
                },
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            import re
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())
        except Exception:
            pass
    return _template_plan(target, scope, objectives, categories)


def _template_plan(target: str, scope: list, objectives: list, categories: list) -> dict:
    phases = []

    if "reconnaissance" in categories:
        phases.append({
            "phase_name": "Reconnaissance",
            "duration_days": 3,
            "techniques": ["T1595", "T1592", "T1596"],
            "tools": ["nmap", "amass", "shodan", "theHarvester", "recon-ng"],
            "success_criteria": "Complete asset inventory and attack surface map",
            "deliverables": ["Asset list", "Network topology diagram", "Technology stack report"],
        })

    if "web_application" in categories:
        phases.append({
            "phase_name": "Web Application Testing",
            "duration_days": 5,
            "techniques": ["T1190", "T1059.007", "T1552.001"],
            "tools": ["burpsuite", "sqlmap", "nuclei", "nikto", "wfuzz"],
            "success_criteria": "At least one exploitable vulnerability found",
            "deliverables": ["Vulnerability report", "PoC exploits", "Remediation guidance"],
        })

    if "privilege_escalation" in categories:
        phases.append({
            "phase_name": "Post-Exploitation",
            "duration_days": 2,
            "techniques": ["T1548", "T1574"],
            "tools": ["linpeas", "winpeas", "bloodhound", "mimikatz"],
            "success_criteria": "Root/SYSTEM access achieved",
            "deliverables": ["Privilege escalation path", "Credential dump report"],
        })

    phases.append({
        "phase_name": "Reporting",
        "duration_days": 2,
        "techniques": [],
        "tools": ["dradis", "serpico", "plextrac"],
        "success_criteria": "Comprehensive report delivered",
        "deliverables": ["Executive report", "Technical findings", "Remediation roadmap"],
    })

    return {
        "phases": phases,
        "estimated_risk": "high",
        "estimated_duration_days": sum(p["duration_days"] for p in phases),
        "key_attack_vectors": ["Web application vulnerabilities", "Misconfigured services", "Weak credentials"],
        "detection_evasion": ["Low-and-slow scanning", "Mimicking legitimate traffic", "Using HTTPS for C2"],
        "pivot_points": ["Web shell", "Database server", "Internal API"],
        "executive_summary": f"Red team engagement against {target} covering {len(categories)} attack categories over {sum(p['duration_days'] for p in phases)} days.",
    }


async def log_finding(engagement_id: str, finding: dict) -> dict:
    engagements = _load_engagements()
    eng = next((e for e in engagements if e["id"] == engagement_id), None)
    if not eng:
        return {"error": f"Engagement {engagement_id} not found"}

    finding["id"] = f"F-{len(eng['findings']) + 1:03d}"
    finding["logged_at"] = datetime.utcnow().isoformat()
    eng["findings"].append(finding)
    _save_engagements(engagements)
    return finding


def list_engagements() -> list:
    return _load_engagements()


def get_engagement(engagement_id: str) -> Optional[dict]:
    return next((e for e in _load_engagements() if e["id"] == engagement_id), None)


def get_technique_library() -> dict:
    return TECHNIQUE_LIBRARY
