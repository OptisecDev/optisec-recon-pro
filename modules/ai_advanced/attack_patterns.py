"""Attack Pattern Recognition — correlate events into kill-chain stages."""

import re
import json
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from typing import Optional

PATTERN_DB = Path("data/attack_patterns.json")

# MITRE ATT&CK Kill Chain Stages (simplified)
KILL_CHAIN = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
]

# Pattern signatures mapped to kill-chain stages + techniques
ATTACK_PATTERNS = [
    {
        "id": "RECON-001",
        "name": "Port Scanning",
        "stage": "reconnaissance",
        "technique_id": "T1595.001",
        "indicators": ["multiple ports", "port scan", "syn scan", "nmap", "masscan"],
        "log_patterns": [
            r"(?i)(nmap|masscan|port.?scan|syn.?flood)",
            r"(\d{1,3}\.){3}\d{1,3}:\d+ .*(REJECT|RESET|TIMEOUT)",
        ],
        "severity": "medium",
    },
    {
        "id": "RECON-002",
        "name": "Subdomain Enumeration",
        "stage": "reconnaissance",
        "technique_id": "T1590.001",
        "indicators": ["subdomain", "dns brute", "zone transfer", "amass", "subfinder"],
        "log_patterns": [r"(?i)(zone.?transfer|AXFR|sublist3r|amass|subfinder|dnsx)"],
        "severity": "low",
    },
    {
        "id": "DELIVERY-001",
        "name": "Phishing via Email",
        "stage": "delivery",
        "technique_id": "T1566.001",
        "indicators": ["phish", "suspicious attachment", "macro", ".docm", ".xlsm", "credential harvest"],
        "log_patterns": [r"(?i)(phish|malicious.attach|macro.enabled|credential.harvest)"],
        "severity": "high",
    },
    {
        "id": "EXPLOIT-001",
        "name": "SQL Injection",
        "stage": "exploitation",
        "technique_id": "T1190",
        "indicators": ["union select", "sqlmap", "1=1", "blind sqli", "time-based"],
        "log_patterns": [
            r"(?i)(union\s+select|1\s*=\s*1|sqlmap|sleep\(\d+\)|benchmark\()",
        ],
        "severity": "critical",
    },
    {
        "id": "EXPLOIT-002",
        "name": "XSS Exploitation",
        "stage": "exploitation",
        "technique_id": "T1059.007",
        "indicators": ["<script>", "javascript:", "xss", "dom injection"],
        "log_patterns": [r"(?i)(<script|javascript:|onerror=|document\.cookie)"],
        "severity": "high",
    },
    {
        "id": "EXPLOIT-003",
        "name": "Remote Code Execution",
        "stage": "exploitation",
        "technique_id": "T1190",
        "indicators": ["rce", "command execution", "os.system", "eval(", "exec("],
        "log_patterns": [r"(?i)(os\.system|eval\(|exec\(|subprocess|/bin/sh|cmd\.exe)"],
        "severity": "critical",
    },
    {
        "id": "INSTALL-001",
        "name": "Webshell Upload",
        "stage": "installation",
        "technique_id": "T1505.003",
        "indicators": ["webshell", ".php upload", "c99", "b374k", "chopper"],
        "log_patterns": [r"(?i)(webshell|c99\.php|b374k|china.chopper|\.php.*upload)"],
        "severity": "critical",
    },
    {
        "id": "C2-001",
        "name": "C2 Beacon",
        "stage": "command_and_control",
        "technique_id": "T1071.001",
        "indicators": ["beacon", "c2", "cobalt strike", "metasploit", "empire", "sliver"],
        "log_patterns": [
            r"(?i)(cobalt.?strike|metasploit|empire.?c2|sliver|cobaltstrike)",
            r"(?i)(beacon|checkin|heartbeat).{0,20}(seconds|interval)",
        ],
        "severity": "critical",
    },
    {
        "id": "C2-002",
        "name": "DNS Tunneling",
        "stage": "command_and_control",
        "technique_id": "T1071.004",
        "indicators": ["dns tunnel", "iodine", "dnscat", "high entropy dns"],
        "log_patterns": [r"(?i)(iodine|dnscat|dns.?tunnel|dns2tcp)"],
        "severity": "high",
    },
    {
        "id": "ACTION-001",
        "name": "Data Exfiltration",
        "stage": "actions_on_objectives",
        "technique_id": "T1041",
        "indicators": ["exfil", "large transfer", "data theft", "upload to external"],
        "log_patterns": [
            r"(?i)(exfil|data.?theft|large.?upload|megabytes.*external)",
        ],
        "severity": "critical",
    },
    {
        "id": "ACTION-002",
        "name": "Ransomware Activity",
        "stage": "actions_on_objectives",
        "technique_id": "T1486",
        "indicators": ["ransomware", "encrypt", "ransom note", ".encrypted", "vssadmin delete"],
        "log_patterns": [
            r"(?i)(ransomware|vssadmin.delete|ransom.note|\.encrypted|\.locked)",
        ],
        "severity": "critical",
    },
    {
        "id": "LATERAL-001",
        "name": "Lateral Movement",
        "stage": "command_and_control",
        "technique_id": "T1021",
        "indicators": ["psexec", "wmi", "lateral", "pass the hash", "mimikatz"],
        "log_patterns": [
            r"(?i)(psexec|mimikatz|pass.the.hash|lateral.movement|wmiexec)",
        ],
        "severity": "critical",
    },
]

_compiled_patterns = [
    (p, [re.compile(pat, re.IGNORECASE) for pat in p["log_patterns"]])
    for p in ATTACK_PATTERNS
]


def analyze_events(events: list[str]) -> dict:
    """Correlate a list of log/event strings into attack pattern matches."""
    matches = defaultdict(list)
    timeline = []

    for event_str in events:
        event_time = datetime.utcnow().isoformat()
        for pattern, compiled_list in _compiled_patterns:
            for regex in compiled_list:
                if regex.search(event_str):
                    matches[pattern["id"]].append({
                        "event": event_str[:300],
                        "timestamp": event_time,
                        "pattern": pattern["name"],
                    })
                    break

    detected = []
    for pat_id, occurrences in matches.items():
        pattern = next(p for p, _ in _compiled_patterns if p["id"] == pat_id)
        detected.append({
            **pattern,
            "occurrences": len(occurrences),
            "samples": occurrences[:3],
        })

    kill_chain_coverage = _build_kill_chain(detected)
    campaign = _correlate_campaign(detected)

    result = {
        "analyzed_events": len(events),
        "detected_patterns": len(detected),
        "kill_chain_coverage": kill_chain_coverage,
        "campaign": campaign,
        "patterns": sorted(detected, key=lambda x: (
            KILL_CHAIN.index(x["stage"]) if x["stage"] in KILL_CHAIN else 99
        )),
        "analyzed_at": datetime.utcnow().isoformat(),
    }

    _persist(result)
    return result


def analyze_text(text: str) -> dict:
    """Analyze free-form text (logs, reports) for attack patterns."""
    lines = text.strip().split("\n")
    return analyze_events(lines)


def _build_kill_chain(patterns: list) -> dict:
    covered = {p["stage"] for p in patterns}
    return {
        stage: {
            "covered": stage in covered,
            "patterns": [p["name"] for p in patterns if p["stage"] == stage],
            "severity": max(
                (p["severity"] for p in patterns if p["stage"] == stage),
                key=lambda s: ["low", "medium", "high", "critical"].index(s),
                default="none",
            ) if stage in covered else "none",
        }
        for stage in KILL_CHAIN
    }


def _correlate_campaign(patterns: list) -> dict:
    if not patterns:
        return {"detected": False}

    stages_covered = len({p["stage"] for p in patterns})
    critical_count = sum(1 for p in patterns if p["severity"] == "critical")
    total_hits = sum(p["occurrences"] for p in patterns)

    if stages_covered >= 4 and critical_count >= 2:
        campaign_type = "APT Campaign"
        confidence = 0.85
    elif stages_covered >= 3:
        campaign_type = "Targeted Attack"
        confidence = 0.65
    elif critical_count >= 1:
        campaign_type = "Opportunistic Attack"
        confidence = 0.5
    else:
        campaign_type = "Reconnaissance / Probing"
        confidence = 0.3

    return {
        "detected": True,
        "type": campaign_type,
        "confidence": confidence,
        "stages_covered": stages_covered,
        "total_indicators": total_hits,
        "critical_patterns": critical_count,
        "mitre_techniques": list({p["technique_id"] for p in patterns}),
        "recommended_response": _response_playbook(campaign_type),
    }


def _response_playbook(campaign_type: str) -> list:
    common = [
        "Isolate affected systems from network",
        "Preserve forensic evidence — capture memory and disk images",
        "Notify incident response team immediately",
    ]
    if "APT" in campaign_type:
        return common + [
            "Engage threat hunting team for lateral movement",
            "Review all privileged account activity for past 90 days",
            "Notify CISO and legal team — potential data breach",
        ]
    if "Targeted" in campaign_type:
        return common + [
            "Block attacker IPs at perimeter firewall",
            "Reset credentials for all affected accounts",
            "Review access logs for data exfiltration indicators",
        ]
    return common + [
        "Apply patches for exploited vulnerabilities",
        "Update WAF rules to block attack signatures",
    ]


def _persist(result: dict) -> None:
    PATTERN_DB.parent.mkdir(parents=True, exist_ok=True)
    history = []
    if PATTERN_DB.exists():
        history = json.loads(PATTERN_DB.read_text())
    history.insert(0, {
        "analyzed_at": result["analyzed_at"],
        "events": result["analyzed_events"],
        "patterns": result["detected_patterns"],
        "campaign": result["campaign"],
    })
    PATTERN_DB.write_text(json.dumps(history[:50], indent=2, default=str))


def get_all_patterns() -> list:
    return ATTACK_PATTERNS


def pattern_history() -> list:
    if PATTERN_DB.exists():
        return json.loads(PATTERN_DB.read_text())
    return []
