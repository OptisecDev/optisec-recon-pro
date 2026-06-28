"""Full MITRE ATT&CK Enterprise Navigator — 14 tactics, 200+ techniques, real-time detection mapping."""
import json
import hashlib
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

DATA_FILE = Path("data/attack_navigator_state.json")

# ── Full ATT&CK Enterprise Matrix ─────────────────────────────────────────────

TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance",       "shortname": "recon",      "color": "#8D6E63"},
    {"id": "TA0042", "name": "Resource Development",  "shortname": "resource",   "color": "#78909C"},
    {"id": "TA0001", "name": "Initial Access",        "shortname": "initial",    "color": "#FF6B6B"},
    {"id": "TA0002", "name": "Execution",             "shortname": "exec",       "color": "#FF8E53"},
    {"id": "TA0003", "name": "Persistence",           "shortname": "persist",    "color": "#FFA726"},
    {"id": "TA0004", "name": "Privilege Escalation",  "shortname": "privesc",    "color": "#FFCA28"},
    {"id": "TA0005", "name": "Defense Evasion",       "shortname": "evasion",    "color": "#D4E157"},
    {"id": "TA0006", "name": "Credential Access",     "shortname": "cred",       "color": "#66BB6A"},
    {"id": "TA0007", "name": "Discovery",             "shortname": "discovery",  "color": "#26C6DA"},
    {"id": "TA0008", "name": "Lateral Movement",      "shortname": "lateral",    "color": "#42A5F5"},
    {"id": "TA0009", "name": "Collection",            "shortname": "collect",    "color": "#7E57C2"},
    {"id": "TA0011", "name": "Command & Control",     "shortname": "c2",         "color": "#EC407A"},
    {"id": "TA0010", "name": "Exfiltration",          "shortname": "exfil",      "color": "#AB47BC"},
    {"id": "TA0040", "name": "Impact",                "shortname": "impact",     "color": "#EF5350"},
]

TECHNIQUES: Dict[str, List[dict]] = {
    "TA0043": [
        {"id": "T1595",     "name": "Active Scanning",              "sub": None,  "severity": "medium", "platforms": ["Network"]},
        {"id": "T1595.001", "name": "Scanning IP Blocks",           "sub": "T1595", "severity": "low",    "platforms": ["Network"]},
        {"id": "T1595.002", "name": "Vulnerability Scanning",       "sub": "T1595", "severity": "high",   "platforms": ["Network"]},
        {"id": "T1595.003", "name": "Wordlist Scanning",            "sub": "T1595", "severity": "medium", "platforms": ["Network"]},
        {"id": "T1592",     "name": "Gather Victim Host Info",      "sub": None,  "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1592.001", "name": "Hardware",                     "sub": "T1592", "severity": "low",    "platforms": ["PRE"]},
        {"id": "T1592.002", "name": "Software",                     "sub": "T1592", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1592.004", "name": "Client Configurations",        "sub": "T1592", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1589",     "name": "Gather Victim Identity Info",  "sub": None,  "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1589.001", "name": "Credentials",                  "sub": "T1589", "severity": "high",   "platforms": ["PRE"]},
        {"id": "T1589.002", "name": "Email Addresses",              "sub": "T1589", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1589.003", "name": "Employee Names",               "sub": "T1589", "severity": "low",    "platforms": ["PRE"]},
        {"id": "T1590",     "name": "Gather Victim Network Info",   "sub": None,  "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1590.001", "name": "Domain Properties",            "sub": "T1590", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1590.004", "name": "Network Topology",             "sub": "T1590", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1591",     "name": "Gather Victim Org Info",       "sub": None,  "severity": "low",    "platforms": ["PRE"]},
        {"id": "T1598",     "name": "Phishing for Information",     "sub": None,  "severity": "high",   "platforms": ["PRE"]},
        {"id": "T1597",     "name": "Search Closed Sources",        "sub": None,  "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1596",     "name": "Search Open Tech Databases",   "sub": None,  "severity": "low",    "platforms": ["PRE"]},
        {"id": "T1593",     "name": "Search Open Websites/Domains", "sub": None,  "severity": "low",    "platforms": ["PRE"]},
    ],
    "TA0042": [
        {"id": "T1583",     "name": "Acquire Infrastructure",       "sub": None,  "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1583.001", "name": "Domains",                      "sub": "T1583", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1583.002", "name": "DNS Server",                   "sub": "T1583", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1583.003", "name": "Virtual Private Server",       "sub": "T1583", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1583.004", "name": "Server",                       "sub": "T1583", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1583.006", "name": "Web Services",                 "sub": "T1583", "severity": "low",    "platforms": ["PRE"]},
        {"id": "T1584",     "name": "Compromise Infrastructure",    "sub": None,  "severity": "high",   "platforms": ["PRE"]},
        {"id": "T1584.001", "name": "Domains",                      "sub": "T1584", "severity": "high",   "platforms": ["PRE"]},
        {"id": "T1584.004", "name": "Server",                       "sub": "T1584", "severity": "high",   "platforms": ["PRE"]},
        {"id": "T1587",     "name": "Develop Capabilities",         "sub": None,  "severity": "high",   "platforms": ["PRE"]},
        {"id": "T1587.001", "name": "Malware",                      "sub": "T1587", "severity": "critical", "platforms": ["PRE"]},
        {"id": "T1587.002", "name": "Code Signing Certs",           "sub": "T1587", "severity": "high",   "platforms": ["PRE"]},
        {"id": "T1587.003", "name": "Digital Certs",                "sub": "T1587", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1587.004", "name": "Exploits",                     "sub": "T1587", "severity": "critical", "platforms": ["PRE"]},
        {"id": "T1588",     "name": "Obtain Capabilities",          "sub": None,  "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1588.001", "name": "Malware",                      "sub": "T1588", "severity": "high",   "platforms": ["PRE"]},
        {"id": "T1588.002", "name": "Tool",                         "sub": "T1588", "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1588.005", "name": "Exploits",                     "sub": "T1588", "severity": "high",   "platforms": ["PRE"]},
        {"id": "T1585",     "name": "Establish Accounts",           "sub": None,  "severity": "medium", "platforms": ["PRE"]},
        {"id": "T1586",     "name": "Compromise Accounts",          "sub": None,  "severity": "high",   "platforms": ["PRE"]},
    ],
    "TA0001": [
        {"id": "T1189", "name": "Drive-by Compromise",              "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1190", "name": "Exploit Public-Facing Application","sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1133", "name": "External Remote Services",         "sub": None, "severity": "high",     "platforms": ["Windows","Linux","Containers"]},
        {"id": "T1200", "name": "Hardware Additions",               "sub": None, "severity": "medium",   "platforms": ["Windows","Linux","macOS"]},
        {"id": "T1566",     "name": "Phishing",                     "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1566.001", "name": "Spearphishing Attachment",     "sub": "T1566", "severity": "high",  "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1566.002", "name": "Spearphishing Link",           "sub": "T1566", "severity": "high",  "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1566.003", "name": "Spearphishing via Service",    "sub": "T1566", "severity": "medium","platforms": ["Windows","macOS","Linux"]},
        {"id": "T1091",     "name": "Replication Through Removable Media","sub": None,"severity": "medium","platforms": ["Windows"]},
        {"id": "T1195",     "name": "Supply Chain Compromise",      "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1195.001", "name": "Compromise SW Supply Chain",   "sub": "T1195","severity": "critical","platforms": ["Windows","macOS","Linux"]},
        {"id": "T1078",     "name": "Valid Accounts",               "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1078.001", "name": "Default Accounts",             "sub": "T1078","severity": "medium", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1078.002", "name": "Domain Accounts",              "sub": "T1078","severity": "high",   "platforms": ["Windows"]},
        {"id": "T1078.004", "name": "Cloud Accounts",               "sub": "T1078","severity": "high",   "platforms": ["Cloud","SaaS"]},
    ],
    "TA0002": [
        {"id": "T1059",     "name": "Command/Script Interpreter",   "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1059.001", "name": "PowerShell",                   "sub": "T1059","severity": "high",   "platforms": ["Windows"]},
        {"id": "T1059.002", "name": "AppleScript",                  "sub": "T1059","severity": "medium", "platforms": ["macOS"]},
        {"id": "T1059.003", "name": "Windows CMD Shell",            "sub": "T1059","severity": "high",   "platforms": ["Windows"]},
        {"id": "T1059.004", "name": "Unix Shell",                   "sub": "T1059","severity": "high",   "platforms": ["macOS","Linux"]},
        {"id": "T1059.005", "name": "VBScript",                     "sub": "T1059","severity": "high",   "platforms": ["Windows"]},
        {"id": "T1059.006", "name": "Python",                       "sub": "T1059","severity": "medium", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1059.007", "name": "JavaScript",                   "sub": "T1059","severity": "high",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1203",     "name": "Exploitation for Execution",   "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1559",     "name": "Inter-Process Communication",  "sub": None, "severity": "medium",   "platforms": ["Windows","macOS"]},
        {"id": "T1106",     "name": "Native API",                   "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1053",     "name": "Scheduled Task/Job",           "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1053.001", "name": "At",                           "sub": "T1053","severity": "medium", "platforms": ["Windows","Linux","macOS"]},
        {"id": "T1053.003", "name": "Cron",                         "sub": "T1053","severity": "high",   "platforms": ["macOS","Linux"]},
        {"id": "T1053.005", "name": "Scheduled Task",               "sub": "T1053","severity": "high",   "platforms": ["Windows"]},
        {"id": "T1569",     "name": "System Services",              "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1204",     "name": "User Execution",               "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1204.001", "name": "Malicious Link",               "sub": "T1204","severity": "high",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1204.002", "name": "Malicious File",               "sub": "T1204","severity": "high",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1047",     "name": "Windows Management Instrumentation","sub": None,"severity": "high", "platforms": ["Windows"]},
    ],
    "TA0003": [
        {"id": "T1098",     "name": "Account Manipulation",         "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1098.001", "name": "Additional Cloud Credentials", "sub": "T1098","severity": "high",   "platforms": ["IaaS","SaaS"]},
        {"id": "T1197",     "name": "BITS Jobs",                    "sub": None, "severity": "medium",   "platforms": ["Windows"]},
        {"id": "T1547",     "name": "Boot/Logon Autostart Execution","sub": None,"severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1547.001", "name": "Registry Run Keys / Startup",  "sub": "T1547","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1547.004", "name": "Winlogon Helper DLL",          "sub": "T1547","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1037",     "name": "Boot/Logon Init Scripts",      "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1176",     "name": "Browser Extensions",           "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1554",     "name": "Compromise Client SW Binary",  "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1136",     "name": "Create Account",               "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1136.001", "name": "Local Account",                "sub": "T1136","severity": "high",  "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1543",     "name": "Create/Modify System Process", "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1543.003", "name": "Windows Service",              "sub": "T1543","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1546",     "name": "Event Triggered Execution",    "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1574",     "name": "Hijack Execution Flow",        "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1574.001", "name": "DLL Search Order Hijacking",   "sub": "T1574","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1525",     "name": "Implant Internal Image",       "sub": None, "severity": "high",     "platforms": ["IaaS","Containers"]},
        {"id": "T1505",     "name": "Server Software Component",    "sub": None, "severity": "critical", "platforms": ["Windows","Linux","macOS","Network"]},
        {"id": "T1505.003", "name": "Web Shell",                    "sub": "T1505","severity": "critical","platforms": ["Windows","Linux","macOS","Network"]},
        {"id": "T1053",     "name": "Scheduled Task/Job",           "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
    ],
    "TA0004": [
        {"id": "T1548",     "name": "Abuse Elevation Control",      "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1548.002", "name": "Bypass UAC",                   "sub": "T1548","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1548.003", "name": "Sudo and Sudo Caching",        "sub": "T1548","severity": "high",  "platforms": ["macOS","Linux"]},
        {"id": "T1134",     "name": "Access Token Manipulation",    "sub": None, "severity": "high",     "platforms": ["Windows"]},
        {"id": "T1134.001", "name": "Token Impersonation/Theft",    "sub": "T1134","severity": "critical","platforms": ["Windows"]},
        {"id": "T1547",     "name": "Boot/Logon Autostart Execution","sub": None,"severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1068",     "name": "Exploitation for Privilege Esc","sub": None,"severity": "critical", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1574",     "name": "Hijack Execution Flow",        "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1055",     "name": "Process Injection",            "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1055.001", "name": "DLL Injection",                "sub": "T1055","severity": "critical","platforms": ["Windows"]},
        {"id": "T1055.002", "name": "Portable Exec Injection",      "sub": "T1055","severity": "critical","platforms": ["Windows"]},
        {"id": "T1055.012", "name": "Process Hollowing",            "sub": "T1055","severity": "critical","platforms": ["Windows"]},
        {"id": "T1053",     "name": "Scheduled Task/Job",           "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1078",     "name": "Valid Accounts",               "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
    ],
    "TA0005": [
        {"id": "T1134",     "name": "Access Token Manipulation",    "sub": None, "severity": "high",     "platforms": ["Windows"]},
        {"id": "T1197",     "name": "BITS Jobs",                    "sub": None, "severity": "medium",   "platforms": ["Windows"]},
        {"id": "T1622",     "name": "Debugger Evasion",             "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1140",     "name": "Deobfuscate/Decode Files",     "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1006",     "name": "Direct Volume Access",         "sub": None, "severity": "high",     "platforms": ["Windows"]},
        {"id": "T1484",     "name": "Domain/Group Policy Modify",   "sub": None, "severity": "high",     "platforms": ["Windows","Azure AD"]},
        {"id": "T1480",     "name": "Execution Guardrails",         "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1211",     "name": "Exploitation for Defense Evasion","sub": None,"severity": "high",   "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1222",     "name": "File/Directory Permissions Mod","sub": None,"severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1564",     "name": "Hide Artifacts",               "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1564.001", "name": "Hidden Files and Directories", "sub": "T1564","severity": "medium", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1574",     "name": "Hijack Execution Flow",        "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1562",     "name": "Impair Defenses",              "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1562.001", "name": "Disable/Modify Tools",         "sub": "T1562","severity": "high",  "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1562.004", "name": "Disable/Modify Firewall",      "sub": "T1562","severity": "high",  "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1070",     "name": "Indicator Removal",            "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1070.001", "name": "Clear Windows Event Logs",     "sub": "T1070","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1070.004", "name": "File Deletion",                "sub": "T1070","severity": "medium", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1036",     "name": "Masquerading",                 "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1556",     "name": "Modify Auth Process",          "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","IaaS"]},
        {"id": "T1578",     "name": "Modify Cloud Compute Infra",   "sub": None, "severity": "high",     "platforms": ["IaaS"]},
        {"id": "T1112",     "name": "Modify Registry",              "sub": None, "severity": "medium",   "platforms": ["Windows"]},
        {"id": "T1027",     "name": "Obfuscated Files/Info",        "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1027.002", "name": "Software Packing",             "sub": "T1027","severity": "high",  "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1055",     "name": "Process Injection",            "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1207",     "name": "Rogue Domain Controller",      "sub": None, "severity": "high",     "platforms": ["Windows"]},
        {"id": "T1014",     "name": "Rootkit",                      "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1218",     "name": "Signed Binary Proxy Execution","sub": None, "severity": "high",     "platforms": ["Windows"]},
        {"id": "T1218.011", "name": "Rundll32",                     "sub": "T1218","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1553",     "name": "Subvert Trust Controls",       "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1221",     "name": "Template Injection",           "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1205",     "name": "Traffic Signaling",            "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1497",     "name": "Virtualization Sandbox Evasion","sub": None,"severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
    ],
    "TA0006": [
        {"id": "T1110",     "name": "Brute Force",                  "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1110.001", "name": "Password Guessing",            "sub": "T1110","severity": "high",  "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1110.002", "name": "Password Cracking",            "sub": "T1110","severity": "high",  "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1110.003", "name": "Password Spraying",            "sub": "T1110","severity": "high",  "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1110.004", "name": "Credential Stuffing",          "sub": "T1110","severity": "high",  "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1555",     "name": "Credentials from Password Stores","sub": None,"severity": "critical","platforms": ["Windows","macOS","Linux"]},
        {"id": "T1555.001", "name": "Keychain",                     "sub": "T1555","severity": "critical","platforms": ["macOS"]},
        {"id": "T1555.003", "name": "Credentials from Web Browsers","sub": "T1555","severity": "critical","platforms": ["Windows","macOS","Linux"]},
        {"id": "T1212",     "name": "Exploitation for Credential Access","sub": None,"severity": "critical","platforms": ["Windows","macOS","Linux"]},
        {"id": "T1187",     "name": "Forced Authentication",        "sub": None, "severity": "high",     "platforms": ["Windows"]},
        {"id": "T1056",     "name": "Input Capture",                "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1056.001", "name": "Keylogging",                   "sub": "T1056","severity": "critical","platforms": ["Windows","macOS","Linux"]},
        {"id": "T1056.003", "name": "Web Portal Capture",           "sub": "T1056","severity": "high",  "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1557",     "name": "Adversary-in-the-Middle",      "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1557.001", "name": "LLMNR/NBT-NS Poisoning",       "sub": "T1557","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1040",     "name": "Network Sniffing",             "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1003",     "name": "OS Credential Dumping",        "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1003.001", "name": "LSASS Memory",                 "sub": "T1003","severity": "critical","platforms": ["Windows"]},
        {"id": "T1003.003", "name": "NTDS",                         "sub": "T1003","severity": "critical","platforms": ["Windows"]},
        {"id": "T1528",     "name": "Steal App Access Token",       "sub": None, "severity": "critical", "platforms": ["SaaS","Cloud"]},
        {"id": "T1539",     "name": "Steal Web Session Cookie",     "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","SaaS"]},
        {"id": "T1552",     "name": "Unsecured Credentials",        "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1552.001", "name": "Credentials in Files",         "sub": "T1552","severity": "high",  "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1552.004", "name": "Private Keys",                 "sub": "T1552","severity": "critical","platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1606",     "name": "Forge Web Credentials",        "sub": None, "severity": "critical", "platforms": ["SaaS","Cloud","IaaS"]},
    ],
    "TA0007": [
        {"id": "T1087",     "name": "Account Discovery",            "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1087.001", "name": "Local Account",                "sub": "T1087","severity": "medium", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1087.002", "name": "Domain Account",               "sub": "T1087","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1010",     "name": "Application Window Discovery", "sub": None, "severity": "low",      "platforms": ["Windows","macOS"]},
        {"id": "T1217",     "name": "Browser Bookmark Discovery",   "sub": None, "severity": "low",      "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1580",     "name": "Cloud Infrastructure Discovery","sub": None,"severity": "medium",   "platforms": ["IaaS","Azure AD"]},
        {"id": "T1538",     "name": "Cloud Service Dashboard",      "sub": None, "severity": "medium",   "platforms": ["Azure AD","SaaS","IaaS","Office 365","Google Workspace"]},
        {"id": "T1526",     "name": "Cloud Service Discovery",      "sub": None, "severity": "medium",   "platforms": ["Azure AD","SaaS","IaaS","Office 365","Google Workspace"]},
        {"id": "T1482",     "name": "Domain Trust Discovery",       "sub": None, "severity": "high",     "platforms": ["Windows"]},
        {"id": "T1083",     "name": "File/Directory Discovery",     "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1615",     "name": "Group Policy Discovery",       "sub": None, "severity": "medium",   "platforms": ["Windows"]},
        {"id": "T1046",     "name": "Network Service Discovery",    "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Containers"]},
        {"id": "T1135",     "name": "Network Share Discovery",      "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1040",     "name": "Network Sniffing",             "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1201",     "name": "Password Policy Discovery",    "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","IaaS"]},
        {"id": "T1120",     "name": "Peripheral Device Discovery",  "sub": None, "severity": "low",      "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1069",     "name": "Permission Group Discovery",   "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1057",     "name": "Process Discovery",            "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1012",     "name": "Query Registry",               "sub": None, "severity": "medium",   "platforms": ["Windows"]},
        {"id": "T1018",     "name": "Remote System Discovery",      "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1518",     "name": "Software Discovery",           "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1082",     "name": "System Information Discovery", "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","IaaS"]},
        {"id": "T1614",     "name": "System Location Discovery",    "sub": None, "severity": "low",      "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1016",     "name": "System Network Config Discovery","sub": None,"severity": "medium",  "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1049",     "name": "System Network Connections",   "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1033",     "name": "System Owner/User Discovery",  "sub": None, "severity": "low",      "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1007",     "name": "System Service Discovery",     "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
    ],
    "TA0008": [
        {"id": "T1210", "name": "Exploitation of Remote Services",  "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1534", "name": "Internal Spearphishing",           "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","SaaS","Office 365"]},
        {"id": "T1570", "name": "Lateral Tool Transfer",            "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1563", "name": "Remote Service Session Hijacking", "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1021",     "name": "Remote Services",              "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1021.001", "name": "Remote Desktop Protocol",      "sub": "T1021","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1021.002", "name": "SMB/Windows Admin Shares",     "sub": "T1021","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1021.004", "name": "SSH",                          "sub": "T1021","severity": "high",  "platforms": ["macOS","Linux"]},
        {"id": "T1021.006", "name": "Windows Remote Management",    "sub": "T1021","severity": "high",  "platforms": ["Windows"]},
        {"id": "T1091",     "name": "Replication via Removable Media","sub": None,"severity": "medium",  "platforms": ["Windows"]},
        {"id": "T1072",     "name": "Software Deployment Tools",    "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1080",     "name": "Taint Shared Content",         "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Office 365"]},
        {"id": "T1550",     "name": "Use Alternate Auth Material",  "sub": None, "severity": "high",     "platforms": ["Windows","macOS","SaaS","Google Workspace"]},
        {"id": "T1550.002", "name": "Pass the Hash",                "sub": "T1550","severity": "critical","platforms": ["Windows"]},
        {"id": "T1550.003", "name": "Pass the Ticket",              "sub": "T1550","severity": "critical","platforms": ["Windows"]},
    ],
    "TA0009": [
        {"id": "T1560",     "name": "Archive Collected Data",       "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1123",     "name": "Audio Capture",                "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1119",     "name": "Automated Collection",         "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1115",     "name": "Clipboard Data",               "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1530",     "name": "Data from Cloud Storage",      "sub": None, "severity": "high",     "platforms": ["IaaS","SaaS"]},
        {"id": "T1602",     "name": "Data from Config Repository",  "sub": None, "severity": "high",     "platforms": ["Network"]},
        {"id": "T1213",     "name": "Data from Info Repositories",  "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","SaaS","Office 365"]},
        {"id": "T1005",     "name": "Data from Local System",       "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network","Cloud"]},
        {"id": "T1039",     "name": "Data from Network Shared Drive","sub": None,"severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1025",     "name": "Data from Removable Media",    "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1074",     "name": "Data Staged",                  "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1114",     "name": "Email Collection",             "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Office 365","Google Workspace"]},
        {"id": "T1056",     "name": "Input Capture",                "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1185",     "name": "Browser Session Hijacking",    "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1113",     "name": "Screen Capture",               "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1125",     "name": "Video Capture",                "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux"]},
    ],
    "TA0011": [
        {"id": "T1071",     "name": "App Layer Protocol",           "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1071.001", "name": "Web Protocols",                "sub": "T1071","severity": "high",  "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1071.004", "name": "DNS",                          "sub": "T1071","severity": "high",  "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1092",     "name": "Communication via Removable Media","sub": None,"severity": "medium","platforms": ["Windows","macOS","Linux"]},
        {"id": "T1132",     "name": "Data Encoding",                "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1001",     "name": "Data Obfuscation",             "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1568",     "name": "Dynamic Resolution",           "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1568.002", "name": "Domain Generation Algorithms", "sub": "T1568","severity": "high",  "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1573",     "name": "Encrypted Channel",            "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1573.001", "name": "Symmetric Cryptography",       "sub": "T1573","severity": "high",  "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1573.002", "name": "Asymmetric Cryptography",      "sub": "T1573","severity": "high",  "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1008",     "name": "Fallback Channels",            "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1105",     "name": "Ingress Tool Transfer",        "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1104",     "name": "Multi-Stage Channels",         "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1095",     "name": "Non-App Layer Protocol",       "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1571",     "name": "Non-Standard Port",            "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1572",     "name": "Protocol Tunneling",           "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1090",     "name": "Proxy",                        "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1090.001", "name": "Internal Proxy",               "sub": "T1090","severity": "medium", "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1090.002", "name": "External Proxy",               "sub": "T1090","severity": "high",  "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1090.003", "name": "Multi-hop Proxy",              "sub": "T1090","severity": "high",  "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1219",     "name": "Remote Access Software",       "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1205",     "name": "Traffic Signaling",            "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1102",     "name": "Web Service",                  "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Network"]},
    ],
    "TA0010": [
        {"id": "T1020",     "name": "Automated Exfiltration",       "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","Network","Cloud"]},
        {"id": "T1030",     "name": "Data Transfer Size Limits",    "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Network","Cloud"]},
        {"id": "T1048",     "name": "Exfil Over Alt Protocol",      "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network","Cloud"]},
        {"id": "T1048.001", "name": "Exfil Over Sym Enc Non-C2",    "sub": "T1048","severity": "high",  "platforms": ["Windows","macOS","Linux","Network","Cloud"]},
        {"id": "T1048.003", "name": "Exfil Over Unencrypted Protocol","sub": "T1048","severity": "high", "platforms": ["Windows","macOS","Linux","Network","Cloud"]},
        {"id": "T1041",     "name": "Exfil Over C2 Channel",        "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","Network","Cloud"]},
        {"id": "T1011",     "name": "Exfil Over Other Network Medium","sub": None,"severity": "high",    "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1052",     "name": "Exfil Over Physical Medium",   "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1567",     "name": "Exfil Over Web Service",       "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","SaaS"]},
        {"id": "T1567.002", "name": "Exfil to Cloud Storage",       "sub": "T1567","severity": "high",  "platforms": ["Windows","macOS","Linux","SaaS"]},
        {"id": "T1029",     "name": "Scheduled Transfer",           "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","Network","Cloud"]},
        {"id": "T1537",     "name": "Transfer Data to Cloud Account","sub": None,"severity": "high",     "platforms": ["IaaS","SaaS"]},
    ],
    "TA0040": [
        {"id": "T1531", "name": "Account Access Removal",           "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Cloud"]},
        {"id": "T1485", "name": "Data Destruction",                 "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","IaaS"]},
        {"id": "T1486", "name": "Data Encrypted for Impact",        "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","IaaS"]},
        {"id": "T1565", "name": "Data Manipulation",                "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","IaaS","SaaS"]},
        {"id": "T1565.001", "name": "Stored Data Manipulation",     "sub": "T1565","severity": "high",  "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1565.002", "name": "Transmitted Data Manipulation","sub": "T1565","severity": "high",  "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1491", "name": "Defacement",                       "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","IaaS"]},
        {"id": "T1491.001", "name": "Internal Defacement",          "sub": "T1491","severity": "medium", "platforms": ["Windows","macOS","Linux"]},
        {"id": "T1491.002", "name": "External Defacement",          "sub": "T1491","severity": "high",  "platforms": ["Windows","macOS","Linux","IaaS"]},
        {"id": "T1561", "name": "Disk Wipe",                        "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1499", "name": "Endpoint Denial of Service",       "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","IaaS","Network"]},
        {"id": "T1495", "name": "Firmware Corruption",              "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1490", "name": "Inhibit System Recovery",          "sub": None, "severity": "critical", "platforms": ["Windows","macOS","Linux","IaaS","Network"]},
        {"id": "T1498", "name": "Network Denial of Service",        "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","IaaS","Network"]},
        {"id": "T1496", "name": "Resource Hijacking",               "sub": None, "severity": "medium",   "platforms": ["Windows","macOS","Linux","IaaS","Containers"]},
        {"id": "T1489", "name": "Service Stop",                     "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
        {"id": "T1529", "name": "System Shutdown/Reboot",           "sub": None, "severity": "high",     "platforms": ["Windows","macOS","Linux","Network"]},
    ],
}

# ── APT Group Profiles ─────────────────────────────────────────────────────────

APT_GROUPS = [
    {
        "id": "G0007", "name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm"],
        "origin": "Russia", "sponsor": "GRU", "active_since": "2004",
        "target_sectors": ["Government", "Military", "Defense", "Aerospace", "Media"],
        "techniques": ["T1566.001","T1566.002","T1059.001","T1055","T1027","T1083","T1071.001","T1041"],
        "malware": ["X-Agent", "Sofacy", "Komplex", "GAMEFISH"],
        "risk_level": "critical",
        "description": "Russian GRU Unit 26165 — notorious for election interference and NATO espionage.",
    },
    {
        "id": "G0016", "name": "APT29", "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM"],
        "origin": "Russia", "sponsor": "SVR", "active_since": "2008",
        "target_sectors": ["Government", "Think Tanks", "Healthcare", "Energy", "Technology"],
        "techniques": ["T1195.001","T1078","T1552","T1573.002","T1090.003","T1027","T1105"],
        "malware": ["SUNBURST", "TEARDROP", "MiniDuke", "CosmicDuke"],
        "risk_level": "critical",
        "description": "Russian SVR — responsible for SolarWinds supply chain attack targeting 18,000+ organizations.",
    },
    {
        "id": "G0096", "name": "APT41", "aliases": ["Winnti", "Double Dragon", "Barium"],
        "origin": "China", "sponsor": "MSS", "active_since": "2012",
        "target_sectors": ["Healthcare", "Technology", "Telecom", "Finance", "Gaming"],
        "techniques": ["T1195","T1190","T1133","T1059.003","T1055.001","T1486","T1496"],
        "malware": ["PlugX", "ShadowPad", "Winnti", "HIGHNOON"],
        "risk_level": "critical",
        "description": "Chinese MSS — uniquely combines state-sponsored espionage with financially motivated cybercrime.",
    },
    {
        "id": "G0004", "name": "Lazarus Group", "aliases": ["HIDDEN COBRA", "Guardians of Peace"],
        "origin": "North Korea", "sponsor": "RGB", "active_since": "2009",
        "target_sectors": ["Financial", "Cryptocurrency", "Defense", "Energy", "Media"],
        "techniques": ["T1566","T1059","T1486","T1041","T1105","T1003"],
        "malware": ["ELECTRICFISH", "HOPLIGHT", "WannaCry", "NotPetya"],
        "risk_level": "critical",
        "description": "North Korean RGB Unit 180 — responsible for $1.7B+ in cryptocurrency theft and Sony Pictures hack.",
    },
    {
        "id": "G0064", "name": "APT33", "aliases": ["Elfin", "MAGNALLIUM", "Refined Kitten"],
        "origin": "Iran", "sponsor": "IRGC", "active_since": "2013",
        "target_sectors": ["Aerospace", "Energy", "Petrochemical", "Government"],
        "techniques": ["T1566.001","T1078","T1059.001","T1053.005","T1070","T1041"],
        "malware": ["DROPSHOT", "SHAPESHIFT", "TURNEDUP", "NANOCORE"],
        "risk_level": "high",
        "description": "Iranian IRGC — focuses on industrial sabotage in aviation and energy sectors.",
    },
    {
        "id": "G0059", "name": "Magic Hound", "aliases": ["APT35", "Charming Kitten", "TA453"],
        "origin": "Iran", "sponsor": "IRGC", "active_since": "2014",
        "target_sectors": ["Academic", "Journalist", "Human Rights", "Government", "Defense"],
        "techniques": ["T1566.002","T1598","T1589.002","T1539","T1185"],
        "malware": ["POWERSTATS", "CHAINSHOT", "BellaCPP"],
        "risk_level": "high",
        "description": "Iranian intelligence — known for sophisticated social engineering and credential phishing.",
    },
    {
        "id": "G0125", "name": "HAFNIUM", "aliases": [],
        "origin": "China", "sponsor": "MSS", "active_since": "2021",
        "target_sectors": ["Research", "Law Firms", "Higher Education", "Defense", "NGOs"],
        "techniques": ["T1190","T1505.003","T1003.001","T1560","T1041"],
        "malware": ["China Chopper", "ASPXSPY", "ProxyLogon"],
        "risk_level": "critical",
        "description": "Chinese MSS — exploited four zero-days in Microsoft Exchange (ProxyLogon) affecting 250,000+ servers.",
    },
    {
        "id": "G0010", "name": "Turla", "aliases": ["Snake", "Uroboros", "Waterbug"],
        "origin": "Russia", "sponsor": "FSB", "active_since": "1996",
        "target_sectors": ["Government", "Military", "Embassies", "Education", "Research"],
        "techniques": ["T1190","T1090","T1572","T1071","T1027","T1014"],
        "malware": ["Snake", "Carbon", "Mosquito", "Kazuar"],
        "risk_level": "critical",
        "description": "Russian FSB Center 16 — one of the oldest and most sophisticated APT groups, active since 1996.",
    },
]

# ── IOC Indicator Types ────────────────────────────────────────────────────────

IOC_TYPES = [
    "ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "hash_sha512",
    "email", "user_agent", "mutex", "registry_key", "file_path", "file_name",
    "cve", "asn", "cidr", "bitcoin_address", "mac_address", "ja3_hash",
    "yara_rule", "ssdeep", "imphash", "tlsh", "certificate_sha1",
    "process_name", "service_name", "scheduled_task", "network_share",
    "dns_query", "http_method", "http_header", "cookie_value",
    "uri_parameter", "email_subject", "email_attachment", "email_sender",
    "phone_number", "social_media_handle", "username", "password_hash",
    "api_key", "jwt_token", "tls_fingerprint", "port", "protocol",
    "malware_family", "campaign_name", "threat_actor",
]


def _load_state() -> dict:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            pass
    return {"detections": [], "custom_layers": [], "ioc_hits": []}


def _save_state(state: dict) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(state, indent=2, default=str))


def get_full_matrix() -> dict:
    """Return the complete ATT&CK matrix structure."""
    matrix = []
    total_techniques = 0
    for tactic in TACTICS:
        tac_id = tactic["id"]
        techs = TECHNIQUES.get(tac_id, [])
        total_techniques += len(techs)
        matrix.append({
            **tactic,
            "techniques": techs,
            "technique_count": len(techs),
        })
    return {
        "tactics": matrix,
        "total_techniques": total_techniques,
        "total_tactics": len(TACTICS),
    }


def get_apt_profiles() -> List[dict]:
    return APT_GROUPS


def get_ioc_types() -> List[str]:
    return IOC_TYPES


def detect_techniques_in_iocs(ioc_list: List[dict]) -> dict:
    """Map a list of IOCs to likely MITRE techniques."""
    hits: Dict[str, dict] = {}
    for ioc in ioc_list:
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")

        mappings = _ioc_to_technique_map(ioc_type, value)
        for tech_id, tactic_id in mappings:
            if tech_id not in hits:
                tech_info = _find_technique(tech_id)
                hits[tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": tech_info.get("name", tech_id),
                    "tactic_id": tactic_id,
                    "ioc_count": 0,
                    "iocs": [],
                }
            hits[tech_id]["ioc_count"] += 1
            hits[tech_id]["iocs"].append({"type": ioc_type, "value": value[:80]})

    return {
        "technique_hits": list(hits.values()),
        "total_hits": len(hits),
        "iocs_processed": len(ioc_list),
    }


def _ioc_to_technique_map(ioc_type: str, value: str) -> List[tuple]:
    mapping = {
        "ip":              [("T1071", "TA0011"), ("T1090", "TA0011")],
        "domain":          [("T1568.002", "TA0011"), ("T1071.001", "TA0011")],
        "url":             [("T1566.002", "TA0001"), ("T1071.001", "TA0011")],
        "hash_md5":        [("T1027", "TA0005"), ("T1587.001", "TA0042")],
        "hash_sha256":     [("T1027", "TA0005"), ("T1587.001", "TA0042")],
        "email":           [("T1566", "TA0001"), ("T1589.002", "TA0043")],
        "user_agent":      [("T1071.001", "TA0011"), ("T1036", "TA0005")],
        "mutex":           [("T1480", "TA0005"), ("T1027", "TA0005")],
        "registry_key":    [("T1547.001", "TA0003"), ("T1112", "TA0005")],
        "cve":             [("T1190", "TA0001"), ("T1211", "TA0005")],
        "bitcoin_address": [("T1486", "TA0040"), ("T1020", "TA0010")],
        "ja3_hash":        [("T1573", "TA0011"), ("T1071", "TA0011")],
        "malware_family":  [("T1587.001", "TA0042"), ("T1027", "TA0005")],
        "certificate_sha1":[("T1553", "TA0005"), ("T1573.002", "TA0011")],
        "dns_query":       [("T1071.004", "TA0011"), ("T1568", "TA0011")],
        "process_name":    [("T1055", "TA0004"), ("T1059", "TA0002")],
    }
    return mapping.get(ioc_type, [("T1027", "TA0005")])


def _find_technique(tech_id: str) -> dict:
    for techs in TECHNIQUES.values():
        for t in techs:
            if t["id"] == tech_id:
                return t
    return {"name": tech_id}


def add_detection(technique_id: str, confidence: int, source: str, details: str = "") -> dict:
    state = _load_state()
    detection = {
        "id": hashlib.md5(f"{technique_id}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:8],
        "technique_id": technique_id,
        "technique_name": _find_technique(technique_id).get("name", technique_id),
        "confidence": min(100, max(0, confidence)),
        "source": source,
        "details": details,
        "timestamp": datetime.utcnow().isoformat(),
    }
    state["detections"].insert(0, detection)
    state["detections"] = state["detections"][:500]
    _save_state(state)
    return detection


def get_detections(limit: int = 50) -> List[dict]:
    return _load_state()["detections"][:limit]


def get_matrix_coverage(detections: List[dict]) -> dict:
    """Compute which tactics/techniques have been detected."""
    detected_ids = {d["technique_id"] for d in detections}
    coverage = {}
    for tac in TACTICS:
        techs = TECHNIQUES.get(tac["id"], [])
        covered = [t for t in techs if t["id"] in detected_ids]
        coverage[tac["id"]] = {
            "tactic_name": tac["name"],
            "total": len(techs),
            "covered": len(covered),
            "pct": round(len(covered) / len(techs) * 100, 1) if techs else 0,
        }
    return coverage
