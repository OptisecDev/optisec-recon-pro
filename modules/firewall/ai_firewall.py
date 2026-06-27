"""AI Firewall — Deep Packet Inspection + ML-based anomaly detection."""

import re
import math
import asyncio
from datetime import datetime
from collections import defaultdict
from urllib.parse import unquote, urlparse


# ── Severity weights (0-100 risk points per hit) ──────────────────────────────

_SEVERITY_SCORE = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 5}


# ── Signature Database ────────────────────────────────────────────────────────

SIGNATURES = [

    # ── SQL INJECTION (30 rules) ──────────────────────────────────────────────

    {
        "id": "SQL-001",
        "name": "UNION-Based SQL Injection",
        "pattern": r"(?i)\bunion\b[\s/\*]+(?:all\s+)?select\b",
        "severity": "CRITICAL",
        "category": "sqli",
        "description": "UNION SELECT attack extracts data from other tables by combining result sets.",
        "recommendation": "Use parameterized queries. Never concatenate user input into SQL strings.",
    },
    {
        "id": "SQL-002",
        "name": "Boolean-Based Blind SQL Injection",
        "pattern": r"(?i)(\bor\b\s+[\d'\"]+\s*=\s*[\d'\"]+|\band\b\s+[\d'\"]+\s*=\s*[\d'\"]+|\bor\b\s+\btrue\b|\band\b\s+\bfalse\b)",
        "severity": "CRITICAL",
        "category": "sqli",
        "description": "Boolean-based blind SQLi uses TRUE/FALSE conditions to infer database content byte-by-byte.",
        "recommendation": "Use ORM or prepared statements. Implement strict type validation on all query parameters.",
    },
    {
        "id": "SQL-003",
        "name": "Time-Based Blind SQL Injection",
        "pattern": r"(?i)(\bsleep\s*\(|\bwaitfor\s+delay\b|\bbenchmark\s*\(|\bpg_sleep\s*\()",
        "severity": "CRITICAL",
        "category": "sqli",
        "description": "Time-based blind SQLi causes intentional database delays to infer data without visible output.",
        "recommendation": "Use parameterized queries. Monitor slow query logs. Set statement_timeout in PostgreSQL.",
    },
    {
        "id": "SQL-004",
        "name": "Destructive SQL Statement",
        "pattern": r"(?i)\b(drop\s+table|drop\s+database|truncate\s+table|delete\s+from\s+\w+\s+where\s+1\s*=\s*1)\b",
        "severity": "CRITICAL",
        "category": "sqli",
        "description": "Destructive SQL commands can wipe entire tables or databases in a single injection.",
        "recommendation": "Use least-privilege DB accounts. Never allow DDL via user input. Enable bin-log for recovery.",
    },
    {
        "id": "SQL-005",
        "name": "Stacked Query Injection",
        "pattern": r"(?i);\s*(select|insert|update|delete|drop|exec|execute|create|alter)\b",
        "severity": "CRITICAL",
        "category": "sqli",
        "description": "Stacked queries execute multiple SQL statements in a single injection, enabling arbitrary DML/DDL.",
        "recommendation": "Use single-statement prepared statements. Disable stacked queries in the DB driver.",
    },
    {
        "id": "SQL-006",
        "name": "System Procedure Execution (xp_cmdshell)",
        "pattern": r"(?i)\b(xp_cmdshell|sp_executesql|sp_oacreate|exec\s*\(|execute\s*\()\b",
        "severity": "CRITICAL",
        "category": "sqli",
        "description": "xp_cmdshell and exec() allow OS command execution directly from SQL Server context.",
        "recommendation": "Disable xp_cmdshell in SQL Server. Use stored procedures with least privilege.",
    },
    {
        "id": "SQL-007",
        "name": "Error-Based SQL Injection",
        "pattern": r"(?i)(extractvalue\s*\(|updatexml\s*\(|exp\s*\(\s*~|floor\s*\(\s*rand\s*\()",
        "severity": "CRITICAL",
        "category": "sqli",
        "description": "Error-based SQLi exploits verbose DB error messages to leak data in the response.",
        "recommendation": "Suppress detailed DB errors in production. Use generic error pages. Log errors server-side.",
    },
    {
        "id": "SQL-008",
        "name": "SQL Comment Authentication Bypass",
        "pattern": r"(?i)('|\")\s*(--|#|/\*|;--)",
        "severity": "HIGH",
        "category": "sqli",
        "description": "SQL comment sequences truncate WHERE conditions to bypass authentication checks.",
        "recommendation": "Escape all SQL metacharacters. Use prepared statements for authentication queries.",
    },
    {
        "id": "SQL-009",
        "name": "SELECT Data Extraction",
        "pattern": r"(?i)\bselect\b.{0,50}\bfrom\b",
        "severity": "HIGH",
        "category": "sqli",
        "description": "SELECT...FROM in user input indicates a data extraction attempt via SQL injection.",
        "recommendation": "Whitelist allowed input characters. Use ORM with parameterized queries at all access points.",
    },
    {
        "id": "SQL-010",
        "name": "INSERT/UPDATE Record Modification",
        "pattern": r"(?i)\b(insert\s+into\s+\w+\s*\(|update\s+\w+\s+set\s+\w+\s*=)\b",
        "severity": "HIGH",
        "category": "sqli",
        "description": "Injected INSERT/UPDATE statements can modify database records or create admin accounts.",
        "recommendation": "Use parameterized queries for all write operations. Implement input length limits.",
    },
    {
        "id": "SQL-011",
        "name": "Information Schema Enumeration",
        "pattern": r"(?i)(information_schema\.|sys\.tables|sys\.columns|pg_catalog\.|mysql\.user)",
        "severity": "HIGH",
        "category": "sqli",
        "description": "Attackers query information_schema to enumerate all tables, columns, and DB structure.",
        "recommendation": "Restrict DB user's access to information_schema. Parameterize all queries.",
    },
    {
        "id": "SQL-012",
        "name": "ORDER BY Column Enumeration",
        "pattern": r"(?i)\border\s+by\s+\d+\b",
        "severity": "HIGH",
        "category": "sqli",
        "description": "ORDER BY with numeric column index enumerates the number of columns for UNION attacks.",
        "recommendation": "Whitelist sort columns server-side. Never pass ORDER BY values directly from user input.",
    },
    {
        "id": "SQL-013",
        "name": "HAVING Clause Injection",
        "pattern": r"(?i)\bhaving\s+\d+\s*=\s*\d+",
        "severity": "HIGH",
        "category": "sqli",
        "description": "HAVING clause injection enables error-based and aggregation-based data extraction.",
        "recommendation": "Use parameterized queries. Never construct HAVING clauses from user input.",
    },
    {
        "id": "SQL-014",
        "name": "Hex Encoding Evasion",
        "pattern": r"(?i)0x[0-9a-f]{6,}",
        "severity": "HIGH",
        "category": "sqli",
        "description": "Hex-encoded payloads bypass string-based WAF rules in SQL injection attacks.",
        "recommendation": "Decode and inspect all encoded input layers before processing. Use parameterized queries.",
    },
    {
        "id": "SQL-015",
        "name": "CHAR() Function Obfuscation",
        "pattern": r"(?i)\bchar\s*\(\s*\d+",
        "severity": "MEDIUM",
        "category": "sqli",
        "description": "CHAR() function concatenation builds SQL keywords character-by-character to evade filters.",
        "recommendation": "Apply deep input validation. Use parameterized queries that are immune to this technique.",
    },
    {
        "id": "SQL-016",
        "name": "INTO OUTFILE Webshell Upload",
        "pattern": r"(?i)\binto\s+(outfile|dumpfile)\b",
        "severity": "CRITICAL",
        "category": "sqli",
        "description": "INTO OUTFILE writes query results to server filesystem — the classic webshell upload vector.",
        "recommendation": "Remove FILE privilege from DB user. Ensure web directory is not writable by DB process.",
    },
    {
        "id": "SQL-017",
        "name": "LOAD DATA INFILE Read",
        "pattern": r"(?i)\bload\s+data\s+(local\s+)?infile\b",
        "severity": "CRITICAL",
        "category": "sqli",
        "description": "LOAD DATA INFILE reads arbitrary server files into the database — a data exfiltration path.",
        "recommendation": "Disable LOAD DATA on DB server. Revoke FILE privilege. Apply parameterized queries.",
    },
    {
        "id": "SQL-018",
        "name": "MySQL Global Variable Fingerprint",
        "pattern": r"(?i)(@@version\b|@@global\.|@@datadir|version\s*\(\s*\))",
        "severity": "MEDIUM",
        "category": "sqli",
        "description": "Attackers read MySQL global variables to fingerprint DB version for targeted exploitation.",
        "recommendation": "Parameterize all queries. Suppress DB version information in error messages.",
    },
    {
        "id": "SQL-019",
        "name": "DB Identity Function Probe",
        "pattern": r"(?i)(database\s*\(\s*\)|schema\s*\(\s*\)|current_user\s*\(\s*\)|user\s*\(\s*\))",
        "severity": "MEDIUM",
        "category": "sqli",
        "description": "DB identity functions leak current database name, schema, and user context to attacker.",
        "recommendation": "Use parameterized queries. Restrict error verbosity. Apply least privilege.",
    },
    {
        "id": "SQL-020",
        "name": "SUBSTRING Blind Character Extraction",
        "pattern": r"(?i)\b(substring|substr|mid)\s*\([^)]+,\s*\d+\s*,\s*\d+",
        "severity": "HIGH",
        "category": "sqli",
        "description": "SUBSTRING() in injection context extracts data character-by-character in blind SQLi.",
        "recommendation": "Use parameterized queries. Implement query result size limits and query monitoring.",
    },
    {
        "id": "SQL-021",
        "name": "ASCII/ORD Character Code Extraction",
        "pattern": r"(?i)\b(ascii|ord)\s*\(\s*(substring|substr|mid|char)",
        "severity": "HIGH",
        "category": "sqli",
        "description": "ASCII/ORD wrapping converts characters to numeric codes for boolean blind extraction.",
        "recommendation": "Use parameterized queries. Monitor for patterns of repeated requests with numeric responses.",
    },
    {
        "id": "SQL-022",
        "name": "IF/CASE Conditional Blind Injection",
        "pattern": r"(?i)(\bif\s*\([^,]+,\s*\d+\s*,\s*\d+|\bcase\s+when\s+.{0,60}\bthen\b)",
        "severity": "HIGH",
        "category": "sqli",
        "description": "IF/CASE WHEN conditional logic enables time-based or response-based blind SQLi.",
        "recommendation": "Use parameterized queries. Avoid dynamic SQL construction at all application layers.",
    },
    {
        "id": "SQL-023",
        "name": "CAST/CONVERT Type Confusion",
        "pattern": r"(?i)\b(cast\s*\(.*\s+as\s+\w+\s*\)|convert\s*\([^,]+,\s*\w+\))",
        "severity": "MEDIUM",
        "category": "sqli",
        "description": "CAST/CONVERT is used in error-based injection to force type mismatch errors revealing data.",
        "recommendation": "Use parameterized queries. Validate and type-check all user inputs before DB access.",
    },
    {
        "id": "SQL-024",
        "name": "GROUP BY Aggregation Injection",
        "pattern": r"(?i)\bgroup\s+by\s+.{0,40}(having|count\s*\(|rand\s*\()",
        "severity": "MEDIUM",
        "category": "sqli",
        "description": "GROUP BY + HAVING + COUNT(RAND()) combination enables error-based data extraction.",
        "recommendation": "Whitelist GROUP BY columns. Never construct aggregation clauses from user input.",
    },
    {
        "id": "SQL-025",
        "name": "String Concatenation Injection",
        "pattern": r"(?i)(\|\|.{0,30}\bselect\b|concat\s*\([^)]*\bselect\b)",
        "severity": "HIGH",
        "category": "sqli",
        "description": "String concatenation operators (||, CONCAT) build SQL payloads to bypass keyword filters.",
        "recommendation": "Never build SQL by string concatenation. Use parameterized queries exclusively.",
    },
    {
        "id": "SQL-026",
        "name": "Inline Comment Keyword Splitting",
        "pattern": r"(?i)(un/\*\*/ion|sel/\*\*/ect|/\*\*/or\b|/\*\*/and\b)",
        "severity": "HIGH",
        "category": "sqli",
        "description": "Inline SQL comments split keywords to bypass WAF pattern matching (SEL/**/ECT).",
        "recommendation": "Normalize input by collapsing comments before validation. Use parameterized queries.",
    },
    {
        "id": "SQL-027",
        "name": "Arithmetic Tautology Injection",
        "pattern": r"(?i)(\b\d+\s*=\s*\d+\b|\btrue\s*=\s*true\b|\b'[^']+'\s*=\s*'[^']+')",
        "severity": "HIGH",
        "category": "sqli",
        "description": "Arithmetic tautologies like 1=1 always evaluate TRUE, bypassing WHERE conditions.",
        "recommendation": "Use parameterized queries. Validate numeric inputs are integers before comparison.",
    },
    {
        "id": "SQL-028",
        "name": "pg_sleep PostgreSQL Time Injection",
        "pattern": r"(?i)(pg_sleep\s*\(|generate_series\s*\().*select",
        "severity": "CRITICAL",
        "category": "sqli",
        "description": "PostgreSQL-specific time delay functions used for time-based blind SQL injection.",
        "recommendation": "Use parameterized queries. Set statement_timeout. Monitor for slow query anomalies.",
    },
    {
        "id": "SQL-029",
        "name": "SQL LIMIT/OFFSET Chain Injection",
        "pattern": r"(?i)\blimit\s+\d+\s*(,\s*\d+)?\s*(union|--|#)",
        "severity": "HIGH",
        "category": "sqli",
        "description": "LIMIT/OFFSET followed by UNION SELECT injects additional query after pagination clause.",
        "recommendation": "Validate LIMIT/OFFSET are positive integers only. Use parameterized pagination.",
    },
    {
        "id": "SQL-030",
        "name": "Null Byte SQL Filter Bypass",
        "pattern": r"\x00",
        "severity": "HIGH",
        "category": "sqli",
        "description": "Null bytes terminate strings in C-based DBs, bypassing SQL filters and extension checks.",
        "recommendation": "Strip or reject null bytes from all user input. Use binary-safe parameterized queries.",
    },

    # ── XSS (20 rules) ────────────────────────────────────────────────────────

    {
        "id": "XSS-001",
        "name": "Script Tag Injection",
        "pattern": r"(?i)<\s*script[\s/>]",
        "severity": "HIGH",
        "category": "xss",
        "description": "Direct <script> tag injection executes arbitrary JavaScript in the victim's browser.",
        "recommendation": "Apply output encoding on all rendered user data. Implement strict CSP with script-src.",
    },
    {
        "id": "XSS-002",
        "name": "JavaScript Protocol URI",
        "pattern": r"(?i)javascript\s*:",
        "severity": "HIGH",
        "category": "xss",
        "description": "javascript: URI scheme executes code when used in href, src, or action attributes.",
        "recommendation": "Validate and whitelist URL schemes (allow only http/https). Use CSP default-src.",
    },
    {
        "id": "XSS-003",
        "name": "onerror Event Handler XSS",
        "pattern": r"(?i)\bonerror\s*=",
        "severity": "HIGH",
        "category": "xss",
        "description": "onerror fires JavaScript when a resource fails to load — triggered without user interaction.",
        "recommendation": "Strip event handler attributes from HTML input. Use DOMPurify HTML sanitizer.",
    },
    {
        "id": "XSS-004",
        "name": "onload/onscroll Auto-Execute XSS",
        "pattern": r"(?i)\b(onload|onscroll|onresize|onunload|onbeforeunload)\s*=",
        "severity": "HIGH",
        "category": "xss",
        "description": "Auto-trigger event handlers execute XSS payload without any user interaction.",
        "recommendation": "Whitelist allowed HTML attributes. Implement Content-Security-Policy header.",
    },
    {
        "id": "XSS-005",
        "name": "User Interaction Event XSS",
        "pattern": r"(?i)\bon(click|dblclick|mouse(over|out|enter|leave|move)|key(up|down|press)|submit|focus|blur|change|input|select)\s*=",
        "severity": "HIGH",
        "category": "xss",
        "description": "User interaction event handlers inject JavaScript triggered by mouse, keyboard, or form actions.",
        "recommendation": "Strip all on* event handler attributes from user-supplied HTML using an allowlist sanitizer.",
    },
    {
        "id": "XSS-006",
        "name": "eval() Arbitrary Execution",
        "pattern": r"(?i)\beval\s*\(",
        "severity": "CRITICAL",
        "category": "xss",
        "description": "eval() executes arbitrary JavaScript strings — the most dangerous XSS primitive.",
        "recommendation": "Prohibit eval() via CSP unsafe-eval restriction. Never pass user data to eval().",
    },
    {
        "id": "XSS-007",
        "name": "Cookie Theft (document.cookie)",
        "pattern": r"(?i)document\s*\.\s*cookie",
        "severity": "HIGH",
        "category": "xss",
        "description": "Accessing document.cookie is the primary goal of session-hijacking XSS attacks.",
        "recommendation": "Set HttpOnly flag on all session cookies. Use CSP. Output-encode all user data.",
    },
    {
        "id": "XSS-008",
        "name": "document.write DOM Injection",
        "pattern": r"(?i)document\s*\.\s*(write|writeln)\s*\(",
        "severity": "HIGH",
        "category": "xss",
        "description": "document.write with user input directly modifies the DOM, enabling full HTML injection.",
        "recommendation": "Never use document.write with user content. Use safe DOM APIs (textContent, createElement).",
    },
    {
        "id": "XSS-009",
        "name": "iframe Embedding Injection",
        "pattern": r"(?i)<\s*iframe[\s/>]",
        "severity": "HIGH",
        "category": "xss",
        "description": "Injected iframes embed malicious pages or execute cross-origin scripts via framing.",
        "recommendation": "Add X-Frame-Options: DENY and CSP frame-ancestors 'none'. Sanitize HTML input.",
    },
    {
        "id": "XSS-010",
        "name": "SVG-Based XSS",
        "pattern": r"(?i)<\s*svg[\s/>]",
        "severity": "HIGH",
        "category": "xss",
        "description": "SVG elements support script tags and event handlers, enabling XSS in SVG rendering context.",
        "recommendation": "Sanitize SVG input with DOMPurify. Block SVG in user content or serve from isolated domain.",
    },
    {
        "id": "XSS-011",
        "name": "Alert/Confirm Probe Payload",
        "pattern": r"(?i)\b(alert|confirm|prompt)\s*\(",
        "severity": "MEDIUM",
        "category": "xss",
        "description": "Classic XSS probe functions used to verify JavaScript execution in the victim browser.",
        "recommendation": "Encode HTML output. Implement CSP. Use X-XSS-Protection and X-Content-Type-Options.",
    },
    {
        "id": "XSS-012",
        "name": "innerHTML DOM-Based XSS",
        "pattern": r"(?i)\.innerHTML\s*=",
        "severity": "HIGH",
        "category": "xss",
        "description": "Setting innerHTML with user data injects HTML/JavaScript directly into the live DOM.",
        "recommendation": "Use textContent or innerText for user data. Apply DOMPurify before innerHTML assignment.",
    },
    {
        "id": "XSS-013",
        "name": "location.href Open Redirect / XSS",
        "pattern": r"(?i)(location\s*\.\s*href|location\s*\.\s*replace|location\s*\.\s*assign)\s*=",
        "severity": "HIGH",
        "category": "xss",
        "description": "Overwriting location.href with a javascript: URI executes code on navigation.",
        "recommendation": "Validate URL schemes before navigation. Implement CSP navigate-to directive.",
    },
    {
        "id": "XSS-014",
        "name": "Server-Side Template Injection (SSTI)",
        "pattern": r"(\{\{.*?\}\}|\{%.*?%\}|\$\{[^}]+\}|<%=.*?%>|#\{[^}]+\})",
        "severity": "CRITICAL",
        "category": "ssti",
        "description": "Template injection executes server-side code via Jinja2, Twig, Freemarker, or ERB engine.",
        "recommendation": "Never render user input as template code. Use sandboxed template evaluation with no globals.",
    },
    {
        "id": "XSS-015",
        "name": "AngularJS Template Expression XSS",
        "pattern": r"(?i)(ng-app\b|ng-bind\b|ng-model\b|\[\[.*?\]\])",
        "severity": "HIGH",
        "category": "xss",
        "description": "AngularJS template expressions in user input execute client-side JavaScript via data-binding.",
        "recommendation": "Disable ng-app in user-controlled markup. Use $sce.trustAsHtml only with DOMPurify output.",
    },
    {
        "id": "XSS-016",
        "name": "data:text/html URI XSS",
        "pattern": r"(?i)data\s*:\s*text/(html|javascript)",
        "severity": "HIGH",
        "category": "xss",
        "description": "data:text/html URIs embed executable HTML/JS, bypassing URL scheme allow-list checks.",
        "recommendation": "Block data: URIs in href/src attributes. Enforce strict URL scheme allowlisting.",
    },
    {
        "id": "XSS-017",
        "name": "VBScript Injection (Legacy IE)",
        "pattern": r"(?i)vbscript\s*:",
        "severity": "HIGH",
        "category": "xss",
        "description": "VBScript URI scheme executes code in legacy IE/Edge, similar to javascript:.",
        "recommendation": "Block vbscript: scheme in all URL contexts. Enforce modern CSP headers.",
    },
    {
        "id": "XSS-018",
        "name": "CSS expression() Execution",
        "pattern": r"(?i)\bexpression\s*\(",
        "severity": "HIGH",
        "category": "xss",
        "description": "CSS expression() in older IE executes JavaScript within style attributes on each repaint.",
        "recommendation": "Strip expression() from CSS input. Apply CSP with style-src 'unsafe-inline' removed.",
    },
    {
        "id": "XSS-019",
        "name": "String.fromCharCode Obfuscation",
        "pattern": r"(?i)fromCharCode\s*\(",
        "severity": "HIGH",
        "category": "xss",
        "description": "fromCharCode() converts numeric codes to strings to obfuscate XSS payloads from filters.",
        "recommendation": "Apply JavaScript de-obfuscation before XSS scanning. Enforce strict CSP.",
    },
    {
        "id": "XSS-020",
        "name": "img onerror/src XSS",
        "pattern": r"(?i)<\s*img[^>]+on\w+\s*=",
        "severity": "HIGH",
        "category": "xss",
        "description": "img tags with onerror/onload handlers auto-execute JavaScript when image loads or fails.",
        "recommendation": "Strip event attributes from img tags. Allow only safe attributes: src, alt, width, height.",
    },

    # ── COMMAND INJECTION (8 rules) ───────────────────────────────────────────

    {
        "id": "CMD-001",
        "name": "Semicolon OS Command Injection",
        "pattern": r";\s*(ls|cat|id|whoami|pwd|env|uname|ps|netstat|ifconfig|hostname|echo)",
        "severity": "CRITICAL",
        "category": "cmdi",
        "description": "Semicolon chaining appends OS commands after existing application commands.",
        "recommendation": "Never pass user input to shell. Use subprocess with argument list and shell=False.",
    },
    {
        "id": "CMD-002",
        "name": "Shell AND/OR Operator Injection",
        "pattern": r"(?:&&|\|\|)\s*(ls|cat|id|whoami|curl|wget|nc|bash|sh|python|perl|ruby)",
        "severity": "CRITICAL",
        "category": "cmdi",
        "description": "Shell && and || operators execute arbitrary commands based on exit status conditions.",
        "recommendation": "Validate input against strict whitelist. Use application library calls instead of shell.",
    },
    {
        "id": "CMD-003",
        "name": "Pipe to Shell Injection",
        "pattern": r"\|\s*(sh|bash|nc|ncat|netcat|python\d*|perl|ruby|lua|php)",
        "severity": "CRITICAL",
        "category": "cmdi",
        "description": "Pipe operator redirects output to shell interpreter enabling arbitrary command execution.",
        "recommendation": "Reject pipe characters in all user-controlled command parameters.",
    },
    {
        "id": "CMD-004",
        "name": "Backtick Command Substitution",
        "pattern": r"`[^`\n]{1,100}`",
        "severity": "CRITICAL",
        "category": "cmdi",
        "description": "Backtick command substitution executes shell commands and substitutes output inline.",
        "recommendation": "Escape or reject backtick characters. Use subprocess with shell=False argument arrays.",
    },
    {
        "id": "CMD-005",
        "name": "$() Subshell Injection",
        "pattern": r"\$\([^)]{1,100}\)",
        "severity": "CRITICAL",
        "category": "cmdi",
        "description": "$() subshell is a modern alternative to backticks for command substitution injection.",
        "recommendation": "Sanitize $ characters in user input. Use subprocess lists, never shell=True.",
    },
    {
        "id": "CMD-006",
        "name": "Shell Binary Path Injection",
        "pattern": r"(?i)(/bin/sh|/bin/bash|/usr/bin/python\d*|/usr/bin/perl|cmd\.exe|powershell\.exe)",
        "severity": "CRITICAL",
        "category": "cmdi",
        "description": "Direct shell binary paths in user input attempt to spawn privileged shell sessions.",
        "recommendation": "Block shell path references. Use application-level APIs with explicit argument validation.",
    },
    {
        "id": "CMD-007",
        "name": "Network Exfiltration Command",
        "pattern": r"(?i)\b(curl|wget|nc|ncat|netcat|nmap|socat)\b.{0,60}(https?://|ftp://|\d+\.\d+\.\d+)",
        "severity": "CRITICAL",
        "category": "cmdi",
        "description": "Network utility commands can exfiltrate data to attacker-controlled servers or download malware.",
        "recommendation": "Implement egress filtering. Never pass user input to system() or subprocess with shell=True.",
    },
    {
        "id": "CMD-008",
        "name": "Windows CMD/PowerShell Injection",
        "pattern": r"(?i)(cmd\.exe\s*/[cCkK]|powershell\s+(-\w+\s+)*-[eE]nc\w*|%COMSPEC%)",
        "severity": "CRITICAL",
        "category": "cmdi",
        "description": "Windows command prompt and PowerShell injection execute arbitrary commands with full OS access.",
        "recommendation": "Sanitize Windows shell metacharacters. Use .NET framework APIs directly instead of cmd.exe.",
    },

    # ── PATH TRAVERSAL (7 rules) ──────────────────────────────────────────────

    {
        "id": "PATH-001",
        "name": "Unix Directory Traversal (../)",
        "pattern": r"(\.\./){2,}",
        "severity": "HIGH",
        "category": "path_traversal",
        "description": "Multiple ../ sequences navigate outside the web root to access arbitrary system files.",
        "recommendation": "Canonicalize paths using os.path.realpath(). Validate the resolved path starts with the allowed base.",
    },
    {
        "id": "PATH-002",
        "name": "Windows Directory Traversal (..\\ )",
        "pattern": r"(\.\.[/\\]){2,}",
        "severity": "HIGH",
        "category": "path_traversal",
        "description": "Windows backslash traversal accesses files outside web root on Windows-hosted applications.",
        "recommendation": "Normalize path separators. Use Path.resolve() and validate against allowed base directory.",
    },
    {
        "id": "PATH-003",
        "name": "URL-Encoded Path Traversal (%2e%2e)",
        "pattern": r"(?i)(%2e%2e[%/\\]){2,}",
        "severity": "HIGH",
        "category": "path_traversal",
        "description": "URL-encoded ../ sequences bypass naive string-based path traversal filters.",
        "recommendation": "Decode URL encoding before path validation. Use urllib.parse.unquote() recursively.",
    },
    {
        "id": "PATH-004",
        "name": "Double-Encoded Path Traversal (%252e)",
        "pattern": r"(?i)(%252e%252e|%25252e|%c0%af)",
        "severity": "HIGH",
        "category": "path_traversal",
        "description": "Double URL encoding (%252e = .) bypasses WAFs that decode only once before validation.",
        "recommendation": "Decode URL encoding recursively until stable before path validation.",
    },
    {
        "id": "PATH-005",
        "name": "Unix Sensitive File Read",
        "pattern": r"(?i)(etc/passwd|etc/shadow|etc/hosts|proc/self/environ|proc/self/cmdline|proc/self/mem)",
        "severity": "CRITICAL",
        "category": "path_traversal",
        "description": "Attempts to read Unix credential files and process memory — high-value targets for attackers.",
        "recommendation": "Apply strict path allowlisting. Run application as non-root. Use read-only filesystem mounts.",
    },
    {
        "id": "PATH-006",
        "name": "Windows System File Read",
        "pattern": r"(?i)(windows[/\\]win\.ini|windows[/\\]system32[/\\]|boot\.ini|autoexec\.bat)",
        "severity": "HIGH",
        "category": "path_traversal",
        "description": "Attempts to access Windows system configuration files — reveals OS version and settings.",
        "recommendation": "Restrict filesystem permissions. Validate file paths against strict allowlist.",
    },
    {
        "id": "PATH-007",
        "name": "Null Byte Path Extension Bypass",
        "pattern": r"\x00[./\\]",
        "severity": "HIGH",
        "category": "path_traversal",
        "description": "Null byte terminates filename in C-based code, bypassing file extension validation (file.php%00.jpg).",
        "recommendation": "Sanitize null bytes from filenames. Validate file extensions after null byte stripping.",
    },

    # ── SSRF (8 rules) ────────────────────────────────────────────────────────

    {
        "id": "SSRF-001",
        "name": "AWS Instance Metadata (169.254.169.254)",
        "pattern": r"169\.254\.169\.254",
        "severity": "CRITICAL",
        "category": "ssrf",
        "description": "AWS EC2 metadata endpoint exposes IAM credentials and instance configuration to SSRF.",
        "recommendation": "Enforce IMDSv2. Block 169.254.169.254 at VPC firewall level. Use SSRF-safe URL fetching.",
    },
    {
        "id": "SSRF-002",
        "name": "Localhost SSRF (127.0.0.1)",
        "pattern": r"(?i)(localhost|127\.\d+\.\d+\.\d+)",
        "severity": "CRITICAL",
        "category": "ssrf",
        "description": "SSRF to localhost bypasses external firewall to access internal services (Redis, Elasticsearch).",
        "recommendation": "Block all loopback addresses in URL fetching code. Use network-level egress filtering.",
    },
    {
        "id": "SSRF-003",
        "name": "Private Network SSRF (RFC1918)",
        "pattern": r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
        "severity": "HIGH",
        "category": "ssrf",
        "description": "SSRF targeting RFC1918 private ranges probes internal network infrastructure and services.",
        "recommendation": "Block all RFC1918 IP ranges in outgoing URL requests. Use allowlist for external URLs.",
    },
    {
        "id": "SSRF-004",
        "name": "IPv6 Localhost SSRF (::1)",
        "pattern": r"(?i)(::1|\[::1\]|0:0:0:0:0:0:0:1)",
        "severity": "CRITICAL",
        "category": "ssrf",
        "description": "IPv6 loopback ::1 bypasses IPv4-only SSRF protections in URL validation code.",
        "recommendation": "Block IPv4 and IPv6 loopback addresses. Resolve hostnames and validate against IP blocklist.",
    },
    {
        "id": "SSRF-005",
        "name": "Alternative Loopback Encoding",
        "pattern": r"(?i)(0\.0\.0\.0|0177\.\d|0x7f\.\d{1,3}|2130706433)",
        "severity": "CRITICAL",
        "category": "ssrf",
        "description": "Octal (0177.0.0.1), hex (0x7f.0.0.1), and decimal (2130706433) encodings bypass naive IP checks.",
        "recommendation": "Resolve hostnames to canonical IPs using socket.getaddrinfo(). Validate resolved IPs against blocklist.",
    },
    {
        "id": "SSRF-006",
        "name": "Cloud Metadata Endpoint SSRF",
        "pattern": r"(?i)(metadata\.google\.internal|metadata\.aws\.internal|100\.100\.100\.200|fd00:ec2::254)",
        "severity": "CRITICAL",
        "category": "ssrf",
        "description": "Cloud provider metadata endpoints expose VM credentials and instance configuration data.",
        "recommendation": "Block cloud metadata IPs at network layer. Use IMDSv2 / workload identity instead.",
    },
    {
        "id": "SSRF-007",
        "name": "Internal Hostname Probe",
        "pattern": r"(?i)\b(internal\.|intranet\.|corp\.|admin\.|management\.|k8s\.|kubernetes\.)",
        "severity": "HIGH",
        "category": "ssrf",
        "description": "Internal hostname patterns in user-supplied URLs probe corporate intranet services via SSRF.",
        "recommendation": "Validate hostnames against external DNS only. Use allowlist for permitted external domains.",
    },
    {
        "id": "SSRF-008",
        "name": "Dangerous Protocol Scheme (SSRF)",
        "pattern": r"(?i)(gopher://|dict://|file://|ldap://|ftp://|tftp://|sftp://)",
        "severity": "CRITICAL",
        "category": "ssrf",
        "description": "Non-HTTP protocols (gopher, file, dict) dramatically expand the SSRF attack surface.",
        "recommendation": "Whitelist only http:// and https:// schemes. Reject all other protocols at URL parse time.",
    },

    # ── LDAP INJECTION (2 rules) ──────────────────────────────────────────────

    {
        "id": "LDAP-001",
        "name": "LDAP Filter Metacharacter Injection",
        "pattern": r"(\*\)\(|\)\(|\|\s*\(|\&\s*\()",
        "severity": "HIGH",
        "category": "ldap",
        "description": "LDAP filter metacharacters can bypass authentication and dump directory contents.",
        "recommendation": "Escape LDAP special chars: *, (, ), \\, NUL, /. Use parameterized LDAP queries via SDK.",
    },
    {
        "id": "LDAP-002",
        "name": "LDAP Wildcard Auth Bypass",
        "pattern": r"(?i)(\*\s*\)\s*\(\s*(objectClass|uid|cn|mail)\s*=|\*\s*\)\s*\(\s*objectCategory)",
        "severity": "CRITICAL",
        "category": "ldap",
        "description": "LDAP wildcard injection matches any directory entry, completely bypassing authentication.",
        "recommendation": "Validate that username/password fields contain no LDAP metacharacters before binding.",
    },

    # ── XXE INJECTION (3 rules) ───────────────────────────────────────────────

    {
        "id": "XXE-001",
        "name": "XXE DOCTYPE Declaration",
        "pattern": r"(?i)<!DOCTYPE\s+\w+\s*(\[|SYSTEM|PUBLIC)",
        "severity": "CRITICAL",
        "category": "xxe",
        "description": "External entity DOCTYPE declaration enables server-side file reading via XML expansion.",
        "recommendation": "Disable DOCTYPE processing. Use defusedxml in Python. Set FEATURE_DISALLOW_DOCTYPE_DECL=true.",
    },
    {
        "id": "XXE-002",
        "name": "XXE SYSTEM Entity Reference",
        "pattern": r"(?i)<!ENTITY\s+\w+\s+SYSTEM\s+['\"]",
        "severity": "CRITICAL",
        "category": "xxe",
        "description": "SYSTEM entity reference reads arbitrary server filesystem paths via XML entity expansion.",
        "recommendation": "Disable external entity resolution. Use lxml with resolve_entities=False and no_network=True.",
    },
    {
        "id": "XXE-003",
        "name": "XXE Parameter Entity (Blind XXE)",
        "pattern": r"(?i)<!ENTITY\s+%\s+\w+",
        "severity": "CRITICAL",
        "category": "xxe",
        "description": "Parameter entities enable advanced blind XXE attacks with out-of-band data exfiltration.",
        "recommendation": "Disable DTD processing entirely. Switch from XML to JSON APIs where possible.",
    },

    # ── OTHER HIGH-VALUE RULES ─────────────────────────────────────────────────

    {
        "id": "LOG4J-001",
        "name": "Log4Shell (CVE-2021-44228)",
        "pattern": r"\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)://",
        "severity": "CRITICAL",
        "category": "log4shell",
        "description": "Log4Shell exploits Log4j JNDI lookup to achieve unauthenticated RCE on Java servers.",
        "recommendation": "Upgrade Log4j to 2.17.1+. Set -Dlog4j2.formatMsgNoLookups=true. Block ${jndi: in WAF.",
    },
    {
        "id": "BOT-001",
        "name": "Security Scanner Signature",
        "pattern": r"(?i)(nikto|sqlmap|nessus|openvas|masscan|zgrab|nuclei|burpsuite|acunetix|nmap|dirb|gobuster|wfuzz|ffuf)",
        "severity": "MEDIUM",
        "category": "scanner",
        "description": "Known security scanner user-agent or fingerprint detected in the request headers.",
        "recommendation": "Block known scanner signatures. Monitor source IP for follow-up attack attempts. Alert SOC.",
    },
    {
        "id": "AUTH-001",
        "name": "JWT None Algorithm Tampering",
        "pattern": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.(none|None|NONE|\s*)$",
        "severity": "CRITICAL",
        "category": "auth",
        "description": "JWT with 'none' algorithm bypasses signature verification, allowing arbitrary session forgery.",
        "recommendation": "Explicitly reject the 'none' algorithm. Use a strict JWT library with alg allowlist enforcement.",
    },
]

_compiled = [(s, re.compile(s["pattern"])) for s in SIGNATURES if s.get("pattern")]


# ── Request Inspector ─────────────────────────────────────────────────────────

def inspect_request(
    method: str,
    path: str,
    headers: dict,
    body: str = "",
    ip: str = "",
) -> dict:
    """Inspect an HTTP request across all fields and return a threat report."""
    path_decoded = unquote(path)
    body_decoded = unquote(body) if body else ""

    parsed = urlparse(path_decoded)
    url_path = parsed.path
    query_string = parsed.query

    # Build named inspection targets
    targets = {
        "url_path": url_path,
        "query_params": query_string,
        "request_body": body_decoded,
    }
    if headers:
        targets["headers"] = " ".join(f"{k}: {v}" for k, v in headers.items())

    threats = []
    seen_rules = set()

    for sig, pattern in _compiled:
        if sig["id"] in seen_rules:
            continue
        for location, content in targets.items():
            if not content:
                continue
            m = pattern.search(content)
            if m:
                start = max(0, m.start() - 12)
                end = min(len(content), m.end() + 12)
                snippet = content[start:end].strip()
                threats.append({
                    "rule_id": sig["id"],
                    "name": sig["name"],
                    "severity": sig["severity"],
                    "category": sig["category"],
                    "found_in": location,
                    "matched_payload": snippet,
                    "description": sig.get("description", ""),
                    "recommendation": sig.get("recommendation", ""),
                })
                seen_rules.add(sig["id"])
                break

    anomaly = _ml_anomaly_score(method, path_decoded, headers, body_decoded)
    risk_score = _composite_risk(threats, anomaly["score"])
    action = _decide_action(threats, anomaly["score"], risk_score)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "method": method,
        "path": path[:200],
        "threats": threats,
        "anomaly": anomaly,
        "action": action,
        "blocked": action == "block",
        "risk_score": risk_score,
    }


# ── Scoring ───────────────────────────────────────────────────────────────────

def _composite_risk(threats: list, anomaly_score: float) -> float:
    """Return risk score 0–100 based on threat severity counts + anomaly."""
    score = 0.0
    for t in threats:
        score += _SEVERITY_SCORE.get(t["severity"], 5)
    score += anomaly_score * 20
    return round(min(score, 100.0), 1)


def _decide_action(threats: list, anomaly_score: float, risk_score: float) -> str:
    severities = [t["severity"] for t in threats]
    if "CRITICAL" in severities or risk_score >= 70 or anomaly_score >= 0.8:
        return "block"
    if risk_score >= 40 or (len([s for s in severities if s == "HIGH"]) >= 2):
        return "alert"
    if threats or anomaly_score > 0.3:
        return "alert"
    return "allow"


# ── ML Anomaly Engine ─────────────────────────────────────────────────────────

def _ml_anomaly_score(method: str, path: str, headers: dict, body: str) -> dict:
    """Heuristic anomaly scoring that simulates a behavioral ML model."""
    score = 0.0
    signals = []

    # 1. Payload entropy
    if body:
        ent = _entropy(body)
        if ent > 4.5:
            score += 0.25
            signals.append(f"High-entropy payload ({ent:.2f} bits) — possible encoded/encrypted attack")

    # 2. Non-standard HTTP method
    if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        score += 0.4
        signals.append(f"Non-standard HTTP method: {method}")

    # 3. URL path length
    if len(path) > 1000:
        score += 0.3
        signals.append(f"Extremely long URL path ({len(path):,} chars)")
    elif len(path) > 500:
        score += 0.15
        signals.append(f"Unusually long URL path ({len(path)} chars)")

    # 4. Null byte presence
    if "\x00" in path or "\x00" in body:
        score += 0.6
        signals.append("Null byte injection detected in request")

    # 5. Double URL encoding
    if "%25" in path.lower() or "%2525" in path.lower():
        score += 0.4
        signals.append("Double URL-encoding detected — WAF evasion technique")

    # 6. Missing User-Agent
    ua = headers.get("user-agent", headers.get("User-Agent", ""))
    if not ua:
        score += 0.2
        signals.append("Missing User-Agent header (automated scanner / bot behavior)")

    # 7. Excessive parameters
    param_count = path.count("=") + body.count("=")
    if param_count > 30:
        score += 0.25
        signals.append(f"Excessive parameters ({param_count}) — parameter pollution attempt")

    # 8. High density of special characters in body
    if body:
        special = sum(1 for c in body if c in "<>\"'`;|&${}[]\\")
        density = special / len(body)
        if density > 0.15:
            score += 0.3
            signals.append(f"High special-character density ({density:.0%}) — injection payload signature")

    # 9. Oversized body
    if len(body) > 50_000:
        score += 0.15
        signals.append(f"Oversized request body ({len(body):,} bytes) — potential DoS or buffer overflow")

    # 10. Non-ASCII characters in URL path
    try:
        path.encode("ascii")
    except UnicodeEncodeError:
        score += 0.2
        signals.append("Non-ASCII characters in URL path — possible homoglyph or unicode evasion")

    # 11. Excessive fragment repetition (e.g., repeated ../../../)
    if re.search(r"(\.\./|%2e%2e){4,}", path, re.IGNORECASE):
        score += 0.35
        signals.append("Deep directory traversal sequence detected in path")

    # 12. Suspicious Content-Type absence with large body
    ct = headers.get("content-type", headers.get("Content-Type", ""))
    if len(body) > 100 and not ct:
        score += 0.1
        signals.append("Non-empty body submitted with no Content-Type header")

    return {"score": round(min(score, 1.0), 3), "signals": signals}


def _entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


# ── Batch Log Analysis ────────────────────────────────────────────────────────

async def analyze_log_sample(log_lines: list[str]) -> dict:
    """Parse Apache/Nginx-style log lines and inspect each request."""
    apache_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[.*?\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+)'
    )
    results = []
    for line in log_lines[:500]:
        m = apache_pattern.match(line)
        if m:
            result = inspect_request(
                method=m.group("method"),
                path=m.group("path"),
                headers={},
                body="",
                ip=m.group("ip"),
            )
            result["status_code"] = int(m.group("status"))
            results.append(result)

    blocked = [r for r in results if r["action"] == "block"]
    alerted = [r for r in results if r["action"] == "alert"]
    top_threats = _top_threat_categories(results)

    return {
        "analyzed": len(results),
        "blocked": len(blocked),
        "alerted": len(alerted),
        "allowed": len(results) - len(blocked) - len(alerted),
        "top_threats": top_threats,
        "high_risk_requests": blocked[:20],
        "analyzed_at": datetime.utcnow().isoformat(),
    }


def _top_threat_categories(results: list) -> list:
    cats = defaultdict(int)
    for r in results:
        for t in r.get("threats", []):
            cats[t["category"]] += 1
    return sorted(
        [{"category": k, "count": v} for k, v in cats.items()],
        key=lambda x: -x["count"],
    )[:10]


# ── Rate Limiting ─────────────────────────────────────────────────────────────

_rate_tracker: dict[str, list] = defaultdict(list)


def check_rate_limit(ip: str, window_seconds: int = 60, max_requests: int = 100) -> dict:
    now = datetime.utcnow().timestamp()
    requests = _rate_tracker[ip]
    requests = [t for t in requests if now - t < window_seconds]
    requests.append(now)
    _rate_tracker[ip] = requests

    count = len(requests)
    limited = count > max_requests
    return {
        "ip": ip,
        "requests_in_window": count,
        "limit": max_requests,
        "window_seconds": window_seconds,
        "rate_limited": limited,
        "action": "block" if limited else "allow",
    }


def get_firewall_rules() -> list:
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "severity": s["severity"].lower(),
            "category": s["category"],
            "enabled": True,
        }
        for s in SIGNATURES
    ]
