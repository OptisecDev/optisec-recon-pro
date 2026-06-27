import socket
import subprocess
import shutil
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# Common ports to check when nmap is unavailable
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 3000, 3306, 3389, 4444,
    5432, 5900, 6379, 6443, 8000, 8080, 8443, 8888, 9200, 27017,
]

PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 4444: "metasploit", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 6443: "kubernetes", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


def is_nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _check_port(host: str, port: int, timeout: float = 1.5) -> Optional[dict]:
    """Try to connect to a port; return port info if open."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            try:
                s.settimeout(0.5)
                banner = s.recv(256).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
            return {
                "port": str(port),
                "protocol": "tcp",
                "state": "open",
                "service": PORT_SERVICES.get(port, "unknown"),
                "product": banner[:60] if banner else "",
                "version": "",
            }
    except Exception:
        return None


def socket_scan(target: str) -> dict:
    """Socket-based port scanner used when nmap is not available."""
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target

    ports = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(_check_port, target, p): p for p in COMMON_PORTS}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                ports.append(result)

    ports.sort(key=lambda x: int(x["port"]))
    return {
        "target": target,
        "ip": ip,
        "state": "up" if ports else "unknown",
        "hostname": target,
        "ports": ports,
        "scanner": "socket",
    }


def nmap_scan(target: str, flags: str = "-sV --open -T4 --top-ports 1000") -> dict:
    if not is_nmap_available():
        result = socket_scan(target)
        result["note"] = "nmap not found — used socket scanner for common ports"
        return result

    try:
        cmd = ["nmap"] + flags.split() + ["-oX", "-", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0 and not result.stdout:
            # Fall back to socket scan on nmap failure
            r = socket_scan(target)
            r["note"] = f"nmap error — used socket scanner: {result.stderr[:100]}"
            return r
        return _parse_xml(result.stdout, target)
    except subprocess.TimeoutExpired:
        r = socket_scan(target)
        r["note"] = "nmap timed out — used socket scanner"
        return r
    except Exception as e:
        return {"error": str(e), "ports": []}


def _parse_xml(xml_output: str, target: str) -> dict:
    ports = []
    host_info = {"target": target, "state": "unknown", "hostname": ""}

    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            state_el = host.find("status")
            if state_el is not None:
                host_info["state"] = state_el.get("state", "unknown")

            hn_el = host.find(".//hostname")
            if hn_el is not None:
                host_info["hostname"] = hn_el.get("name", "")

            for port_el in host.findall(".//port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port_el.find("service")
                ports.append({
                    "port": port_el.get("portid"),
                    "protocol": port_el.get("protocol"),
                    "state": "open",
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                })
    except ET.ParseError:
        pass

    return {**host_info, "ports": ports}
