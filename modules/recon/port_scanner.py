"""Fast port scanner using socket — top 100 common ports."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

TOP_100_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 162: "SNMP-TRAP", 179: "BGP", 194: "IRC", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 513: "rlogin",
    514: "syslog", 515: "LPD", 520: "RIP", 587: "SMTP-SUBMISSION",
    631: "IPP", 636: "LDAPS", 873: "rsync", 989: "FTPS-DATA", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1434: "MSSQL-UDP", 1521: "Oracle", 1723: "PPTP",
    1883: "MQTT", 2049: "NFS", 2181: "Zookeeper", 2375: "Docker",
    2376: "Docker-TLS", 3000: "Node.js/Grafana", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4200: "Angular Dev", 4848: "GlassFish",
    5000: "Flask/UPnP", 5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "K8s API",
    7001: "WebLogic", 7474: "Neo4j", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8082: "HTTP-Alt",
    8083: "HTTP-Alt", 8088: "Hadoop", 8090: "HTTP-Alt",
    8443: "HTTPS-Alt", 8444: "HTTPS-Alt", 8500: "Consul", 8888: "Jupyter",
    9000: "SonarQube/PHP-FPM", 9090: "Prometheus/Openshift",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    9418: "Git", 9999: "Icecast", 10000: "Webmin", 11211: "Memcached",
    15672: "RabbitMQ-Mgmt", 16443: "Microk8s", 27017: "MongoDB",
    27018: "MongoDB", 28017: "MongoDB-Web", 50000: "IBM-DB2",
}

HIGH_RISK_PORTS = {
    21, 23, 111, 135, 137, 138, 139, 445, 1433, 1521, 3306,
    3389, 5432, 5900, 6379, 7001, 9200, 11211, 27017, 50000,
}


def _probe_port(host: str, port: int, timeout: float = 0.8) -> tuple[int, bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            try:
                s.settimeout(1)
                data = s.recv(512)
                banner = data.decode("utf-8", errors="replace").strip()[:100]
            except Exception:
                pass
            return port, True, banner
    except Exception:
        return port, False, ""


def scan_ports(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 0.8,
    max_workers: int = 50,
) -> dict:
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"target": target, "error": f"DNS resolution failed: {e}"}

    port_list = ports or list(TOP_100_PORTS.keys())

    open_ports = []
    closed_count = 0

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe_port, host, p, timeout): p for p in port_list}
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                service = TOP_100_PORTS.get(port, "unknown")
                open_ports.append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "high_risk": port in HIGH_RISK_PORTS,
                    "risk_label": "HIGH" if port in HIGH_RISK_PORTS else "LOW",
                })
            else:
                closed_count += 1

    open_ports.sort(key=lambda x: x["port"])
    high_risk_open = [p for p in open_ports if p["high_risk"]]

    risk_score = min(len(high_risk_open) * 15 + len(open_ports) * 2, 100)

    return {
        "target": target,
        "host": host,
        "ip": ip,
        "ports_scanned": len(port_list),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "high_risk_count": len(high_risk_open),
        "risk_score": risk_score,
        "risk_label": "HIGH" if risk_score > 60 else "MEDIUM" if risk_score > 30 else "LOW",
        "notes": _build_notes(open_ports, high_risk_open),
    }


def _build_notes(open_ports: list, high_risk: list) -> list:
    notes = []
    if not open_ports:
        notes.append("No open ports found — target may be firewalled")
        return notes

    notes.append(f"{len(open_ports)} open ports found")
    if high_risk:
        services = ", ".join(f"{p['port']}/{p['service']}" for p in high_risk[:5])
        notes.append(f"High-risk services exposed: {services}")
    if any(p["port"] == 3389 for p in open_ports):
        notes.append("RDP (3389) open — brute force risk, should not be internet-facing")
    if any(p["port"] == 6379 for p in open_ports):
        notes.append("Redis (6379) open — often unauthenticated, immediate remediation needed")
    if any(p["port"] == 27017 for p in open_ports):
        notes.append("MongoDB (27017) open — check authentication is enforced")
    return notes
