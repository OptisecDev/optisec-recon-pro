import subprocess
import shutil
import xml.etree.ElementTree as ET
from typing import Optional


def is_nmap_available() -> bool:
    return shutil.which("nmap") is not None


def nmap_scan(target: str, flags: str = "-sV --open -T4 --top-ports 1000") -> dict:
    if not is_nmap_available():
        return {"error": "nmap is not installed or not in PATH", "ports": []}

    try:
        cmd = ["nmap"] + flags.split() + ["-oX", "-", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0 and not result.stdout:
            return {"error": result.stderr, "ports": []}
        return _parse_xml(result.stdout, target)
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 120 seconds", "ports": []}
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
