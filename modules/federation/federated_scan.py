"""Federated Scanning — distributed scan orchestration across multiple nodes."""

import os
import json
import uuid
import asyncio
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional
import httpx

FEDERATION_DB = Path("data/federation.json")
NODE_KEY_FILE = Path("data/federation_node.key")


def _load_federation() -> dict:
    FEDERATION_DB.parent.mkdir(parents=True, exist_ok=True)
    if FEDERATION_DB.exists():
        return json.loads(FEDERATION_DB.read_text())
    return {"nodes": [], "tasks": [], "results": [], "this_node": None}


def _save_federation(data: dict) -> None:
    FEDERATION_DB.parent.mkdir(parents=True, exist_ok=True)
    FEDERATION_DB.write_text(json.dumps(data, indent=2, default=str))


def _node_key() -> str:
    NODE_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if NODE_KEY_FILE.exists():
        return NODE_KEY_FILE.read_text().strip()
    key = secrets.token_hex(32)
    NODE_KEY_FILE.write_text(key)
    NODE_KEY_FILE.chmod(0o600)
    return key


def initialize_node(
    name: str,
    endpoint: str,
    capabilities: list[str] = None,
    region: str = "default",
) -> dict:
    """Register this instance as a federation node."""
    fed = _load_federation()
    node_id = f"node-{hashlib.sha256(endpoint.encode()).hexdigest()[:12]}"
    node_key = _node_key()

    this_node = {
        "id": node_id,
        "name": name,
        "endpoint": endpoint,
        "capabilities": capabilities or ["recon", "vuln", "osint"],
        "region": region,
        "api_key": node_key,
        "status": "active",
        "registered_at": datetime.utcnow().isoformat(),
        "last_heartbeat": datetime.utcnow().isoformat(),
        "tasks_completed": 0,
        "version": "2.0",
    }

    fed["this_node"] = this_node
    _save_federation(fed)
    return this_node


def register_peer(
    name: str,
    endpoint: str,
    api_key: str,
    capabilities: list[str] = None,
    region: str = "remote",
) -> dict:
    """Add a peer federation node."""
    fed = _load_federation()
    node_id = f"node-{hashlib.sha256(endpoint.encode()).hexdigest()[:12]}"

    existing = next((n for n in fed["nodes"] if n["id"] == node_id), None)
    if existing:
        return {"error": f"Node {node_id} already registered", "node": existing}

    node = {
        "id": node_id,
        "name": name,
        "endpoint": endpoint.rstrip("/"),
        "api_key": api_key,
        "capabilities": capabilities or ["recon"],
        "region": region,
        "status": "unknown",
        "registered_at": datetime.utcnow().isoformat(),
        "last_heartbeat": None,
        "last_ping_ms": None,
    }
    fed["nodes"].append(node)
    _save_federation(fed)
    return node


async def ping_node(node_id: str) -> dict:
    """Health-check a peer node."""
    fed = _load_federation()
    node = next((n for n in fed["nodes"] if n["id"] == node_id), None)
    if not node:
        return {"error": f"Node {node_id} not found"}

    start = asyncio.get_event_loop().time()
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.get(
                f"{node['endpoint']}/api/federation/ping",
                headers={"X-Federation-Key": node["api_key"]},
            )
            elapsed_ms = round((asyncio.get_event_loop().time() - start) * 1000, 1)
            status = "online" if r.status_code == 200 else "degraded"
            info = r.json() if r.status_code == 200 else {}
        except Exception as e:
            elapsed_ms = None
            status = "offline"
            info = {"error": str(e)}

    node["status"] = status
    node["last_heartbeat"] = datetime.utcnow().isoformat()
    node["last_ping_ms"] = elapsed_ms
    _save_federation(fed)
    return {"node_id": node_id, "status": status, "ping_ms": elapsed_ms, "info": info}


async def ping_all_nodes() -> list:
    """Ping all registered peer nodes concurrently."""
    fed = _load_federation()
    tasks = [ping_node(n["id"]) for n in fed["nodes"]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r if not isinstance(r, Exception) else {"error": str(r)} for r in results]


async def dispatch_scan(
    target: str,
    scan_types: list[str],
    strategy: str = "parallel",
    preferred_regions: list[str] = None,
) -> dict:
    """Distribute a scan task across available federation nodes."""
    fed = _load_federation()
    task_id = str(uuid.uuid4())

    online_nodes = [n for n in fed["nodes"] if n["status"] == "online"]
    if preferred_regions:
        online_nodes = [n for n in online_nodes if n["region"] in preferred_regions] or online_nodes

    if not online_nodes:
        return await _local_fallback_scan(task_id, target, scan_types, fed)

    # Assign scan types to nodes based on capabilities
    assignments = _assign_scan_tasks(scan_types, online_nodes, strategy)

    task = {
        "task_id": task_id,
        "target": target,
        "scan_types": scan_types,
        "strategy": strategy,
        "status": "dispatched",
        "created_at": datetime.utcnow().isoformat(),
        "assignments": assignments,
        "node_count": len(set(a["node_id"] for a in assignments)),
    }

    fed["tasks"].append(task)
    _save_federation(fed)

    # Dispatch to nodes
    dispatch_results = await _send_to_nodes(task_id, target, assignments, online_nodes)

    task["dispatch_results"] = dispatch_results
    task["status"] = "running"
    _save_federation(fed)

    return task


def _assign_scan_tasks(
    scan_types: list, nodes: list, strategy: str
) -> list:
    assignments = []
    if strategy == "parallel":
        # Each node gets all scan types it can handle
        for node in nodes:
            node_types = [t for t in scan_types if _node_can_handle(node, t)]
            if node_types:
                assignments.append({
                    "node_id": node["id"],
                    "node_name": node["name"],
                    "scan_types": node_types,
                    "status": "pending",
                })
    else:
        # Round-robin distribution
        for i, scan_type in enumerate(scan_types):
            node = nodes[i % len(nodes)]
            existing = next((a for a in assignments if a["node_id"] == node["id"]), None)
            if existing:
                existing["scan_types"].append(scan_type)
            else:
                assignments.append({
                    "node_id": node["id"],
                    "node_name": node["name"],
                    "scan_types": [scan_type],
                    "status": "pending",
                })
    return assignments


def _node_can_handle(node: dict, scan_type: str) -> bool:
    caps = node.get("capabilities", [])
    mapping = {
        "recon": ["recon", "dns", "subdomain", "whois"],
        "vuln": ["vuln", "xss", "sqli", "ssrf"],
        "osint": ["osint", "email", "social"],
        "threat_intel": ["threat_intel", "mitre", "ioc"],
    }
    for cap, types in mapping.items():
        if cap in caps and scan_type in types:
            return True
    return scan_type in caps


async def _send_to_nodes(task_id: str, target: str, assignments: list, nodes: list) -> list:
    results = []
    node_map = {n["id"]: n for n in nodes}

    async def _send(assignment):
        node = node_map.get(assignment["node_id"])
        if not node:
            return {"node_id": assignment["node_id"], "status": "not_found"}
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                r = await client.post(
                    f"{node['endpoint']}/api/federation/execute",
                    json={"task_id": task_id, "target": target,
                          "scan_types": assignment["scan_types"]},
                    headers={"X-Federation-Key": node["api_key"]},
                )
                return {"node_id": node["id"], "status": "dispatched" if r.status_code == 200 else "error",
                        "response": r.json() if r.status_code == 200 else {}}
            except Exception as e:
                return {"node_id": node["id"], "status": "unreachable", "error": str(e)}

    tasks = [_send(a) for a in assignments]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r if not isinstance(r, Exception) else {"error": str(r)} for r in results]


async def _local_fallback_scan(task_id: str, target: str, scan_types: list, fed: dict) -> dict:
    task = {
        "task_id": task_id,
        "target": target,
        "scan_types": scan_types,
        "strategy": "local_fallback",
        "status": "local",
        "created_at": datetime.utcnow().isoformat(),
        "note": "No online peers available — scan will run locally",
        "assignments": [{"node_id": "local", "node_name": "This Node", "scan_types": scan_types}],
    }
    fed["tasks"].append(task)
    _save_federation(fed)
    return task


async def collect_results(task_id: str) -> dict:
    """Poll all nodes for results of a dispatched task."""
    fed = _load_federation()
    task = next((t for t in fed["tasks"] if t["task_id"] == task_id), None)
    if not task:
        return {"error": f"Task {task_id} not found"}

    collected = []
    for assignment in task.get("assignments", []):
        node = next((n for n in fed["nodes"] if n["id"] == assignment["node_id"]), None)
        if not node or node["status"] != "online":
            continue
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                r = await client.get(
                    f"{node['endpoint']}/api/federation/results/{task_id}",
                    headers={"X-Federation-Key": node["api_key"]},
                )
                if r.status_code == 200:
                    data = r.json()
                    data["node_id"] = node["id"]
                    data["node_name"] = node["name"]
                    collected.append(data)
            except Exception as e:
                collected.append({"node_id": node["id"], "error": str(e)})

    merged = _merge_results(collected)
    task["collected_results"] = collected
    task["merged_results"] = merged
    task["status"] = "completed"
    _save_federation(fed)
    return {"task_id": task_id, "results": merged, "node_results": collected}


def _merge_results(results: list) -> dict:
    """Deduplicate and merge scan results from multiple nodes."""
    merged = {"findings": [], "subdomains": set(), "open_ports": [], "errors": []}
    seen_findings = set()

    for r in results:
        if "error" in r:
            merged["errors"].append(r["error"])
            continue
        for finding in r.get("findings", []):
            key = f"{finding.get('vuln_type')}:{finding.get('url')}:{finding.get('parameter')}"
            if key not in seen_findings:
                seen_findings.add(key)
                finding["source_node"] = r.get("node_id")
                merged["findings"].append(finding)
        for sub in r.get("subdomains", []):
            merged["subdomains"].add(sub)
        merged["open_ports"].extend(r.get("open_ports", []))

    merged["subdomains"] = list(merged["subdomains"])
    merged["total_findings"] = len(merged["findings"])
    return merged


def list_nodes() -> list:
    return _load_federation().get("nodes", [])


def list_tasks() -> list:
    return _load_federation().get("tasks", [])


def get_this_node() -> Optional[dict]:
    return _load_federation().get("this_node")


def remove_node(node_id: str) -> dict:
    fed = _load_federation()
    before = len(fed["nodes"])
    fed["nodes"] = [n for n in fed["nodes"] if n["id"] != node_id]
    if len(fed["nodes"]) == before:
        return {"error": f"Node {node_id} not found"}
    _save_federation(fed)
    return {"removed": node_id}
