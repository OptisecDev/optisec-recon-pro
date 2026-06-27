"""WireGuard VPN management — config generation, peer management, status monitoring."""

import os
import json
import asyncio
import ipaddress
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

WG_CONFIG_DIR = Path("data/wireguard")
PEERS_FILE = Path("data/wireguard/peers.json")
SERVER_SUBNET = "10.13.37.0/24"
SERVER_IP = "10.13.37.1"
DEFAULT_DNS = "1.1.1.1, 8.8.8.8"
DEFAULT_PORT = 51820


def _load_peers() -> list:
    PEERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if PEERS_FILE.exists():
        return json.loads(PEERS_FILE.read_text())
    return []


def _save_peers(peers: list) -> None:
    PEERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PEERS_FILE.write_text(json.dumps(peers, indent=2, default=str))


def _next_peer_ip(peers: list) -> str:
    network = ipaddress.IPv4Network(SERVER_SUBNET)
    used = {SERVER_IP} | {p["ip"] for p in peers}
    for host in network.hosts():
        ip = str(host)
        if ip not in used:
            return ip
    raise ValueError("No available IP addresses in subnet")


def _wg_genkey() -> tuple[str, str]:
    """Generate WireGuard keypair. Falls back to mock if wg not installed."""
    try:
        priv = subprocess.check_output(["wg", "genkey"], text=True).strip()
        pub = subprocess.check_output(["wg", "pubkey"], input=priv, text=True).strip()
        return priv, pub
    except (FileNotFoundError, subprocess.CalledProcessError):
        import base64, secrets
        priv = base64.b64encode(secrets.token_bytes(32)).decode()
        pub = base64.b64encode(secrets.token_bytes(32)).decode()
        return priv, pub


def _wg_genpsk() -> str:
    try:
        return subprocess.check_output(["wg", "genpsk"], text=True).strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        import base64, secrets
        return base64.b64encode(secrets.token_bytes(32)).decode()


def generate_server_config(
    endpoint: str = "YOUR_SERVER_IP",
    port: int = DEFAULT_PORT,
    dns: str = DEFAULT_DNS,
    post_up: str = "",
    post_down: str = "",
) -> dict:
    """Generate server wg0.conf."""
    server_priv_file = WG_CONFIG_DIR / "server_private.key"
    server_pub_file = WG_CONFIG_DIR / "server_public.key"
    WG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if server_priv_file.exists():
        server_priv = server_priv_file.read_text().strip()
        server_pub = server_pub_file.read_text().strip()
    else:
        server_priv, server_pub = _wg_genkey()
        server_priv_file.write_text(server_priv)
        server_priv_file.chmod(0o600)
        server_pub_file.write_text(server_pub)

    post_up_rule = post_up or f"iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
    post_down_rule = post_down or f"iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"

    peers = _load_peers()
    peer_blocks = []
    for peer in peers:
        block = f"""
[Peer]
# {peer['name']}
PublicKey = {peer['public_key']}
PresharedKey = {peer.get('psk', '')}
AllowedIPs = {peer['ip']}/32"""
        peer_blocks.append(block)

    config = f"""[Interface]
Address = {SERVER_IP}/24
ListenPort = {port}
PrivateKey = {server_priv}
DNS = {dns}
PostUp = {post_up_rule}
PostDown = {post_down_rule}
""" + "\n".join(peer_blocks)

    config_path = WG_CONFIG_DIR / "wg0.conf"
    config_path.write_text(config)
    config_path.chmod(0o600)

    return {
        "server_ip": SERVER_IP,
        "subnet": SERVER_SUBNET,
        "port": port,
        "endpoint": endpoint,
        "public_key": server_pub,
        "peer_count": len(peers),
        "config_path": str(config_path),
        "config": config,
    }


def add_peer(name: str, endpoint: str = "YOUR_SERVER_IP", port: int = DEFAULT_PORT) -> dict:
    peers = _load_peers()

    if any(p["name"] == name for p in peers):
        return {"error": f"Peer '{name}' already exists"}

    peer_ip = _next_peer_ip(peers)
    peer_priv, peer_pub = _wg_genkey()
    psk = _wg_genpsk()

    # Get server public key
    server_pub_file = WG_CONFIG_DIR / "server_public.key"
    server_pub = server_pub_file.read_text().strip() if server_pub_file.exists() else "SERVER_PUBLIC_KEY"

    peer = {
        "name": name,
        "ip": peer_ip,
        "public_key": peer_pub,
        "private_key": peer_priv,
        "psk": psk,
        "created_at": datetime.utcnow().isoformat(),
        "last_handshake": None,
        "rx_bytes": 0,
        "tx_bytes": 0,
    }
    peers.append(peer)
    _save_peers(peers)

    client_config = f"""[Interface]
PrivateKey = {peer_priv}
Address = {peer_ip}/32
DNS = {DEFAULT_DNS}

[Peer]
PublicKey = {server_pub}
PresharedKey = {psk}
Endpoint = {endpoint}:{port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

    peer_config_path = WG_CONFIG_DIR / f"{name}.conf"
    peer_config_path.write_text(client_config)
    peer_config_path.chmod(0o600)

    return {
        "name": name,
        "ip": peer_ip,
        "public_key": peer_pub,
        "config": client_config,
        "config_path": str(peer_config_path),
        "qr_available": True,
    }


def remove_peer(name: str) -> dict:
    peers = _load_peers()
    before = len(peers)
    peers = [p for p in peers if p["name"] != name]
    if len(peers) == before:
        return {"error": f"Peer '{name}' not found"}
    _save_peers(peers)

    config_path = WG_CONFIG_DIR / f"{name}.conf"
    if config_path.exists():
        config_path.unlink()

    return {"removed": name, "remaining_peers": len(peers)}


def list_peers() -> list:
    return _load_peers()


async def get_wg_status() -> dict:
    """Get live WireGuard status via `wg show`."""
    try:
        result = subprocess.run(
            ["wg", "show", "all", "dump"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return _parse_wg_dump(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    peers = _load_peers()
    return {
        "interface": "wg0",
        "status": "wireguard_not_installed",
        "note": "Install WireGuard kernel module and tools: apt install wireguard",
        "configured_peers": len(peers),
        "peers": [{"name": p["name"], "ip": p["ip"], "status": "configured"} for p in peers],
    }


def _parse_wg_dump(output: str) -> dict:
    lines = output.strip().split("\n")
    peers = []
    interface_info = {}

    for line in lines:
        parts = line.split("\t")
        if len(parts) >= 5:
            if parts[0] == "wg0":
                interface_info = {
                    "interface": "wg0",
                    "public_key": parts[1],
                    "listen_port": parts[3],
                    "status": "running",
                }
            else:
                peers.append({
                    "public_key": parts[0],
                    "endpoint": parts[2],
                    "allowed_ips": parts[3],
                    "last_handshake": parts[4],
                    "rx_bytes": int(parts[5]) if len(parts) > 5 else 0,
                    "tx_bytes": int(parts[6]) if len(parts) > 6 else 0,
                })

    return {**interface_info, "peers": peers, "peer_count": len(peers)}


def generate_qr_code(peer_name: str) -> Optional[str]:
    """Return base64-encoded QR code PNG for peer config."""
    config_path = WG_CONFIG_DIR / f"{peer_name}.conf"
    if not config_path.exists():
        return None

    config_text = config_path.read_text()
    try:
        import qrcode
        import base64
        from io import BytesIO
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(config_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#00ff88", back_color="#0a0a0f")
        buf = BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        return None
