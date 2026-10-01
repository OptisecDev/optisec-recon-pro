"""Tests for the VPN server-key lazy-generation fix: before this fix,
add_peer() shipped a client config whose [Peer] PublicKey was the literal
string "SERVER_PUBLIC_KEY" whenever no admin had hit "Generate Server
Config" first -- a silently broken config an admin could hand to a real
device. add_peer() must now generate (and persist) the server keypair on
first use, the same way generate_server_config() does, so the client
config always carries a real Curve25519 public key.

Mirrors tests/test_vpn_peer_name_path_traversal.py's convention:
monkeypatch.chdir(tmp_path) for filesystem isolation, call module
functions directly.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.vpn.wireguard as wireguard


class TestAddPeerNeverEmitsPlaceholderKey:
    def test_first_peer_with_no_server_keys_gets_a_real_public_key(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(wireguard, "_load_peers", lambda: [])
        saved = {}
        monkeypatch.setattr(wireguard, "_save_peers", lambda peers: saved.setdefault("peers", peers))

        result = wireguard.add_peer(name="laptop", endpoint="vpn.example.com")

        assert "error" not in result
        assert "SERVER_PUBLIC_KEY" not in result["config"]
        server_pub_file = tmp_path / "data" / "wireguard" / "server_public.key"
        server_priv_file = tmp_path / "data" / "wireguard" / "server_private.key"
        assert server_pub_file.exists()
        assert server_priv_file.exists()
        real_pub = server_pub_file.read_text().strip()
        assert real_pub and real_pub != "SERVER_PUBLIC_KEY"
        assert f"PublicKey = {real_pub}" in result["config"]

    def test_server_keys_generated_once_are_reused_by_later_peers(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        peers_state = []
        monkeypatch.setattr(wireguard, "_load_peers", lambda: list(peers_state))
        monkeypatch.setattr(wireguard, "_save_peers", lambda peers: peers_state.extend(peers))

        first = wireguard.add_peer(name="laptop", endpoint="vpn.example.com")
        peers_state.clear()
        peers_state.append({
            "name": "laptop", "ip": first["ip"], "public_key": first["public_key"],
            "private_key": "x", "psk": "x", "created_at": "x",
            "last_handshake": None, "rx_bytes": 0, "tx_bytes": 0,
        })
        second = wireguard.add_peer(name="phone", endpoint="vpn.example.com")

        first_server_pub = first["config"].split("PublicKey = ")[1].split("\n")[0]
        second_server_pub = second["config"].split("PublicKey = ")[1].split("\n")[0]
        assert first_server_pub == second_server_pub

    def test_generate_server_config_reuses_keys_created_by_add_peer(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(wireguard, "_load_peers", lambda: [])
        monkeypatch.setattr(wireguard, "_save_peers", lambda peers: None)

        peer_result = wireguard.add_peer(name="laptop", endpoint="vpn.example.com")
        peer_server_pub = peer_result["config"].split("PublicKey = ")[1].split("\n")[0]

        server_result = wireguard.generate_server_config(endpoint="vpn.example.com")

        assert server_result["public_key"] == peer_server_pub

    def test_get_or_create_server_keys_is_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        priv1, pub1 = wireguard._get_or_create_server_keys()
        priv2, pub2 = wireguard._get_or_create_server_keys()

        assert (priv1, pub1) == (priv2, pub2)
