from typing import Dict, List
from fastapi import WebSocket

MAX_CONNECTIONS_PER_USER = 3


class ConnectionManager:
    def __init__(self):
        self.connections: Dict[str, List[WebSocket]] = {}
        self.user_connections: Dict[int, List[WebSocket]] = {}

    def user_connection_count(self, user_id: int) -> int:
        return len(self.user_connections.get(user_id, []))

    def has_capacity(self, user_id: int) -> bool:
        return self.user_connection_count(user_id) < MAX_CONNECTIONS_PER_USER

    async def connect(self, scan_id: str, user_id: int, ws: WebSocket):
        await ws.accept()
        self.connections.setdefault(scan_id, []).append(ws)
        self.user_connections.setdefault(user_id, []).append(ws)

    def disconnect(self, scan_id: str, user_id: int, ws: WebSocket):
        conns = self.connections.get(scan_id, [])
        try:
            conns.remove(ws)
        except ValueError:
            pass
        if not conns:
            self.connections.pop(scan_id, None)

        user_conns = self.user_connections.get(user_id, [])
        try:
            user_conns.remove(ws)
        except ValueError:
            pass
        if not user_conns:
            self.user_connections.pop(user_id, None)

    async def broadcast(self, scan_id: str, data: dict):
        conns = list(self.connections.get(scan_id, []))
        dead = []
        for ws in conns:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect_dead(scan_id, ws)

    def disconnect_dead(self, scan_id: str, ws: WebSocket):
        """Drop a socket that failed mid-broadcast, without knowing its user_id."""
        conns = self.connections.get(scan_id, [])
        try:
            conns.remove(ws)
        except ValueError:
            pass
        if not conns:
            self.connections.pop(scan_id, None)
        for user_id, user_conns in list(self.user_connections.items()):
            if ws in user_conns:
                user_conns.remove(ws)
                if not user_conns:
                    self.user_connections.pop(user_id, None)
                break


ws_manager = ConnectionManager()
