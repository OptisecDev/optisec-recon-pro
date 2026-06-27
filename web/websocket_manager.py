from typing import Dict, List
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, scan_id: str, ws: WebSocket):
        await ws.accept()
        self.connections.setdefault(scan_id, []).append(ws)

    def disconnect(self, scan_id: str, ws: WebSocket):
        conns = self.connections.get(scan_id, [])
        try:
            conns.remove(ws)
        except ValueError:
            pass
        if not conns:
            self.connections.pop(scan_id, None)

    async def broadcast(self, scan_id: str, data: dict):
        conns = list(self.connections.get(scan_id, []))
        dead = []
        for ws in conns:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)


ws_manager = ConnectionManager()
