"""WebSocket fan-out of new scan results to dashboards."""
import asyncio
import json
from typing import Set

from fastapi import WebSocket


class LiveHub:
    def __init__(self) -> None:
        self.clients: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def broadcast(self, payload: dict) -> None:
        message = json.dumps(payload, default=str)
        dead = []
        for ws in list(self.clients):
            try:
                await asyncio.wait_for(ws.send_text(message), timeout=2)
            except Exception:  # noqa: BLE001 — drop any client that can't keep up
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


hub = LiveHub()
