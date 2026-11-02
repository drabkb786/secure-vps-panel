#!/usr/bin/env python3
"""Small JSON-over-UNIX-socket client used by the menu and Telegram bot."""
from __future__ import annotations

import json
import socket
from typing import Any

from common import SOCKET_PATH

MAX_RESPONSE = 1024 * 1024


def request(command: str, **params: Any) -> dict[str, Any]:
    payload = json.dumps({"command": command, "params": params}, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(payload) > (512 * 1024 if command == "backup_restore" else 16 * 1024):
        raise RuntimeError("Request is too large")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(240)
        sock.connect(str(SOCKET_PATH))
        sock.sendall(payload)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE:
                raise RuntimeError("Panel daemon response is too large")
            chunks.append(chunk)
            if b"\n" in chunk:
                break
    raw = b"".join(chunks).split(b"\n", 1)[0]
    response = json.loads(raw.decode("utf-8"))
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error", "Unknown panel daemon error")))
    return response
