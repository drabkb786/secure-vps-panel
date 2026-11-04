#!/usr/bin/env python3
"""Small JSON-over-UNIX-socket client used by the menu and Telegram bot."""
from __future__ import annotations

import errno
import json
import socket
import time
from typing import Any

from common import SOCKET_PATH

MAX_RESPONSE = 1024 * 1024
CONNECT_WAIT = 3.0
CONNECT_POLL = .05


class PanelNotReady(RuntimeError):
    pass


def connected_socket(wait: float) -> socket.socket:
    """Retry only before a connection exists, never after sending a command."""
    deadline = time.monotonic() + wait
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PanelNotReady(f'Panel daemon socket not ready: {SOCKET_PATH}; inspect journalctl -u abdulbasit-paneld')
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer.settimeout(min(1.0, remaining))
            peer.connect(str(SOCKET_PATH))
            return peer
        except OSError as exc:
            peer.close()
            if exc.errno not in (errno.ENOENT, errno.ECONNREFUSED):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PanelNotReady(f'Panel daemon socket not ready: {SOCKET_PATH}; inspect journalctl -u abdulbasit-paneld') from exc
            time.sleep(min(CONNECT_POLL, remaining))
        except BaseException:
            peer.close()
            raise


def exchange(command: str, params: dict[str, Any], *, response_timeout: float, connect_wait: float) -> dict[str, Any]:
    payload = json.dumps({"command": command, "params": params}, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(payload) > (512 * 1024 if command == "backup_restore" else 16 * 1024):
        raise RuntimeError("Request is too large")

    with connected_socket(connect_wait) as sock:
        sock.settimeout(response_timeout)
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
    if not raw:
        raise PanelNotReady('Panel daemon closed without a reply; the command was not replayed. Check its journal before retrying a change.')
    response = json.loads(raw.decode("utf-8"))
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error", "Unknown panel daemon error")))
    return response


def request(command: str, **params: Any) -> dict[str, Any]:
    return exchange(command, params, response_timeout=240, connect_wait=CONNECT_WAIT)


def wait_ready(timeout: float = 10) -> None:
    """Confirm an actual bounded, read-only RPC after a service restart."""
    if timeout <= 0:
        raise ValueError('Readiness timeout must be positive')
    exchange('web_revision', {}, response_timeout=min(2.0, timeout), connect_wait=timeout)
