from __future__ import annotations

import sys
import socket
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ws_proxy import parse_request, switching_protocols, relay  # noqa: E402


def test_valid_upgrade() -> None:
    raw = (
        b"GET / HTTP/1.1\r\n"
        b"Host: vpn.example.com\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: keep-alive, Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    )
    path, headers = parse_request(raw)
    assert path == "/"
    response = switching_protocols(headers)
    assert b"101 Switching Protocols" in response
    assert b"Sec-WebSocket-Accept:" in response


def test_reject_non_upgrade() -> None:
    with pytest.raises(ValueError):
        parse_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n")


def test_reject_body() -> None:
    with pytest.raises(ValueError):
        parse_request(
            b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 5\r\n"
        )


def test_relay_preserves_large_stream_under_backpressure_and_half_close():
    client, left = socket.socketpair()
    right, target = socket.socketpair()
    client.settimeout(5); target.settimeout(5)
    payload = bytes(range(256)) * 16384
    errors = []
    def worker():
        try:
            relay(left, right)
        except Exception as exc:
            errors.append(exc)
        finally:
            left.close(); right.close()
    def sender():
        client.sendall(payload); client.shutdown(socket.SHUT_WR)
    relay_thread = threading.Thread(target=worker, daemon=True)
    send_thread = threading.Thread(target=sender, daemon=True)
    relay_thread.start(); send_thread.start()
    try:
        received = bytearray()
        while True:
            chunk = target.recv(8192)
            if not chunk: break
            received.extend(chunk)
        assert bytes(received) == payload
        target.sendall(b"reply-after-client-half-close")
        target.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = client.recv(8192)
            if not chunk: break
            response.extend(chunk)
        assert bytes(response) == b"reply-after-client-half-close"
        assert not errors
    finally:
        client.close(); target.close(); send_thread.join(timeout=5); relay_thread.join(timeout=5)
