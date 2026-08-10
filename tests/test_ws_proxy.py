from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ws_proxy import parse_request, switching_protocols  # noqa: E402


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

