#!/usr/bin/env python3
"""Loopback-only HTTP Upgrade to Dropbear TCP proxy.

This is intentionally not exposed directly to the Internet. Nginx terminates
HTTP/TLS and forwards only to 127.0.0.1:2082.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import select
import socket
import socketserver
import threading
import time
from typing import Final

LISTEN_HOST: Final = "127.0.0.1"
LISTEN_PORT: Final = 2082
TARGET_HOST: Final = "127.0.0.1"
TARGET_PORT: Final = 109
MAX_HEADER: Final = 16 * 1024
HEADER_TIMEOUT: Final = 10
IDLE_TIMEOUT: Final = 3600
MAX_CONNECTIONS: Final = 200
GUID: Final = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

LOG = logging.getLogger("abdulbasit-ws")
SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)


def recv_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    sock.settimeout(HEADER_TIMEOUT)
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Client closed before headers completed")
        data.extend(chunk)
        if len(data) > MAX_HEADER:
            raise ValueError("Request headers are too large")
    header, remainder = bytes(data).split(b"\r\n\r\n", 1)
    return header, remainder


def parse_request(raw_header: bytes) -> tuple[str, dict[str, str]]:
    try:
        text = raw_header.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid HTTP headers") from exc
    lines = text.split("\r\n")
    if not lines:
        raise ValueError("Missing request line")
    parts = lines[0].split()
    if len(parts) != 3 or parts[0] not in {"GET", "CONNECT"} or not parts[2].startswith("HTTP/1."):
        raise ValueError("Only HTTP GET/CONNECT upgrade requests are accepted")
    if len(parts[1]) > 2048 or any(ord(ch) < 32 for ch in parts[1]):
        raise ValueError("Invalid request target")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ValueError("Malformed HTTP header")
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        if not name or "\x00" in value:
            raise ValueError("Malformed HTTP header")
        if name not in headers:
            headers[name] = value

    upgrade = headers.get("upgrade", "").lower()
    connection_tokens = {token.strip().lower() for token in headers.get("connection", "").split(",")}
    if upgrade != "websocket" or "upgrade" not in connection_tokens:
        raise ValueError("A WebSocket Upgrade request is required")
    if headers.get("content-length", "0") not in {"", "0"}:
        raise ValueError("Request bodies are not accepted")
    return parts[1], headers


def client_ip(peer_ip: str, headers: dict[str, str]) -> str:
    # X-Forwarded-For is trusted only because the listener is loopback-only and
    # therefore reachable solely through local Nginx.
    candidate = headers.get("x-forwarded-for", headers.get("x-real-ip", peer_ip)).split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return peer_ip


def switching_protocols(headers: dict[str, str]) -> bytes:
    lines = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade"]
    key = headers.get("sec-websocket-key")
    if key:
        digest = hashlib.sha1((key + GUID).encode("ascii", errors="strict")).digest()
        lines.append(f"Sec-WebSocket-Accept: {base64.b64encode(digest).decode('ascii')}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    last_activity = time.monotonic()
    for sock in sockets:
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    while True:
        timeout = max(0.0, IDLE_TIMEOUT - (time.monotonic() - last_activity))
        if timeout == 0:
            return
        readable, _, exceptional = select.select(sockets, [], sockets, min(timeout, 30.0))
        if exceptional:
            return
        if not readable:
            continue
        for source in readable:
            destination = right if source is left else left
            try:
                payload = source.recv(65536)
            except BlockingIOError:
                continue
            if not payload:
                return
            destination.sendall(payload)
            last_activity = time.monotonic()


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        if not SLOTS.acquire(blocking=False):
            self.request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            return
        target: socket.socket | None = None
        try:
            header, remainder = recv_headers(self.request)
            _path, headers = parse_request(header)
            real_ip = client_ip(self.client_address[0], headers)
            target = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
            self.request.sendall(switching_protocols(headers))
            if remainder:
                target.sendall(remainder)
            LOG.info("Tunnel opened for client_ip=%s", real_ip)
            relay(self.request, target)
        except (ConnectionError, OSError, ValueError) as exc:
            LOG.warning("Rejected/closed tunnel from %s: %s", self.client_address[0], exc)
            try:
                self.request.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        finally:
            if target is not None:
                try:
                    target.close()
                except OSError:
                    pass
            SLOTS.release()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with Server((LISTEN_HOST, LISTEN_PORT), Handler) as server:
        LOG.info("Listening on %s:%d and forwarding to %s:%d", LISTEN_HOST, LISTEN_PORT, TARGET_HOST, TARGET_PORT)
        server.serve_forever(poll_interval=0.5)
