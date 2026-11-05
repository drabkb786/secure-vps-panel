#!/usr/bin/env python3
"""Loopback-only SSH bridge: legacy HTTP Upgrade and RFC 6455 binary WS.

This is intentionally not exposed directly to the Internet. Nginx terminates
HTTP/TLS and forwards only to 127.0.0.1:2082.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import re
import selectors
import socket
import socketserver
import threading
import time
from typing import Final
from urllib.parse import urlsplit
import gateway_identity
import ssh_identity

from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, BytesMessage, CloseConnection, Ping, Request, TextMessage
from wsproto.utilities import LocalProtocolError, RemoteProtocolError

LISTEN_HOST: Final = "127.0.0.1"
LISTEN_PORT: Final = 2082
TARGET_HOST: Final = "127.0.0.1"
TARGET_PORT: Final = 109
MAX_HEADER: Final = 16 * 1024
HEADER_TIMEOUT: Final = 10
IDLE_TIMEOUT: Final = 3600
MAX_CONNECTIONS: Final = 200
IO_CHUNK = 64 * 1024
TCP_NODELAY = True
MAX_PENDING: Final = 256 * 1024
MAX_MESSAGE: Final = 8 * 1024 * 1024
WS_PATH: Final = "/ssh/ws"
LEGACY_PATHS: Final = {"/", "/ssh/raw", "/cdn-cgi", "/cdn-cgi/"}
GUID: Final = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

LOG = logging.getLogger("abdulbasit-ws")
SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)


def recv_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    deadline = time.monotonic() + HEADER_TIMEOUT
    data = bytearray()
    while b"\r\n\r\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP header deadline exceeded")
        sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Client closed before headers completed")
        data.extend(chunk)
        end = data.find(b"\r\n\r\n")
        if (end if end >= 0 else len(data)) > MAX_HEADER:
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
    if (len(parts) != 3 or parts[0] not in {"GET", "POST", "CONNECT", "HEAD", "OPTIONS"}
            or parts[2] not in {"HTTP/1.0", "HTTP/1.1"}):
        raise ValueError("Use a supported HTTP/1.0 or HTTP/1.1 upgrade request")
    if len(parts[1]) > 2048 or any(ord(ch) < 32 for ch in parts[1]):
        raise ValueError("Invalid request target")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ValueError("Malformed HTTP header")
        name, value = line.split(":", 1)
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError("Invalid HTTP header name")
        name = name.lower()
        value = value.strip()
        if any(ord(ch) < 32 and ch != "\t" for ch in value) or "\x7f" in value:
            raise ValueError("Malformed HTTP header")
        if name in headers:
            raise ValueError("Duplicate HTTP headers are not accepted")
        headers[name] = value

    upgrade = headers.get("upgrade", "").lower()
    connection_tokens = {token.strip().lower() for token in headers.get("connection", "").split(",")}
    if upgrade != "websocket" or "upgrade" not in connection_tokens:
        raise ValueError("A WebSocket Upgrade request is required")
    if headers.get("content-length", "0") not in {"", "0"}:
        raise ValueError("Request bodies are not accepted")
    if "transfer-encoding" in headers:
        raise ValueError("Transfer encoding is not accepted")
    target = urlsplit(parts[1])
    if target.scheme or target.netloc or target.fragment or target.path not in LEGACY_PATHS | {WS_PATH}:
        raise ValueError("Use /ssh/ws for WebSocket or /cdn-cgi for raw Upgrade")
    if "sec-websocket-key" in headers:
        if parts[0] != "GET" or parts[2] != "HTTP/1.1" or headers.get("sec-websocket-version") != "13":
            raise ValueError("WebSocket requires HTTP/1.1 GET and version 13")
        try:
            key = base64.b64decode(headers.get("sec-websocket-key", ""), validate=True)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Invalid WebSocket key") from exc
        if len(key) != 16:
            raise ValueError("WebSocket key must contain 16 bytes")
        if not headers.get("host"):
            raise ValueError("WebSocket Host is required")
    elif "sec-websocket-version" in headers:
        raise ValueError("WebSocket version requires a WebSocket key")
    return target.path, headers


def tune_socket(peer: socket.socket) -> None:
    """Set transport options before either the HTTP reply or SSH banner flows."""
    peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, int(TCP_NODELAY))
    peer.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)


def client_ip(peer_ip: str, headers: dict[str, str]) -> str:
    # A public constant header is forgeable through a local SSH forward.
    if headers.get(gateway_identity.header_name().lower()) != "1":
        return peer_ip
    candidate = headers.get("x-forwarded-for", peer_ip)
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


def relay(left: socket.socket, right: socket.socket, initial: bytes = b"") -> None:
    sockets = [left, right]
    last_activity = time.monotonic()
    pending = {left: bytearray(), right: bytearray()}
    pending[right].extend(initial)
    reading = set(sockets)
    write_closed: set[socket.socket] = set()
    for sock in sockets:
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    with selectors.DefaultSelector() as selector:
        while reading or any(pending.values()):
            for sock in sockets:
                other = right if sock is left else left
                # Bound queued data and resume reads only after the peer drains it.
                events = selectors.EVENT_READ if sock in reading and len(pending[other]) < MAX_PENDING else 0
                if pending[sock]:
                    events |= selectors.EVENT_WRITE
                try:
                    selector.get_key(sock)
                    if events:
                        selector.modify(sock, events)
                    else:
                        selector.unregister(sock)
                except KeyError:
                    if events:
                        selector.register(sock, events)
                if sock not in reading and not pending[other] and other not in write_closed:
                    other.shutdown(socket.SHUT_WR)
                    write_closed.add(other)
            timeout = max(0.0, IDLE_TIMEOUT - (time.monotonic() - last_activity))
            if timeout == 0:
                return
            for key, events in selector.select(min(timeout, 30.0)):
                source = key.fileobj
                destination = right if source is left else left
                if events & selectors.EVENT_READ:
                    try:
                        payload = source.recv(65536)
                    except BlockingIOError:
                        payload = None
                    if payload == b"":
                        reading.discard(source)
                    elif payload:
                        pending[destination].extend(payload)
                        last_activity = time.monotonic()
                if events & selectors.EVENT_WRITE:
                    try:
                        sent = source.send(pending[source])
                    except BlockingIOError:
                        continue
                    if sent:
                        del pending[source][:sent]
                        last_activity = time.monotonic()


def relay_websocket(client: socket.socket, target: socket.socket, ws: WSConnection,
                    initial: bytes = b"") -> None:
    """Translate bounded binary frames; wsproto handles masking/control/close rules."""
    pending = {client: bytearray(), target: bytearray()}
    last_activity = time.monotonic()
    message_bytes = 0
    closing = False
    close_deadline = 0.0

    def close(code: int, reason: str = "") -> None:
        nonlocal closing, close_deadline
        if not closing:
            pending[client].extend(ws.send(CloseConnection(code=code, reason=reason)))
            closing = True
            close_deadline = time.monotonic() + 5

    def receive(data: bytes) -> None:
        nonlocal message_bytes, closing, close_deadline
        ws.receive_data(data)
        for event in ws.events():
            if isinstance(event, BytesMessage):
                if closing:
                    continue
                message_bytes += len(event.data)
                if message_bytes > MAX_MESSAGE:
                    close(1009, "Binary message too large")
                    continue
                pending[target].extend(event.data)
                if event.message_finished:
                    message_bytes = 0
            elif isinstance(event, TextMessage):
                close(1003, "SSH requires binary WebSocket messages")
            elif isinstance(event, Ping) and not closing:
                pending[client].extend(ws.send(event.response()))
            elif isinstance(event, CloseConnection):
                if not closing:
                    # 1006 is a local abnormal closure and must never go on wire.
                    code = event.code if event.code != 1006 else 1002
                    close(code, event.reason or "")
                closing = True
                close_deadline = time.monotonic() + 5
    for sock in (client, target):
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if initial:
        receive(initial)
    with selectors.DefaultSelector() as selector:
        while True:
            if closing and (not pending[client] or time.monotonic() >= close_deadline):
                return
            if time.monotonic() - last_activity >= IDLE_TIMEOUT:
                close(1001, "Idle timeout")
            for sock in (client, target):
                events = 0
                # Both queues must have room: ping replies are generated on reads too.
                if not closing and all(len(q) < MAX_PENDING for q in pending.values()):
                    events |= selectors.EVENT_READ
                if pending[sock] and (sock is client or not closing):
                    events |= selectors.EVENT_WRITE
                try:
                    selector.get_key(sock)
                    if events:
                        selector.modify(sock, events)
                    else:
                        selector.unregister(sock)
                except KeyError:
                    if events:
                        selector.register(sock, events)
            for key, events in selector.select(1):
                sock = key.fileobj
                if events & selectors.EVENT_READ:
                    try:
                        data = sock.recv(IO_CHUNK)
                    except BlockingIOError:
                        data = None
                    if data == b"":
                        if sock is client:
                            return
                        close(1000, "SSH connection closed")
                    elif data:
                        last_activity = time.monotonic()
                        if sock is client:
                            receive(data)
                        elif not closing:
                            pending[client].extend(ws.send(BytesMessage(data=data)))
                if events & selectors.EVENT_WRITE and pending[sock]:
                    try:
                        sent = sock.send(pending[sock])
                    except BlockingIOError:
                        continue
                    if sent:
                        del pending[sock][:sent]
                        last_activity = time.monotonic()


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        target: socket.socket | None = None
        peer_record = None
        upgraded = False
        response_status = b"400 Bad Request"
        try:
            header, remainder = recv_headers(self.request)
            path, headers = parse_request(header)
            ws = None
            if "sec-websocket-key" in headers:
                ws = WSConnection(ConnectionType.SERVER)
                ws.receive_data(header + b"\r\n\r\n")
                requests = list(ws.events())
                if len(requests) != 1 or not isinstance(requests[0], Request):
                    raise ValueError("Invalid WebSocket handshake")
                # Binary is compatible with websockify clients; no extension/compression.
                subprotocol = "binary" if "binary" in requests[0].subprotocols else None
            real_ip = client_ip(self.client_address[0], headers)
            response_status = b"502 Bad Gateway"
            target = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
            peer_record = ssh_identity.register(target, real_ip, headers.get(gateway_identity.header_name().lower()) == "1")
            for tcp in (self.request, target):
                tune_socket(tcp)
            response = ws.send(AcceptConnection(subprotocol=subprotocol)) if ws else switching_protocols(headers)
            self.request.sendall(response)
            upgraded = True
            LOG.info("SSH bridge mode=%s peer=%s forwarded_hint=%s", "websocket" if ws else "legacy", self.client_address[0], real_ip)
            if ws:
                relay_websocket(self.request, target, ws, remainder)
            else:
                relay(self.request, target, remainder)
        except (ConnectionError, OSError, ValueError, RuntimeError, LocalProtocolError, RemoteProtocolError) as exc:
            LOG.warning("Rejected/closed tunnel from %s: %s", self.client_address[0], exc)
            try:
                if not upgraded:
                    self.request.sendall(b"HTTP/1.1 " + response_status + b"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        finally:
            if peer_record is not None:
                try:
                    peer_record.unlink(missing_ok=True)
                except OSError:
                    LOG.warning("Could not remove closed gateway peer record")
            if target is not None:
                try:
                    target.close()
                except OSError:
                    pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def process_request(self, request, client_address):
        # Acquire before starting a thread, including slow/incomplete handshakes.
        if not SLOTS.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            SLOTS.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            SLOTS.release()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with Server((LISTEN_HOST, LISTEN_PORT), Handler) as server:
        LOG.info("Listening on %s:%d and forwarding to %s:%d", LISTEN_HOST, LISTEN_PORT, TARGET_HOST, TARGET_PORT)
        server.serve_forever(poll_interval=0.5)
