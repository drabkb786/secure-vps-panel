"""Real socket tests with an independent RFC 6455 client implementation."""
import base64
import os
import socket
import socketserver
import struct
import threading
from contextlib import contextmanager

import pytest
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

import ws_proxy as bridge


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(16384):
                self.request.sendall(data)
        except OSError:
            pass


@contextmanager
def running_server(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown(); server.server_close(); thread.join(3)


@pytest.fixture
def echo_bridge(monkeypatch):
    upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    upstream.daemon_threads = True
    with running_server(upstream) as target_port:
        monkeypatch.setattr(bridge, "TARGET_PORT", target_port)
        with running_server(bridge.Server(("127.0.0.1", 0), bridge.Handler)) as port:
            yield port


def ws_url(port):
    return f"ws://127.0.0.1:{port}/ssh/ws"


def test_binary_fragmentation_ping_and_large_roundtrip(echo_bridge):
    payload = bytes(range(256)) * 16384
    with connect(ws_url(echo_bridge), compression=None, proxy=None, max_size=None, subprotocols=["binary"]) as ws:
        assert ws.subprotocol == "binary"
        assert ws.ping(b"alive").wait(2)
        sender = threading.Thread(target=lambda: ws.send([payload[i:i+16384] for i in range(0, len(payload), 16384)]), daemon=True)
        sender.start()
        received = bytearray()
        while len(received) < len(payload):
            received.extend(ws.recv(timeout=5))
        sender.join(3)
        assert not sender.is_alive()
        assert bytes(received) == payload
        assert ws.ping(b"still-alive").wait(2)


def test_text_is_rejected_as_non_binary_ssh(echo_bridge):
    with connect(ws_url(echo_bridge), compression=None, proxy=None) as ws:
        ws.send("not an SSH byte stream")
        with pytest.raises(ConnectionClosed) as exc:
            ws.recv(timeout=3)
        assert exc.value.rcvd.code == 1003


def raw_handshake(port, path="/ssh/ws"):
    peer = socket.create_connection(("127.0.0.1", port), timeout=3)
    key = base64.b64encode(os.urandom(16)).decode()
    peer.sendall((f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                  f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    data = b""
    while b"\r\n\r\n" not in data:
        data += peer.recv(4096)
    assert data.startswith(b"HTTP/1.1 101 ")
    return peer


def test_unmasked_frame_gets_protocol_close_not_http_error(echo_bridge):
    with raw_handshake(echo_bridge) as peer:
        peer.sendall(b"\x82\x03bad")
        response = peer.recv(512)
        assert response[0] == 0x88
        assert struct.unpack("!H", response[2:4])[0] == 1002
        assert b"HTTP/1.1 400" not in response


@pytest.mark.parametrize("path", ["/", "/ssh/raw", "/cdn-cgi", "/ssh/ws?client=standard"])
def test_key_selects_binary_websocket_on_direct_routes(echo_bridge, path):
    with connect(f"ws://127.0.0.1:{echo_bridge}{path}", compression=None, proxy=None) as ws:
        ws.send(b"SSH-2.0-framed-test\r\n")
        assert ws.recv(timeout=3) == b"SSH-2.0-framed-test\r\n"
        assert ws.ping(b"alive").wait(2)


@pytest.mark.parametrize("method,version,path", [("GET", "1.1", "/"), ("GET", "1.1", "/cdn-cgi"), ("POST", "1.0", "/ssh/raw"),
    ("CONNECT", "1.1", "/ssh/raw?client=legacy"), ("HEAD", "1.0", "/ssh/raw"),
    ("OPTIONS", "1.1", "/ssh/raw"), ("GET", "1.1", "/ssh/ws")])
def test_legacy_without_key_preserves_coalesced_ssh_bytes(echo_bridge, method, version, path):
    payload = b"SSH-2.0-legacy-test\r\n"
    with socket.create_connection(("127.0.0.1", echo_bridge), timeout=3) as peer:
        peer.sendall(f"{method} {path} HTTP/{version}\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".encode() + payload)
        response = b""
        while b"\r\n\r\n" not in response:
            response += peer.recv(512)
        headers, echoed = response.split(b"\r\n\r\n", 1)
        assert headers.startswith(b"HTTP/1.1 101 ")
        while len(echoed) < len(payload): echoed += peer.recv(512)
        assert echoed == payload


def test_headers_split_across_tcp_reads_preserve_initial_ssh_data():
    chunks = iter([b"GET /ssh/", b"raw HTTP/1.1\r\nHost: localhost\r", b"\nUpgrade: websocket\r\nConnection: Up", b"grade\r\n\r\nSSH-2.0-client\r\n"])
    class Peer:
        def settimeout(self, value): pass
        def recv(self, size): return next(chunks)
    header, initial = bridge.recv_headers(Peer())
    assert bridge.parse_request(header)[0] == "/ssh/raw"
    assert initial == b"SSH-2.0-client\r\n"


@pytest.mark.parametrize("header", [
    b"Sec-WebSocket-Version: 12\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
    b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: short",
    b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nContent-Length: 0\r\nContent-Length: 8",
    b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nTransfer-Encoding: chunked",
])
def test_invalid_ws_handshake_never_connects_backend(header, monkeypatch):
    monkeypatch.setattr(bridge.socket, "create_connection", lambda *a, **kw: pytest.fail("Invalid handshake reached backend"))
    with running_server(bridge.Server(("127.0.0.1", 0), bridge.Handler)) as port:
        with socket.socket() as peer:
            peer.settimeout(3); peer.connect(("127.0.0.1", port))
            peer.sendall(b"GET /ssh/ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" + header + b"\r\n\r\n")
            assert peer.recv(512).startswith(b"HTTP/1.1 400 ")


def test_capacity_is_rejected_before_starting_another_handler(monkeypatch):
    slots = threading.BoundedSemaphore(1); slots.acquire()
    monkeypatch.setattr(bridge, "SLOTS", slots)
    monkeypatch.setattr(bridge.Handler, "handle", lambda _: pytest.fail("An overload handler was spawned"))
    with running_server(bridge.Server(("127.0.0.1", 0), bridge.Handler)) as port:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as peer:
            assert peer.recv(512).startswith(b"HTTP/1.1 503 ")


def test_pipelined_payload_is_not_counted_as_headers(monkeypatch):
    monkeypatch.setattr(bridge, "MAX_HEADER", 64)
    class Peer:
        def settimeout(self, value): pass
        def recv(self, size): return b"GET / HTTP/1.1\r\n\r\n" + b"x" * 100
    header, payload = bridge.recv_headers(Peer())
    assert header == b"GET / HTTP/1.1" and payload == b"x" * 100


def test_absolute_header_deadline(monkeypatch):
    clock = iter([0, 0, 6, 11])
    monkeypatch.setattr(bridge.time, "monotonic", lambda: next(clock))
    class SlowPeer:
        def settimeout(self, value): pass
        def recv(self, size): return b"x"
    with pytest.raises(TimeoutError):
        bridge.recv_headers(SlowPeer())


def test_frame_size_limit_closes_connection(echo_bridge, monkeypatch):
    monkeypatch.setattr(bridge, "MAX_MESSAGE", 8)
    with connect(ws_url(echo_bridge), compression=None, proxy=None) as ws:
        ws.send(b"larger than eight bytes")
        with pytest.raises(ConnectionClosed) as exc:
            ws.recv(timeout=3)
        assert exc.value.rcvd.code == 1009
