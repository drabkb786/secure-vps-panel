#!/usr/bin/env python3
"""OpenSSH ProxyCommand adapter: verified WSS and real RFC6455 binary frames.

Dependency: python -m pip install wsproto==1.2.0
Example: ssh -o 'ProxyCommand=python3 ssh-ws-client.py --host cdn.example.com' user@origin.example.com
stdout is exclusively the SSH byte stream. No passwords or origin secrets needed.
"""
import argparse
import ipaddress
import os
import select
import socket
import ssl
import sys
import threading
import time
from wsproto import WSConnection, ConnectionType
from wsproto.events import Request, AcceptConnection, RejectConnection, BytesMessage, Ping, Pong, CloseConnection


def connect(host, port, path, address=None):
    if any(ch in host + path for ch in "\r\n\x00") or not path.startswith("/"):
        raise ValueError("Invalid host/path")
    if address:
        ipaddress.ip_address(address)
    raw = socket.create_connection((address or host, port), timeout=10)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    try:
        peer = context.wrap_socket(raw, server_hostname=host)
        ws = WSConnection(ConnectionType.CLIENT)
        peer.sendall(ws.send(Request(host=host, target=path)))
        pending = []
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            data = peer.recv(65536)
            if not data:
                raise OSError("CDN closed before the WebSocket handshake")
            ws.receive_data(data)
            accepted = False
            for event in ws.events():
                if isinstance(event, AcceptConnection):
                    accepted = True
                elif isinstance(event, RejectConnection):
                    raise OSError(f"WebSocket rejected: HTTP {event.status_code}")
                else:
                    pending.append(event)
            if accepted:
                return peer, ws, pending
        raise OSError("WebSocket handshake timed out")
    except Exception:
        raw.close()
        raise


def pump(peer, ws, pending=(), source=None, sink=None):
    source = source or sys.stdin.buffer
    sink = sink or sys.stdout.buffer
    lock = threading.Lock()
    stopped = threading.Event()
    errors = []

    def send(event):
        with lock:
            peer.sendall(ws.send(event))

    def upload():
        try:
            read = getattr(source, "read1", source.read)
            while not stopped.is_set():
                data = read(65536)
                if not data:
                    break
                send(BytesMessage(data=data))
        except (OSError, ValueError) as exc:
            errors.append(exc)
        finally:
            stopped.set()
            try:
                peer.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def events(items):
        for event in items:
            if isinstance(event, BytesMessage):
                sink.write(event.data); sink.flush()
            elif isinstance(event, Ping):
                send(event.response())
            elif isinstance(event, CloseConnection):
                stopped.set()
                return False
        return True

    thread = threading.Thread(target=upload, daemon=True)
    thread.start()
    peer.settimeout(30)
    last_ping = time.monotonic()
    try:
        if not events(pending):
            return
        while True:
            try:
                buffered = getattr(peer, "pending", lambda: 0)()
                if not buffered and not select.select([peer], [], [], 1)[0]:
                    if stopped.is_set():
                        break
                    if time.monotonic() - last_ping >= 25:
                        send(Ping(payload=b"noway")); last_ping = time.monotonic()
                    continue
                data = peer.recv(65536)
            except socket.timeout:
                if stopped.is_set():
                    break
                if time.monotonic() - last_ping >= 25:
                    send(Ping(payload=b"noway")); last_ping = time.monotonic()
                continue
            if not data:
                break
            with lock:
                ws.receive_data(data)
                received = list(ws.events())
            if not events(received):
                break
    finally:
        stopped.set()
        peer.close()
    if errors:
        raise OSError("SSH upload closed unexpectedly") from errors[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="CDN hostname used for Host, SNI and TLS verification")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/ssh/ws")
    parser.add_argument("--address", help="Optional edge IP; never replaces TLS hostname")
    args = parser.parse_args()
    if os.name == "nt":
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    try:
        pump(*connect(args.host, args.port, args.path, args.address))
    except Exception as exc:
        print(f"WSS adapter: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
