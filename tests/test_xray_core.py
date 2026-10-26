"""Optional real-core tests. Set XRAY_TEST_BINARY to a checksum-verified Xray binary."""
from __future__ import annotations

import json
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time
import uuid
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from xray_manager import DEFAULT_DNS, PROTOCOLS, client_config, server_config

CORE = os.environ.get("XRAY_TEST_BINARY", "")
pytestmark = pytest.mark.skipif(not CORE, reason="XRAY_TEST_BINARY is not set")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def record():
    return {"name": "real_core_test", "uuid": str(uuid.uuid4()), "trojan_password": uuid.uuid4().hex,
            "protocols": list(PROTOCOLS), "enabled": True, "expiry": (date.today() + timedelta(days=1)).isoformat()}


def start_core(path: Path):
    log = path.with_suffix(".log").open("w+")
    proc = subprocess.Popen([CORE, "run", "-config", str(path)], stdout=log, stderr=log)
    return proc, log


def wait_port(port, process):
    for _ in range(120):
        if process.poll() is not None:
            raise AssertionError("Xray exited before opening its listener")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                return
        except OSError:
            time.sleep(.025)
    raise AssertionError("Xray listener did not become ready")


def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise AssertionError("Connection closed unexpectedly")
        data += chunk
    return data


def test_generated_configs_accepted_by_real_xray(tmp_path):
    row = record()
    cases = {"server": server_config({"dns": DEFAULT_DNS}, [row]), "no-accounts": server_config({"dns": DEFAULT_DNS}, [])}
    cases.update({protocol: client_config(protocol, row, "vpn.example.com", DEFAULT_DNS) for protocol in PROTOCOLS})
    for name, config in cases.items():
        path = tmp_path / f"{name}.json"; path.write_text(json.dumps(config))
        result = subprocess.run([CORE, "run", "-test", "-config", str(path)], capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr


def test_real_vless_vmess_trojan_over_verified_tls_websocket(tmp_path):
    """Exercise real SOCKS -> Xray -> TLS/WS -> Xray -> local HTTP for all protocols.

    The TLS bridge is a fixture, not Nginx. Only this test config permits its
    loopback HTTP destination; production profiles keep private targets blocked.
    """
    row = record(); server_cfg = server_config({"dns": DEFAULT_DNS}, [row])
    server_cfg["log"]["loglevel"] = "debug"
    ports = {path: free_port() for _, path in PROTOCOLS.values()}
    for inbound in server_cfg["inbounds"]:
        inbound["port"] = ports[inbound["streamSettings"]["wsSettings"]["path"]]

    class HTTPFixture(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            body = b"NOWAY verified transport test"
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    http = ThreadingHTTPServer(("127.0.0.1", 0), HTTPFixture)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    server_cfg["routing"]["rules"].insert(0, {"type": "field", "ip": ["127.0.0.1"], "port": str(http.server_port), "outboundTag": "direct"})
    server_cfg["outbounds"][0]["settings"]["finalRules"] = [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": str(http.server_port)}]

    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=vpn.example.com", "-addext", "subjectAltName=DNS:vpn.example.com"], check=True, capture_output=True, timeout=20)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)

    class Bridge(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with context.wrap_socket(self.request, server_side=True) as secure:
                    secure.settimeout(5); header = b""
                    while b"\r\n\r\n" not in header:
                        part = secure.recv(4096)
                        if not part: return
                        header += part
                        if len(header) > 16384: return
                    path = header.split(b" ")[1].decode().split("?")[0]
                    with socket.create_connection(("127.0.0.1", ports[path]), timeout=5) as upstream:
                        upstream.sendall(header)
                        def pipe(source, target):
                            try:
                                while True:
                                    payload = source.recv(65536)
                                    if not payload: break
                                    target.sendall(payload)
                            except OSError: pass
                        forward = threading.Thread(target=pipe, args=(secure, upstream), daemon=True); forward.start()
                        pipe(upstream, secure)
            except (OSError, KeyError): pass
    class BridgeServer(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True
    tls = BridgeServer(("127.0.0.1", 0), Bridge)
    threading.Thread(target=tls.serve_forever, daemon=True).start()
    path = tmp_path / "server.json"; path.write_text(json.dumps(server_cfg))
    server_proc, server_log = start_core(path)
    try:
        wait_port(next(iter(ports.values())), server_proc)
        for protocol in PROTOCOLS:
            cfg = client_config(protocol, row, "vpn.example.com", DEFAULT_DNS)
            cfg["log"]["loglevel"] = "debug"
            proxy = cfg["outbounds"][0]; proxy["streamSettings"]["tlsSettings"]["certificates"] = [{"certificateFile": str(cert), "usage": "verify"}]
            endpoint = proxy["settings"]["servers" if protocol == "trojan" else "vnext"][0]
            endpoint.update({"address": "127.0.0.1", "port": tls.server_address[1]})
            port = free_port(); cfg["inbounds"][0]["port"] = port
            config_path = tmp_path / f"{protocol}-client.json"; config_path.write_text(json.dumps(cfg))
            proc, log = start_core(config_path)
            try:
                wait_port(port, proc)
                with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
                    sock.sendall(b"\x05\x01\x00"); assert read_exact(sock, 2) == b"\x05\x00"
                    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", http.server_port))
                    answer = read_exact(sock, 4); assert answer[:2] == b"\x05\x00", (protocol, answer)
                    read_exact(sock, 6 if answer[3] == 1 else 18)
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: test.local\r\n\r\n")
                    response = b""
                    while b"NOWAY verified transport test" not in response:
                        data = sock.recv(65536)
                        if not data: break
                        response += data
                    assert b"NOWAY verified transport test" in response, protocol
            finally:
                proc.terminate(); proc.wait(timeout=5); log.close()
    finally:
        server_proc.terminate(); server_proc.wait(timeout=5); server_log.close()
        tls.shutdown(); tls.server_close(); http.shutdown(); http.server_close()
