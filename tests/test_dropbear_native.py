"""Opt-in real Dropbear auth and forwarding through production Nginx routes.

Uses temporary keys and high loopback ports. Does not alter OS users, their
authorized_keys, installed services, firewall or public DNS.
"""
import base64
import os
import pwd
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

import paneld
import ws_proxy as bridge
from test_dropbear_transport import Echo, running_server
import socketserver

DROPBEAR = os.environ.get("DROPBEAR_TEST_BINARY", "")
DROPBEARKEY = os.environ.get("DROPBEARKEY_TEST_BINARY", "")
NGINX = os.environ.get("NGINX_TEST_BINARY", "")
pytestmark = pytest.mark.skipif(not (DROPBEAR and DROPBEARKEY and NGINX), reason="Native Dropbear/key/Nginx binaries not set")


@pytest.fixture
def keydir():
    # Upstream checks every ancestor: a path beneath world-writable /tmp is
    # intentionally rejected. Use a fresh private directory, never ~/.ssh.
    with tempfile.TemporaryDirectory(prefix=".noway-dropbear-test-", dir=Path.home()) as directory:
        yield Path(directory)


def free_port():
    with socket.socket() as peer:
        peer.bind(("127.0.0.1", 0))
        return peer.getsockname()[1]


def wait_port(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert process.poll() is None, "Native test service exited"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.03)
    pytest.fail("Native test listener did not open")


class WebSocketSocket:
    def __init__(self, ws):
        self.ws, self.buffer, self.timeout = ws, bytearray(), 10
        self._closed = False
    def settimeout(self, value): self.timeout = value
    def getpeername(self): return ("127.0.0.1", 443)
    def send(self, data):
        self.ws.send(bytes(data)); return len(data)
    def recv(self, size):
        if not self.buffer:
            try:
                self.buffer.extend(self.ws.recv(timeout=self.timeout))
            except TimeoutError as exc:
                raise socket.timeout() from exc
            except Exception:
                return b""
        data = bytes(self.buffer[:size]); del self.buffer[:size]
        return data
    def close(self):
        self._closed = True; self.ws.close()


@pytest.mark.parametrize("route", ["direct", "legacy", "wss"])
def test_real_dropbear_auth_forwarding_and_tunnel_only_policy(tmp_path, keydir, monkeypatch, route):
    import paramiko
    from websockets.sync.client import connect
    client_key = paramiko.RSAKey.generate(2048)
    authorized = keydir / "authorized_keys"
    authorized.write_text(client_key.get_name() + " " + client_key.get_base64() + " native-test\n")
    authorized.chmod(0o600)
    hostkey = tmp_path / "hostkey"
    result = subprocess.run([DROPBEARKEY, "-t", "ed25519", "-f", str(hostkey)], capture_output=True, text=True, check=True, timeout=10)
    public = next(line for line in result.stdout.splitlines() if line.startswith("ssh-ed25519 "))
    expected_hostkey = base64.b64decode(public.split()[1])
    db_port, http_port, tls_port = (free_port() for _ in range(3))
    cert, cert_key = tmp_path / "cert.pem", tmp_path / "cert.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cert_key), "-out", str(cert), "-days", "1", "-subj", "/CN=vpn.example.com", "-addext", "subjectAltName=DNS:vpn.example.com"], check=True, capture_output=True, timeout=20)
    db_log = (tmp_path / "dropbear.log").open("w+")
    forced_shell = tmp_path / "tunnel-shell"
    forced_shell.write_bytes((Path(__file__).resolve().parents[1] / "scripts/tunnel-shell").read_bytes())
    forced_shell.chmod(0o700)
    # No -w only in this isolated fixture, allowing CI's current UID (including
    # root containers). Production installer always passes -w.
    db = subprocess.Popen([DROPBEAR, "-F", "-E", "-s", "-k", "-T", "3", "-W", "131072",
        "-c", str(forced_shell), "-D", str(keydir), "-r", str(hostkey), "-p", f"127.0.0.1:{db_port}",
        "-P", str(tmp_path / "dropbear.pid")], stdout=db_log, stderr=subprocess.STDOUT)
    nginx = None; transport = None
    echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo); echo.daemon_threads = True
    try:
        wait_port(db_port, db)
        monkeypatch.setattr(bridge, "TARGET_PORT", db_port)
        with running_server(echo) as echo_port, running_server(bridge.Server(("127.0.0.1", 0), bridge.Handler)) as bridge_port:
            monkeypatch.setattr(paneld, "ipv6_enabled", lambda: False)
            site = paneld.nginx_text("vpn.example.com", True)
            site = site.replace("listen 80;", f"listen 127.0.0.1:{http_port};")
            site = site.replace("listen 443 ssl http2;", f"listen 127.0.0.1:{tls_port} ssl http2;")
            site = site.replace("127.0.0.1:2082", f"127.0.0.1:{bridge_port}")
            site = site.replace("/etc/letsencrypt/live/vpn.example.com/fullchain.pem", str(cert))
            site = site.replace("/etc/letsencrypt/live/vpn.example.com/privkey.pem", str(cert_key))
            config = tmp_path / "nginx.conf"
            config.write_text(("user root root;\n" if os.geteuid() == 0 else "") +
                f"pid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/nginx.log;\nevents {{}}\nhttp {{\naccess_log off;\n" +
                "\n".join(f"{name}_temp_path {tmp_path}/{name};" for name in ("client_body", "proxy", "fastcgi", "scgi", "uwsgi")) + "\n" + site + "\n}\n")
            subprocess.run([NGINX, "-t", "-p", str(tmp_path), "-c", str(config)], check=True, capture_output=True, timeout=10)
            nginx = subprocess.Popen([NGINX, "-p", str(tmp_path), "-c", str(config), "-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_port(tls_port, nginx)
            if route == "direct":
                peer = socket.create_connection(("127.0.0.1", db_port), timeout=5)
            elif route == "legacy":
                # Read one byte at a time so coalesced SSH greeting bytes remain.
                peer = socket.create_connection(("127.0.0.1", http_port), timeout=5)
                peer.sendall(b"GET /ssh/raw HTTP/1.1\r\nHost: vpn.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                response = b""
                while not response.endswith(b"\r\n\r\n"):
                    response += peer.recv(1)
                assert response.startswith(b"HTTP/1.1 101 ")
            else:
                context = ssl.create_default_context(cafile=str(cert))
                ws = connect(f"wss://vpn.example.com:{tls_port}/ssh/ws", sock=socket.create_connection(("127.0.0.1", tls_port), timeout=5),
                    ssl=context, compression=None, proxy=None, subprotocols=["binary"])
                peer = WebSocketSocket(ws)
            transport = paramiko.Transport(peer)
            transport.start_client(timeout=5)
            assert transport.get_remote_server_key().asbytes() == expected_hostkey
            user = pwd.getpwuid(os.geteuid()).pw_name
            with pytest.raises(paramiko.AuthenticationException):
                transport.auth_publickey(user, paramiko.RSAKey.generate(2048))
            transport.auth_publickey(user, client_key)
            assert transport.is_authenticated()
            channel = transport.open_channel("direct-tcpip", ("127.0.0.1", echo_port), ("127.0.0.1", 12345), timeout=5)
            channel.settimeout(5)
            payload = bytes(range(256)) * 16384
            sender = threading.Thread(target=lambda: channel.sendall(payload), daemon=True)
            sender.start(); received = bytearray()
            while len(received) < len(payload):
                part = channel.recv(32768)
                assert part, "Forwarded stream closed early"
                received.extend(part)
            sender.join(3)
            assert bytes(received) == payload and not sender.is_alive()
            channel.close()
            with pytest.raises(paramiko.SSHException):
                transport.request_port_forward("127.0.0.1", 0)
            command = transport.open_session(timeout=5)
            marker = tmp_path / "must-not-exist"
            command.exec_command("touch " + str(marker))
            assert command.recv_exit_status() != 0 and not marker.exists()
            transport.close(); transport = None
    finally:
        if transport: transport.close()
        for process in (nginx, db):
            if process:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=2)
        db_log.close()
