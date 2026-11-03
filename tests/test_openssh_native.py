"""Disposable-runner acceptance test of the installed OpenSSH migration.

Run only after the full installer on a disposable systemd GitHub runner. This
creates/deletes a managed account through paneld and exercises its real kernel
session attribution. It never edits administrative sshd configuration.
"""
import hashlib
import http.client
import json
import os
import shlex
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("OPENSSH_NATIVE_SYSTEMD") != "1", reason="Requires disposable installed systemd runner")


def test_installed_openssh_login_wss_ip_limits_and_revocation(monkeypatch):
    assert os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
    import paramiko
    import paneld
    import session_enforcer
    import ssh_identity
    import ssh_sessions
    import gateway_identity
    monkeypatch.setattr(gateway_identity, "CONFIG_FILE", Path("/etc/abdulbasit-gateway/header.conf"))
    monkeypatch.setattr(ssh_identity, "PEER_DIR", Path("/run/abdulbasit-ws/peers"))
    from common import USERS_DIR
    from panel_client import request
    from test_dropbear_native import free_port, wait_port
    name = f"nowayci{os.getpid()}"
    request("create_user", username=name, password="bas", days=30, max_sessions=2, max_ips=0)
    transports = []
    nginx = None
    ssh_client = None
    subprocess.run(["systemctl", "stop", "abdulbasit-session-enforcer"], check=True, timeout=15)
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                while data := self.request.recv(65536): self.request.sendall(data)
            except OSError:
                pass
    echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    echo.daemon_threads = True
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    def login(peer):
        transport = paramiko.Transport(peer); transports.append(transport)
        transport.start_client(timeout=8)
        public = Path("/etc/abdulbasit-sshd/ssh_host_ed25519_key.pub").read_text().split()[1]
        assert transport.get_remote_server_key().get_base64() == public
        transport.auth_password(name, "bas")
        assert transport.is_authenticated()
        channel = transport.open_channel("direct-tcpip", ("127.0.0.1", echo.server_address[1]), ("127.0.0.1", 12345), timeout=8)
        channel.settimeout(15)
        payload = bytes(range(256)) * 8192
        sender = threading.Thread(target=lambda: channel.sendall(payload), daemon=True)
        sender.start(); received = bytearray()
        while len(received) < len(payload):
            chunk = channel.recv(65536)
            assert chunk, "SSH forwarding stream closed"
            received.extend(chunk)
        sender.join(10)
        assert not sender.is_alive() and hashlib.sha256(received).digest() == hashlib.sha256(payload).digest()
        with pytest.raises(paramiko.SSHException): transport.open_session(timeout=5)
        with pytest.raises(paramiko.SSHException): transport.request_port_forward("127.0.0.1", 0)
        return transport, channel
    try:
        first, channel = login(socket.create_connection(("127.0.0.1", 109), timeout=5))
        # /run may be mounted noexec on hosted runners. The ASKPASS helper must
        # execute, while remaining outside home directories hidden by services.
        with tempfile.TemporaryDirectory(prefix="noway-native-", dir="/usr/local/lib") as directory:
            root = Path(directory); cert = root / "cert.pem"; key = root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=vpn.example.com", "-addext", "subjectAltName=DNS:vpn.example.com"], check=True, capture_output=True, timeout=20)
            monkeypatch.setattr(paneld, "ipv6_enabled", lambda: False)
            http_port, tls_port = free_port(), free_port()
            site = paneld.nginx_text("vpn.example.com", True)
            site = site.replace("listen 80;", f"listen 127.0.0.1:{http_port};").replace("listen 443 ssl http2;", f"listen 127.0.0.1:{tls_port} ssl http2;")
            site = site.replace("/etc/letsencrypt/live/vpn.example.com/fullchain.pem", str(cert)).replace("/etc/letsencrypt/live/vpn.example.com/privkey.pem", str(key))
            site = site.replace("X-Forwarded-For $remote_addr;", "X-Forwarded-For 198.51.100.42;")
            config = root / "nginx.conf"
            config.write_text(f"user root root;\npid {root}/nginx.pid;\nerror_log {root}/nginx.log;\nevents {{}}\nhttp {{access_log off;\n" +
                              "\n".join(f"{part}_temp_path {root}/{part};" for part in ("client_body", "proxy", "fastcgi", "scgi", "uwsgi")) + site + "\n}")
            nginx = subprocess.Popen([os.environ.get("NGINX_TEST_BINARY", "/usr/sbin/nginx"), "-p", directory, "-c", str(config), "-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_port(tls_port, nginx)
            monkeypatch.setenv("SSL_CERT_FILE", str(cert))
            # The installed web worker must trust only Nginx's private marker,
            # while remaining reachable over this real verified TLS gateway.
            request("configure_web", username="nativeadmin", password="native-web-password")
            import ssl
            context = ssl.create_default_context(cafile=str(cert))
            with context.wrap_socket(socket.create_connection(("127.0.0.1", tls_port), timeout=5), server_hostname="vpn.example.com") as peer:
                body = json.dumps({"username": "nativeadmin", "password": "native-web-password"}).encode()
                peer.sendall(b"POST /panel/api/login HTTP/1.1\r\nHost: vpn.example.com\r\nOrigin: https://vpn.example.com\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                response = http.client.HTTPResponse(peer); response.begin()
                result = response.read()
                assert response.status == 200, result
                assert "Secure" in response.getheader("Set-Cookie", "")
            adapter = Path(__file__).resolve().parents[1] / "src/ssh_ws_client.py"
            # Test the user's actual OpenSSH ProxyCommand workflow. Paramiko
            # 3.5's ProxyCommand.recv spins on pipe EOF, so it cannot reliably
            # establish whether a remote session was disconnected.
            askpass = root / "askpass.sh"; askpass.write_text("#!/bin/sh\nprintf '%s\\n' bas\n"); askpass.chmod(0o700)
            known = root / "known_hosts"
            known.write_text("vpn.example.com " + Path("/etc/abdulbasit-sshd/ssh_host_ed25519_key.pub").read_text())
            socks_port = free_port()
            proxy_command = shlex.join([sys.executable, str(adapter), "--host", "vpn.example.com", "--address", "127.0.0.1", "--port", str(tls_port)])
            log = (root / "ssh-client.log").open("w+")
            env = dict(os.environ, SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force", DISPLAY=":0")
            ssh_client = subprocess.Popen(["ssh", "-N", "-D", f"127.0.0.1:{socks_port}", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(known), "-o", "ExitOnForwardFailure=yes", "-o", "ProxyCommand=" + proxy_command, name + "@vpn.example.com"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log, env=env)
            try:
                wait_port(socks_port, ssh_client)
            except AssertionError as exc:
                log.flush()
                pytest.fail(f"{exc}\nOpenSSH/adapter output:\n" + (root / "ssh-client.log").read_text())
            import struct
            from test_xray_core import read_exact
            with socket.create_connection(("127.0.0.1", socks_port), timeout=10) as peer:
                peer.settimeout(15)
                peer.sendall(b"\x05\x01\x00"); assert read_exact(peer, 2) == b"\x05\x00"
                peer.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", echo.server_address[1]))
                assert read_exact(peer, 10)[:2] == b"\x05\x00"
                payload = bytes(range(256)) * 8192
                sender = threading.Thread(target=lambda: peer.sendall(payload), daemon=True); sender.start()
                assert hashlib.sha256(read_exact(peer, len(payload))).digest() == hashlib.sha256(payload).digest()
                sender.join(5); assert not sender.is_alive()
            for attempt in range(40):
                state = ssh_sessions.snapshot()
                rows = next((items for uid, items in state["sessions"].items() if state["users"][uid] == name), [])
                if len(rows) == 2:
                    break
                time.sleep(.1)
            if len(rows) != 2:
                debug = []
                processes = subprocess.run(["ps", "-eo", "pid,ppid,euid,comm"], check=True, text=True, capture_output=True).stdout
                for line in processes.splitlines()[1:]:
                    fields = line.split()
                    if len(fields) == 4 and fields[-1].startswith("sshd"):
                        pid = int(fields[0]); group_file = Path(f"/proc/{pid}/cgroup")
                        try: debug.append({"kernel": line, "cgroup": group_file.read_text(), "verified": repr(__import__('openssh_sessions').process(pid))})
                        except OSError: pass
                pytest.fail(f"OpenSSH attribution failed: {state}; kernel processes: {debug}")
            observed = ssh_identity.session_ips({name: [row.pid for row in rows]})
            assert "198.51.100.42" in observed.values(), observed
            # Keep the oldest login and terminate only the newest excess login.
            request("set_sessions", username=name, max_sessions=1)
            session_enforcer.enforce_once()
            for attempt in range(40):
                if ssh_client.poll() is not None: break
                time.sleep(.1)
            log.flush()
            assert first.is_active() and ssh_client.poll() is not None, (root / "ssh-client.log").read_text()
            log.close()
            channel.sendall(b"oldest-survives")
            assert channel.recv(15) == b"oldest-survives"
            # An unattributable direct-loopback source cannot bypass an IP cap.
            request("set_sessions", username=name, max_sessions=1, max_ips=1)
            session_enforcer.enforce_once()
            for attempt in range(40):
                if not first.is_active(): break
                time.sleep(.1)
            assert not first.is_active()
            assert subprocess.run(["systemctl", "is-active", "--quiet", "abdulbasit-sshd"]).returncode == 0
    finally:
        for transport in transports: transport.close()
        if ssh_client is not None and ssh_client.poll() is None:
            ssh_client.terminate(); ssh_client.wait(timeout=5)
        if nginx:
            nginx.terminate(); nginx.wait(timeout=5)
        echo.shutdown(); echo.server_close()
        request("delete_user", username=name)
        subprocess.run(["systemctl", "start", "abdulbasit-session-enforcer"], check=True, timeout=15)
