"""Opt-in migration acceptance on a disposable, installed systemd runner.

Uses actual HAProxy, Nginx, Dropbear password auth, forwarding, kernel session
identity and failed/successful rollback. Never run this against a user's VPS.
"""
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('HAPROXY_NATIVE_SYSTEMD') != '1', reason='Requires disposable installed systemd runner')


def test_real_gateway_migration_password_transports_ip_limits_and_recovery(monkeypatch, tmp_path):
    assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
    import paramiko
    import gateway_identity
    import paneld
    import session_enforcer
    import ssh_backend
    import ssh_identity
    import ssh_sessions
    from common import DOMAIN_FILE, atomic_write
    from panel_client import request
    from test_dropbear_native import WebSocketSocket
    from test_haproxy_migration import ROOT, migration
    from websockets.sync.client import connect

    monkeypatch.setattr(gateway_identity, 'CONFIG_FILE', Path('/etc/abdulbasit-gateway/header.conf'))
    monkeypatch.setattr(ssh_identity, 'PEER_DIR', Path('/run/abdulbasit-ws/peers'))
    monkeypatch.setattr(ssh_backend, 'GATEWAY_FILE', Path('/etc/abdulbasit/gateway-backend'))
    monkeypatch.setattr(ssh_backend, 'HAPROXY_SECRET_FILE', Path('/etc/abdulbasit/haproxy-verify'))
    assert ssh_backend.name() == 'openssh'
    # The existing CI installer deliberately has no public domain. Supply an
    # isolated origin certificate trusted by only this test and its children.
    domain = 'vpn.example.com'
    certdir = Path('/etc/letsencrypt/live') / domain; certdir.mkdir(parents=True, exist_ok=True)
    cert, key = certdir / 'fullchain.pem', certdir / 'privkey.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=' + domain, '-addext', 'subjectAltName=DNS:' + domain], check=True, capture_output=True, timeout=20)
    monkeypatch.setenv('SSL_CERT_FILE', str(cert))
    atomic_write(DOMAIN_FILE, domain + '\n', 0o640)
    paneld.install_nginx_config(domain)
    admin = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/etc/ssh').rglob('*') if p.is_file()}
    name = f'nowaymux{os.getpid()}'
    request('create_user', username=name, password='bas', days=30, max_sessions=2, max_ips=0)
    password_before = next(row for row in Path('/etc/shadow').read_text().splitlines() if row.startswith(name + ':'))
    source = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show', 'scope', 'global']))
    host = next(info['local'] for link in source for info in link.get('addr_info', []) if info.get('family') == 'inet')
    assert not ipaddress.ip_address(host).is_loopback
    echo = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo); echo.daemon_threads = True
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    transports = []
    baseline = migration.Migration()
    recovery = None
    def installed(args):
        result = subprocess.run(args, text=True, capture_output=True, timeout=180)
        assert result.returncode == 0, result.stdout[-7000:] + result.stderr[-7000:]
        return result.stdout
    def login(peer):
        transport = paramiko.Transport(peer); transports.append(transport)
        transport.start_client(timeout=8)
        assert transport.remote_version.startswith('SSH-2.0-dropbear_2026.94')
        transport.auth_password(name, 'bas')
        assert transport.is_authenticated()
        channel = transport.open_channel('direct-tcpip', ('127.0.0.1', echo.server_address[1]), ('127.0.0.1', 32123), timeout=8)
        channel.settimeout(10)
        payload = bytes(range(256)) * 8192
        sender = threading.Thread(target=lambda: channel.sendall(payload), daemon=True); sender.start()
        received = bytearray()
        while len(received) < len(payload):
            part = channel.recv(65536); assert part, 'Forwarded transfer ended early'; received.extend(part)
        sender.join(5)
        assert not sender.is_alive() and hashlib.sha256(received).digest() == hashlib.sha256(payload).digest()
        with pytest.raises(paramiko.SSHException): transport.request_port_forward('127.0.0.1', 0)
        session = transport.open_session(timeout=5); session.settimeout(5); session.exec_command('id')
        assert session.recv_exit_status() == 1
        session.close()
        return transport, channel
    try:
        # Production helper reuses the already checksum-verified CI build.
        installed(['bash', str(ROOT / 'scripts/install-dropbear-2026.sh')])
        original = paneld.NGINX_CONFIG.read_bytes()
        injected = False
        def failing_runner(args, **kwargs):
            nonlocal injected
            if list(map(str, args)) == ['systemctl', 'start', 'abdulbasit-haproxy'] and not injected:
                injected = True
                raise RuntimeError('Injected HAProxy activation failure')
            return migration.run(args, **kwargs)
        baseline.run = failing_runner
        with pytest.raises(RuntimeError, match='Injected HAProxy activation failure'):
            baseline.apply()
        assert injected and paneld.NGINX_CONFIG.read_bytes() == original
        assert ssh_backend.name() == 'openssh' and not ssh_backend.haproxy_enabled()
        installed(['systemctl', 'is-active', 'nginx', 'abdulbasit-sshd', 'abdulbasit-paneld', 'abdulbasit-ws'])
        # Reproduce an older deployment that predates this new adapter module.
        adapter = Path('/usr/local/lib/abdulbasit/ssh_ws_client.py')
        adapter.unlink()
        output = installed(['bash', str(ROOT / 'scripts/migrate-dropbear-haproxy.sh')])
        assert adapter.read_bytes() == (ROOT / 'src/ssh_ws_client.py').read_bytes()
        recovery = Path(re.search(r'^Recovery copy: (.+)$', output, re.M).group(1))
        assert 'Dropbear 2026.94 verified' in output
        # Keep background enforcement from racing the intentional connection
        # churn. Exercise real enforcement explicitly on two known live logins.
        installed(['systemctl', 'stop', 'abdulbasit-session-enforcer'])
        assert ssh_backend.name() == 'dropbear' and ssh_backend.native_dropbear() and ssh_backend.haproxy_enabled()
        assert next(row for row in Path('/etc/shadow').read_text().splitlines() if row.startswith(name + ':')) == password_before
        assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == digest for p, digest in admin.items())
        assert subprocess.run(['systemctl', 'is-active', '--quiet', 'abdulbasit-sshd']).returncode != 0
        config = paneld.NGINX_CONFIG.read_text()
        assert 'listen 127.0.0.1:8080 proxy_protocol;' in config
        assert 'listen 127.0.0.1:8081 ssl http2 proxy_protocol;' in config
        # Unauthenticated local TCP forwarding cannot forge a public client IP.
        for metadata in (b'PROXY TCP4 198.51.100.7 127.0.0.1 54321 8080\r\n', proxy_v2('0' * 64)):
            with socket.create_connection(('127.0.0.1', 8080), timeout=3) as peer:
                peer.sendall(metadata + b'GET /ssh/raw HTTP/1.1\r\nHost: vpn.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
                assert peer.recv(4096).startswith(b'HTTP/1.1 403 ')
        context = ssl.create_default_context(cafile=str(cert))
        for secure in (False, True):
            peer = socket.create_connection((host, 443 if secure else 80), timeout=5)
            if secure: peer = context.wrap_socket(peer, server_hostname=domain)
            with peer:
                peer.sendall(b'GET /panel HTTP/1.1\r\nHost: vpn.example.com\r\nConnection: close\r\n\r\n')
                response = http.client.HTTPResponse(peer); response.begin(); response.read()
                assert response.status == 302
                assert response.getheader('Location') == ('https' if secure else 'http') + '://vpn.example.com/panel/'
        for port in (109, 447):
            transport, channel = login(socket.create_connection((host, port), timeout=5))
            channel.close(); transport.close()
        for secure in (False, True):
            peer = socket.create_connection((host, 443 if secure else 80), timeout=5)
            if secure: peer = context.wrap_socket(peer, server_hostname=domain)
            peer.sendall(b'GET /ssh/raw HTTP/1.1\r\nHost: vpn.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Forwarded-For: 198.51.100.99\r\n\r\n')
            header = b''
            while not header.endswith(b'\r\n\r\n'):
                part = peer.recv(1); assert part; header += part
                assert len(header) < 16384
            assert header.startswith(b'HTTP/1.1 101 ')
            transport, channel = login(peer); channel.close(); transport.close()
        installed(['systemctl', 'stop', 'abdulbasit-session-enforcer'])
        live = []
        for secure in (False, True):
            ws = connect(f'{"wss" if secure else "ws"}://{domain}/ssh/ws',
                         sock=socket.create_connection((host, 443 if secure else 80), timeout=5),
                         **({'ssl': context} if secure else {}), proxy=None, compression=None,
                         additional_headers={'X-Forwarded-For': '198.51.100.99'})
            live.append(login(WebSocketSocket(ws)))
        for _ in range(50):
            state = ssh_sessions.snapshot()
            rows = next((r for uid, r in state['sessions'].items() if state['users'][uid] == name), [])
            if len(rows) == 2: break
            time.sleep(.1)
        assert len(rows) == 2, state
        observed = ssh_identity.session_ips({name: [row.pid for row in rows]})
        assert set(observed.values()) == {host}, observed
        request('set_sessions', username=name, max_sessions=1, max_ips=1)
        session_enforcer.enforce_once()
        for _ in range(50):
            if not live[1][0].is_active(): break
            time.sleep(.1)
        assert live[0][0].is_active() and not live[1][0].is_active()
        live[0][1].sendall(b'oldest-survives'); assert live[0][1].recv(15) == b'oldest-survives'
        for transport in transports: transport.close()
        key_digest = hashlib.sha256(Path('/etc/dropbear/dropbear_ed25519_host_key').read_bytes()).digest()
        again = installed(['bash', str(ROOT / 'scripts/migrate-dropbear-haproxy.sh')])
        assert 'compilation skipped' in again
        assert hashlib.sha256(Path('/etc/dropbear/dropbear_ed25519_host_key').read_bytes()).digest() == key_digest
        installed(['bash', str(ROOT / 'scripts/security-check.sh')])
        request('delete_user', username=name)
        name = None
        installed(['bash', str(ROOT / 'scripts/migrate-dropbear-haproxy.sh'), '--rollback', str(recovery)])
        recovery = None
        assert ssh_backend.name() == 'openssh' and not ssh_backend.haproxy_enabled()
        assert paneld.NGINX_CONFIG.read_bytes() == original
        assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == digest for p, digest in admin.items())
        installed(['systemctl', 'is-active', 'nginx', 'abdulbasit-sshd'])
    finally:
        for transport in transports: transport.close()
        if name:
            try: request('delete_user', username=name)
            except Exception: pass
        if recovery:
            migration.Migration().rollback(recovery)
        echo.shutdown(); echo.server_close()


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536): self.request.sendall(data)
        except OSError: pass


def proxy_v2(identity):
    addresses = socket.inet_aton('198.51.100.7') + socket.inet_aton('127.0.0.1') + struct.pack('!HH', 54321, 8080)
    tlv = b'\x05' + struct.pack('!H', len(identity)) + identity.encode()
    return b'\r\n\r\n\x00\r\nQUIT\n' + b'\x21\x11' + struct.pack('!H', len(addresses + tlv)) + addresses + tlv
