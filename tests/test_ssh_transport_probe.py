"""Actual TCP/TLS and production bridge handshakes from the client probe."""
import asyncio
from contextlib import contextmanager
import socketserver
import ssl
import subprocess
import threading

import pytest

import ssh_ws_client as adapter
import ws_proxy


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
    thread.start()
    try: yield server.server_address[1]
    finally:
        server.shutdown(); server.server_close(); thread.join(3)


@pytest.mark.parametrize('tls', [False, True])
@pytest.mark.parametrize('raw', [False, True])
def test_probe_reads_real_split_ssh_banner_over_both_transports(tmp_path, monkeypatch, tls, raw):
    context = None
    if tls:
        cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert),
                        '-days', '1', '-subj', '/CN=vpn.example.com', '-addext', 'subjectAltName=DNS:vpn.example.com'], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
        trusted = ssl.create_default_context(cafile=str(cert))
        monkeypatch.setattr(adapter.ssl, 'create_default_context', lambda: trusted)
    class SSH(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(b'SSH-2.0-OpenSSH_')
            self.request.sendall(b'probe\r\n')
            self.request.settimeout(2)
            try: self.request.recv(1)
            except OSError: pass
    class Front(ws_proxy.Server):
        def get_request(self):
            peer, address = super().get_request()
            if context: peer = context.wrap_socket(peer, server_side=True)
            return peer, address
    with running(socketserver.ThreadingTCPServer(('127.0.0.1', 0), SSH)) as target:
        monkeypatch.setattr(ws_proxy, 'TARGET_PORT', target)
        with running(Front(('127.0.0.1', 0), ws_proxy.Handler)) as port:
            result = asyncio.run(adapter.probe('vpn.example.com', port, '/ssh/raw' if raw else '/ssh/ws', '127.0.0.1', tls=tls, raw=raw))
    assert result['ok'] is True and result['http_status'] == 101
    assert result['ssh_banner'] == 'SSH-2.0-OpenSSH_probe'
    assert result['authentication'] == 'not_tested' and result['tls'] is tls


@pytest.mark.parametrize('raw', [False, True])
@pytest.mark.parametrize('status', [200, 403])
def test_probe_reports_http_rejection_instead_of_an_ssh_eof(raw, status):
    class Reject(socketserver.BaseRequestHandler):
        def handle(self):
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = self.request.recv(4096)
                if not chunk: return
                data += chunk
            self.request.sendall(f'HTTP/1.1 {status} Rejected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'.encode())
    with running(socketserver.ThreadingTCPServer(('127.0.0.1', 0), Reject)) as port:
        with pytest.raises(OSError, match=str(status)):
            asyncio.run(adapter.probe('vpn.example.com', port, '/ssh/raw', '127.0.0.1', tls=False, raw=raw))
