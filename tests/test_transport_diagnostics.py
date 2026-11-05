"""Transport checks must preserve both split and coalesced SSH identification."""
from contextlib import contextmanager
from pathlib import Path
import socketserver
import ssl
import subprocess
import threading

import pytest
import diagnostics

HEAD = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n'
BANNER = b'SSH-2.0-OpenSSH_test\r\n'


@contextmanager
def responding(chunks, tls_context=None, path='/ssh/raw'):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                data = b''
                while b'\r\n\r\n' not in data: data += self.request.recv(4096)
                assert f'GET {path} HTTP/1.1'.encode() in data and b'Host: vpn.example.com' in data
                for chunk in chunks: self.request.sendall(chunk)
            except OSError:
                pass
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        def get_request(self):
            peer, address = super().get_request()
            if tls_context:
                try: peer = tls_context.wrap_socket(peer, server_side=True)
                except BaseException: peer.close(); raise
            return peer, address
    server = Server(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
    thread.start()
    try: yield server.server_address[1]
    finally: server.shutdown(); server.server_close(); thread.join(3)


@pytest.mark.parametrize('chunks', [[HEAD + BANNER], [HEAD[:17], HEAD[17:] + BANNER[:4], BANNER[4:]]])
def test_probe_accepts_coalesced_and_split_identification(chunks):
    with responding(chunks) as port:
        ok, detail = diagnostics.ssh_upgrade('vpn.example.com', port)
        assert ok and 'HTTP 101' in detail and 'SSH-2.0-OpenSSH_test' in detail


@pytest.mark.parametrize('reply', [b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n',
    b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n',
    HEAD, HEAD + b'HTTP/1.1 400 Bad Request\r\n',
    b'HTTP/1.1 101 Switching Protocols\r\n\r\n' + BANNER])
def test_probe_does_not_report_false_readiness(reply):
    with responding([reply]) as port:
        ok, detail = diagnostics.ssh_upgrade('vpn.example.com', port)
        assert not ok and detail


def test_tls_probe_verifies_the_configured_hostname_and_certificate(tmp_path, monkeypatch):
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
        '-out', str(cert), '-days', '1', '-subj', '/CN=vpn.example.com', '-addext',
        'subjectAltName=DNS:vpn.example.com'], check=True, capture_output=True)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server.load_cert_chain(cert, key)
    client = ssl.create_default_context(cafile=str(cert))
    monkeypatch.setattr(diagnostics.ssl, 'create_default_context', lambda: client)
    with responding([HEAD + BANNER], server) as port:
        assert diagnostics.ssh_upgrade('vpn.example.com', port, tls=True)[0]
        ok, detail = diagnostics.ssh_upgrade('wrong.example.com', port, tls=True)
        assert not ok and 'SSLCertVerificationError' in detail

@pytest.mark.parametrize('path', ['/', '/ssh/raw', '/cdn-cgi'])
def test_probe_checks_the_requested_origin_path(path):
    with responding([HEAD + BANNER], path=path) as port:
        assert diagnostics.ssh_upgrade('vpn.example.com', port, path=path)[0]


def test_conflict_status_preserved_in_probe_detail():
    with responding([b'HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n']) as port:
        ok, detail = diagnostics.ssh_upgrade('vpn.example.com', port)
        assert not ok and '409 Conflict' in detail
