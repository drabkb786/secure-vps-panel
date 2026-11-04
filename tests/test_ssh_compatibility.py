"""Behavioral coverage for direct hybrid SSH transport and routing."""
import socket
import pytest
import paneld
import ssh_backend
import ws_proxy


def test_socket_options_are_enabled_before_transport_data():
    with socket.socket() as peer:
        ws_proxy.tune_socket(peer)
        assert peer.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 1
        assert peer.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1


@pytest.mark.parametrize('raw_request', [
    b'GET http://unrelated.example/ssh/raw HTTP/1.1\r\nHost: localhost',
    b'GET /unconfigured-path HTTP/1.1\r\nHost: localhost',
    b'POST /ssh/raw HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1',
    b'GET /ssh/raw HTTP/1.1\r\nHost: a\r\nHost: b',
    b'GET /ssh/raw HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked',
    b'GET /ssh/ws HTTP/1.1\r\nHost: localhost\r\nSec-WebSocket-Version: 13',
    b'POST /ssh/ws HTTP/1.1\r\nHost: localhost\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
])
def test_compatibility_does_not_accept_ambiguous_or_nonstandard_ws_handshakes(raw_request):
    with pytest.raises(ValueError):
        ws_proxy.parse_request(raw_request + b'\r\nUpgrade: websocket\r\nConnection: Upgrade')


@pytest.mark.parametrize('tls', [False, True])
def test_direct_routes_have_fixed_targets_and_panel_is_separate(tls, monkeypatch):
    monkeypatch.setattr(paneld, 'ipv6_enabled', lambda: False)
    site = paneld.nginx_text('vpn.example.com', tls)
    for path in ('/ssh/ws', '/ssh/raw'):
        block = site.split('location = ' + path + ' {', 1)[1].split('}', 1)[0]
        assert 'proxy_pass http://127.0.0.1:2082;' in block
        assert 'proxy_socket_keepalive on;' in block and 'proxy_buffering off;' in block
    panel = site.split('location /panel/ {', 1)[1].split('}', 1)[0]
    assert 'proxy_pass http://127.0.0.1:9090;' in panel
    assert 'default_server' not in site and 'server_name vpn.example.com;' in site


def test_managed_channels_remain_tunnel_only_and_legacy_crypto_is_explicit():
    modern = ssh_backend.config()
    assert 'MaxSessions 10' in modern and 'PermitTTY yes' in modern
    assert 'ForceCommand /usr/local/lib/abdulbasit/tunnel-shell' in modern
    assert 'AllowTcpForwarding local' in modern and 'PermitRootLogin no' in modern
    assert 'group1-sha1' not in modern and '+ssh-rsa' not in modern
    legacy = ssh_backend.config(legacy_crypto=True)
    assert 'KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group1-sha1' in legacy
