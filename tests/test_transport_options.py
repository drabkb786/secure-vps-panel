"""TLS/non-TLS exports, transactional routing, and usable SSH/dnstt bundles."""
import base64
import json
from datetime import date, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest

import panelctl
import paneld
import slowdns
import ssh_profiles
import xray_manager as xray
from common import ValidationError


def test_non_tls_is_additional_and_reuses_the_same_vless_account(manager):
    manager.configure({'enabled': True, 'vless_non_tls_enabled': True})
    manager.create({'name': 'dual', 'days': 7})
    row = xray.accounts()[0]
    data = manager.export({'name': 'dual'})
    assert set(data['links']) == {'vless', 'vless-non-tls', 'vmess', 'trojan'}
    tls, plain = (urlsplit(data['links'][p]) for p in ('vless', 'vless-non-tls'))
    assert tls.port == 443 and plain.port == 80
    assert plain.username == tls.username == row['uuid']
    query = parse_qs(plain.query)
    assert query['security'] == ['none'] and query['type'] == ['ws'] and query['path'] == ['/vless']
    assert 'sni' not in query and 'alpn' not in query
    config = json.loads(data['files']['dual-vless-non-tls.json'])['outbounds'][0]
    assert config['settings']['vnext'][0]['port'] == 80
    assert config['streamSettings']['security'] == 'none' and 'tlsSettings' not in config['streamSettings']
    encryption = xray.vless_encryption.keys()['encryption']
    assert query['encryption'] == [encryption]
    assert config['settings']['vnext'][0]['users'][0]['encryption'] == encryption
    assert any('compatible Xray client' in s for s in data['readiness']['warnings'])
    server = json.loads(xray.CONFIG_FILE.read_text())
    extra = next(i for i in server['inbounds'] if i['port'] == 10005)
    assert extra['listen'] == '127.0.0.1' and extra['settings']['decryption'] == xray.vless_encryption.keys()['decryption']
    assert next(i for i in server['inbounds'] if i['port'] == 10001)['settings']['decryption'] == 'none'
    assert 'decryption' not in json.dumps(manager.status({}))
    box = json.loads(data['files']['dual-singbox.json'])
    assert all(p.get('server_port', 443) == 443 for p in box['outbounds'])
    clash = json.loads(data['files']['dual-clash.yaml'])
    assert all(p['port'] == 443 and p['tls'] is True for p in clash['proxies'])
    manager.configure({'enabled': True, 'vless_non_tls_enabled': False})
    assert 'vless-non-tls' not in manager.export({'name': 'dual'})['links']
    assert xray.accounts()[0]['uuid'] == row['uuid']


def test_non_tls_is_in_live_subscriptions_but_never_a_cdn_profile(manager, monkeypatch):
    manager.configure({'enabled': True, 'vless_non_tls_enabled': True})
    manager.create({'name': 'dual', 'days': 7})
    issued = manager.subscription_rotate({'name': 'dual'})
    token = issued['url'].rsplit('/', 1)[1]
    body = manager.subscription_get({'token': token})['content']
    assert ':80?' in base64.b64decode(body).decode()
    monkeypatch.setattr(xray.cdn_manager, 'delivery', lambda route, domain: ('edge.example.com', '/bunny'))
    data = manager.export({'name': 'dual', 'route': 'bunny'})
    assert 'vless-non-tls' not in data['links']
    for p in json.loads(data['files']['dual-singbox.json'])['outbounds'][1:]:
        assert p['server_port'] == 443 and p['tls']['enabled'] is True
    with pytest.raises(ValidationError, match='direct-only'):
        xray.client_config('vless-non-tls', xray.accounts()[0], 'edge.example.com', xray.DEFAULT_DNS, '/bunny')


@pytest.mark.parametrize('flag', [False, True])
def test_nginx_non_tls_switch_keeps_other_protocols_and_cdn_tls_only(manager, flag):
    manager.configure({'enabled': True, 'vless_non_tls_enabled': flag})
    http = paneld.nginx_text('vpn.example.com', False)
    if flag:
        assert 'proxy_pass http://127.0.0.1:10005' + xray.gateway_identity.backend_path('vless') + ';' in http
    else:
        assert 'location = /vless { return 403; }' in http
    assert 'location = /vmess { return 403; }' in http and 'location = /trojan { return 403; }' in http
    assert 'location = /bunny/ssh/ws { return 403; }' in http
    assert 'proxy_pass http://127.0.0.1:2082;' in http


def test_failed_gateway_change_restores_xray_and_keeps_credentials(manager, monkeypatch):
    manager.configure({'enabled': True})
    manager.create({'name': 'dual', 'days': 7})
    before, rows = xray.settings(), xray.accounts()
    def fail(): raise RuntimeError('Nginx validation failed')
    manager.gateway_apply = fail
    with pytest.raises(RuntimeError, match='Nginx validation failed'):
        manager.configure({'enabled': True, 'vless_non_tls_enabled': True})
    assert xray.settings() == before and xray.accounts() == rows


def test_backup_restore_preserves_the_transport_switch_and_reloads_gateway(manager):
    manager.configure({'enabled': True, 'vless_non_tls_enabled': True})
    manager.create({'name': 'dual', 'days': 7})
    backup = manager.backup_export({})['backup']
    manager.configure({'enabled': True, 'vless_non_tls_enabled': False})
    observed = []
    manager.gateway_apply = lambda: observed.append(xray.settings()['vless_non_tls_enabled'])
    manager.backup_restore({'backup': backup})
    assert xray.settings()['vless_non_tls_enabled'] is True and observed == [True]


def test_non_tls_identity_is_private_preserved_and_never_exported(manager):
    manager.configure({'enabled': True, 'vless_non_tls_enabled': True})
    key_file = xray.vless_encryption.KEY_FILE
    original = key_file.read_bytes()
    manager.configure({'enabled': True, 'vless_non_tls_enabled': True})
    manager.create({'name': 'identity', 'days': 7})
    assert key_file.read_bytes() == original and key_file.stat().st_mode & 0o777 == 0o600
    assert len([c for c in manager.calls if c[-1] == 'vlessenc']) == 1
    exported = manager.export({'name': 'identity'})
    assert xray.vless_encryption.keys()['decryption'] not in json.dumps(exported)


def test_malformed_key_generation_does_not_save_an_identity(manager):
    from types import SimpleNamespace
    manager.run = lambda *a, **kw: SimpleNamespace(stdout='unexpected output')
    with pytest.raises(RuntimeError, match='no identity was saved'):
        manager.configure({'enabled': True, 'vless_non_tls_enabled': True})
    assert not xray.vless_encryption.KEY_FILE.exists()
    assert xray.settings()['vless_non_tls_enabled'] is False


def test_plain_switch_is_typed_and_exposed_in_cli(manager):
    for value in ('yes', 1, None):
        with pytest.raises(ValidationError, match='must be a boolean'):
            manager.configure({'enabled': True, 'vless_non_tls_enabled': value})
    assert panelctl.parser().parse_args(['xray-enable', '--non-tls']).non_tls is True
    assert panelctl.parser().parse_args(['xray-enable', '--no-non-tls']).non_tls is False
    assert panelctl.parser().parse_args(['xray-link', 'dual', '--protocol', 'vless-non-tls']).protocol == 'vless-non-tls'


@pytest.mark.parametrize('ips,key_valid', [(0, True), (1, True), (0, False)])
def test_ssh_bundle_distinguishes_direct_raw_ws_and_eligible_dnstt(tmp_path, monkeypatch, ips, key_valid):
    domain = tmp_path / 'domain'; domain.write_text('vpn.example.com')
    public = tmp_path / 'server.pub'; public.write_text('a' * 64 if key_valid else 'damaged')
    monkeypatch.setattr(ssh_profiles, 'DOMAIN_FILE', domain)
    monkeypatch.setattr(slowdns, 'PUBLIC_KEY', public)
    monkeypatch.setattr(slowdns, 'settings', lambda: {'enabled': True, 'zone': 'tunnel.example.com', 'ns_host': 'ns1.example.com', 'port': 53})
    account = {'enabled': True, 'expiry': str(date.today() + timedelta(days=7)), 'max_sessions': 2, 'max_ips': ips}
    data = ssh_profiles.export({'username': 'basit', 'password': 'bas'}, lambda _: account)
    files = data['files']
    assert json.loads(files['basit-direct.json'])['port'] == 109
    assert json.loads(files['basit-direct-alt.json'])['port'] == 447
    ws = json.loads(files['basit-ws-non-tls.json'])
    assert ws['port'] == 80 and ws['tls'] is False and ws['requires_rfc6455'] is True
    assert 'server_name' not in ws and 'verify_certificate' not in ws
    assert json.loads(files['basit-raw-http.json'])['requires_rfc6455'] is False
    assert '--no-tls --path /ssh/raw --probe --raw' in files['connect.txt']
    assert '-p 109 -N' in files['connect.txt']
    assert ('basit-dnstt.json' in files) == (ips == 0 and key_valid)
    if ips == 0 and key_valid:
        dns = json.loads(files['basit-dnstt.json'])
        assert dns['public_key'] == 'a' * 64 and dns['zone'] == 'tunnel.example.com'
        assert dns['username'] == 'basit' and dns['password'] == 'bas'
        assert 'server.key' not in json.dumps(files)
