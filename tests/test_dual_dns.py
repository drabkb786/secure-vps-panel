"""Zone isolation, safe migration and real account semantics for DNS tunnels."""
import json
import socket
import struct
import threading
from types import SimpleNamespace

import pytest
import dns_router
import slowdns
import xray_manager as xray
import traffic
import paneld
from common import atomic_write_json, ValidationError
from test_slowdns import dns_manager
from test_xray_core import record


def query(name, identity=123):
    labels = b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'
    return struct.pack('!6H', identity, 0x100, 1, 0, 0, 0) + labels + struct.pack('!HH', 16, 1)


@pytest.mark.parametrize('name,expected', [('payload.tunnel.example.com','tunnel.example.com'),
    ('PAYLOAD.XDNS.EXAMPLE.COM','xdns.example.com'), ('tunnel.example.com.evil.test',None),
    ('unrelated.example.com',None), ('tunnel.example.com','tunnel.example.com')])
def test_dns_router_matches_whole_delegated_suffixes(name, expected):
    assert dns_router.question_zone(query(name), ['tunnel.example.com','xdns.example.com']) == expected


@pytest.mark.parametrize('packet', [b'', b'x'*5000, b'\0'*12,
    struct.pack('!6H',1,0x100,1,0,0,0)+b'\xc0\x0c'+b'\0'*4,
    query('p.tunnel.example.com')[:-4]+struct.pack('!HH',255,1)])
def test_router_drops_malformed_compressed_and_non_txt_queries(packet):
    assert dns_router.question_zone(packet, ['tunnel.example.com']) is None


@pytest.mark.parametrize('query_type',[1,2,6,28])
def test_router_passes_resolver_zone_probes_to_the_authoritative_backend(query_type):
    packet=query('tunnel.example.com')[:-4]+struct.pack('!HH',query_type,1)
    assert dns_router.question_zone(packet,['tunnel.example.com'])=='tunnel.example.com'


def test_router_keeps_identical_ids_from_two_clients_and_zones_isolated(monkeypatch):
    peers = [socket.socket(socket.AF_INET,socket.SOCK_DGRAM) for _ in range(2)]
    for peer in peers:
        peer.bind(('127.0.0.1',0)); peer.settimeout(2)
    router = dns_router.Router(('127.0.0.1',0), dict(zip(['ssh.example.com','xray.example.com'],[p.getsockname() for p in peers])))
    clients = [socket.socket(socket.AF_INET,socket.SOCK_DGRAM) for _ in range(2)]
    for client in clients: client.settimeout(2)
    try:
        packets = [query('a.ssh.example.com'),query('b.xray.example.com')]
        for client,packet in zip(clients,packets): client.sendto(packet,router.listener.getsockname())
        router.step(.1); router.step(.1)
        for backend,packet in zip(peers,packets):
            received,source = backend.recvfrom(4096)
            assert received == packet
            backend.sendto(packet,source)
        router.step(.1); router.step(.1)
        assert [client.recv(4096) for client in clients] == packets
        assert not router.peers
        monkeypatch.setattr(dns_router,'MAX_PEERS',2)
        for client,packet in zip(clients,packets): client.sendto(packet,router.listener.getsockname())
        router.step(.1); router.step(.1)
        third = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            third.sendto(query('c.ssh.example.com'),router.listener.getsockname()); router.step(.1)
            assert len(router.peers) == 2
        finally: third.close()
    finally:
        router.close()
        for peer in peers + clients: peer.close()


def test_both_mode_preserves_existing_key_and_saves_two_zones(dns_manager):
    slowdns.BINARY.touch(); slowdns.CONFIG_DIR.mkdir()
    slowdns.PRIVATE_KEY.write_text('existing-key'); slowdns.PUBLIC_KEY.write_text('a'*64)
    def run(args,**kw):
        if '--property=MainPID' in args: return SimpleNamespace(stdout='4321')
        if '-Hlunp' in args and slowdns.RUNTIME_FILE.exists(): return SimpleNamespace(stdout='python pid=4321,fd=3')
        return SimpleNamespace(stdout='')
    dns_manager.run=run
    result=dns_manager.configure({'enabled':True,'mode':'both','zone':'tunnel.example.com','xray_zone':'xdns.example.com','ns_host':'ns1.example.com'})
    assert set(result['tunnels']) == {'ssh','xray'}
    assert result['tunnels']['ssh']['zone'] == 'tunnel.example.com'
    assert result['tunnels']['xray']['local_port'] == 7001
    assert 'https://dns.google/dns-query' in result['tunnels']['xray']['doh_command']
    assert slowdns.PRIVATE_KEY.read_text() == 'existing-key'
    with pytest.raises(ValidationError,match='distinct'):
        dns_manager.configure({'enabled':True,'mode':'both','zone':'tunnel.example.com','xray_zone':'x.tunnel.example.com','ns_host':'ns1.example.com'})


def test_xray_dns_inbound_is_private_and_excludes_ip_restricted_accounts():
    good=record(); capped={**record(),'max_ips':1}; blocked={**record(),'blocked_ips':['192.0.2.1']}
    config=xray.server_config({'dns':xray.DEFAULT_DNS,'dns_tunnel_enabled':True},[good,capped,blocked])
    inbound=next(x for x in config['inbounds'] if x['tag']=='noway-dnstt')
    assert inbound['listen']=='127.0.0.1' and inbound['port']==10006
    assert inbound['streamSettings']=={'network':'raw','security':'none'}
    assert [x['id'] for x in inbound['settings']['clients']]==[good['uuid']]
    assert inbound['settings']['clients'][0]['email'].endswith('-dnstt@noway.local')


def test_dns_bytes_belong_to_account_without_inventing_a_viewer_ip(tmp_path,monkeypatch):
    monkeypatch.setattr(traffic,'STATE_FILE',tmp_path/'traffic.json')
    row=record(); email=row['uuid']+'-dnstt@noway.local'
    response={'stat':[{'name':f'user>>>{email}>>>traffic>>>downlink','value':'157286400'},
        {'name':f'user>>>{email}>>>ip>>>127.0.0.1>>>traffic>>>downlink','value':'157286400'}]}
    data=traffic.accumulate([row],response,'1'*32)
    assert row['download_bytes']==157286400
    assert data['dns_totals'][row['uuid']]['download_bytes']==157286400
    assert not data['ip_totals']
    atomic_write_json(traffic.STATE_FILE,data)
    again=traffic.accumulate([row],response,'1'*32)
    assert again['totals'][row['uuid']]['download_bytes']==157286400
    assert traffic.ip_rows({'users':[{'email':email,'ips':[{'ip':'127.0.0.1'}]}]})==[]


def test_combined_configuration_rolls_xray_back_when_dns_restart_fails(monkeypatch):
    monkeypatch.setattr(xray,'settings',lambda:{'enabled':True,'dns_tunnel_enabled':False})
    calls=[]
    monkeypatch.setattr(paneld.XRAY,'configure',lambda p:calls.append(p))
    def fail(_): raise RuntimeError('DNS startup failed')
    monkeypatch.setattr(paneld.SLOWDNS,'configure',fail)
    with pytest.raises(RuntimeError,match='startup'):
        paneld.slowdns_configure({'enabled':True,'mode':'both'})
    assert [c['dns_tunnel_enabled'] for c in calls]==[True,False]


def test_invalid_mode_does_not_restart_the_working_xray_core(monkeypatch):
    monkeypatch.setattr(xray,'settings',lambda:{'enabled':True,'dns_tunnel_enabled':True})
    monkeypatch.setattr(paneld.XRAY,'configure',lambda _:pytest.fail('Invalid request restarted Xray'))
    with pytest.raises(ValidationError,match='Choose ssh'):
        paneld.slowdns_configure({'enabled':True,'mode':[]})


def test_dns_export_uses_managed_uuid_and_rejects_ip_limited_accounts(manager,dns_manager):
    atomic_write_json(xray.SETTINGS_FILE,{'enabled':True,'dns_tunnel_enabled':True,'dns':xray.DEFAULT_DNS})
    atomic_write_json(slowdns.SETTINGS_FILE,{'enabled':True,'mode':'both','zone':'ssh.example.com','xray_zone':'xdns.example.com','ns_host':'ns1.example.com'})
    slowdns.CONFIG_DIR.mkdir(); slowdns.PUBLIC_KEY.write_text('a'*64)
    row=record(); atomic_write_json(xray.ACCOUNTS_FILE,[row])
    result=manager.export({'name':row['name'],'route':'dns'})
    assert result['dnstt']['zone']=='xdns.example.com'
    assert result['links']['vless'].startswith(f"vless://{row['uuid']}@127.0.0.1:7001?")
    profile=json.loads(result['files'][row['name']+'-vless-dns.json'])
    assert profile['outbounds'][0]['settings']['vnext'][0]['users'][0]['id']==row['uuid']
    assert '-dot dns.google:853' in result['files']['dnstt-client.txt']
    row['max_ips']=1; atomic_write_json(xray.ACCOUNTS_FILE,[row])
    with pytest.raises(ValidationError,match='IP cap 0'):
        manager.export({'name':row['name'],'route':'dns'})
