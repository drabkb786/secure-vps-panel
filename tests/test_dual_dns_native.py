"""Real concurrent SSH login and VLESS forwarding through two DNS zones."""
import json
import os
import pwd
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

import pytest
import xray_manager
from test_xray_core import record, free_port, read_exact, wait_port
from test_dropbear_transport import Echo

NAMES = ('DNSTT_TEST_SERVER','DNSTT_TEST_CLIENT','XRAY_TEST_BINARY','DROPBEAR_TEST_BINARY','DROPBEARKEY_TEST_BINARY')
pytestmark = pytest.mark.skipif(not all(os.environ.get(name) for name in NAMES), reason='Native DNS, Xray and SSH binaries required')


def test_simultaneous_dns_zones_authenticate_ssh_and_vless(tmp_path):
    import paramiko
    server,client,core,dropbear,keygen = [os.environ[name] for name in NAMES]
    processes=[]; transport=None
    log=(tmp_path/'native.log').open('w+')
    echo=socketserver.ThreadingTCPServer(('127.0.0.1',0),Echo); echo.daemon_threads=True
    threading.Thread(target=echo.serve_forever,daemon=True).start()
    row=record()
    config=xray_manager.server_config({'dns':xray_manager.DEFAULT_DNS,'dns_tunnel_enabled':True},[row])
    dns_inbound=next(i for i in config['inbounds'] if i['tag']=='noway-dnstt')
    dns_inbound['port']=free_port()
    config['inbounds']=[dns_inbound]
    config['api']['listen']=str(tmp_path/'stats.sock')
    config['routing']['rules']=[{'type':'field','inboundTag':['noway-dnstt'],'outboundTag':'direct'}]
    core_config=tmp_path/'xray.json'; core_config.write_text(json.dumps(config))
    private,public=tmp_path/'dns.key',tmp_path/'dns.pub'
    subprocess.run([server,'-gen-key','-privkey-file',str(private),'-pubkey-file',str(public)],check=True,capture_output=True,timeout=10)
    def launch(args):
        proc=subprocess.Popen(args,stdout=log,stderr=log); processes.append(proc); return proc
    with tempfile.TemporaryDirectory(prefix='.noway-dual-dns-',dir=Path.home()) as directory:
        sshdir=Path(directory)
        key=paramiko.RSAKey.generate(2048)
        authorized=sshdir/'authorized_keys'; authorized.write_text(key.get_name()+' '+key.get_base64()+' test\n'); authorized.chmod(0o600)
        hostkey=tmp_path/'ssh.key'
        subprocess.run([keygen,'-t','ed25519','-f',str(hostkey)],check=True,capture_output=True,timeout=10)
        ssh_port=free_port()
        try:
            xray=launch([core,'run','-config',str(core_config)]); wait_port(dns_inbound['port'],xray)
            ssh=launch([dropbear,'-F','-E','-s','-k','-D',directory,'-r',str(hostkey),'-p',f'127.0.0.1:{ssh_port}','-P',str(tmp_path/'ssh.pid')]); wait_port(ssh_port,ssh)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                probe.bind(('127.0.0.1',0)); udp=probe.getsockname()[1]
            program=tmp_path/'router.py'
            program.write_text('''import signal
import dns_router
def stop(*_):
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
dns_router.serve('''+repr(server)+','+repr(str(private))+','+repr({'zone':'ssh.example.com','xray_zone':'xdns.example.com','mtu':1232,'port':udp})+', upstreams='+repr((f'127.0.0.1:{ssh_port}',f'127.0.0.1:{dns_inbound["port"]}'))+')\n')
            env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[1]/'src'))
            router=subprocess.Popen([sys.executable,str(program)],stdout=log,stderr=log,env=env); processes.append(router)
            ports=[free_port(),free_port()]
            for zone,port in zip(('ssh.example.com','xdns.example.com'),ports):
                proc=launch([client,'-udp',f'127.0.0.1:{udp}','-pubkey-file',str(public),zone,f'127.0.0.1:{port}'])
                wait_port(port,proc)
            peer=socket.create_connection(('127.0.0.1',ports[0]),timeout=30)
            transport=paramiko.Transport(peer); transport.banner_timeout=30; transport.auth_timeout=30
            transport.connect(username=pwd.getpwuid(os.geteuid()).pw_name,pkey=key)
            channel=transport.open_channel('direct-tcpip',echo.server_address,('127.0.0.1',1234),timeout=30)
            payload=b'SSH through DNS simultaneously\n'*200
            channel.sendall(payload); assert read_exact(channel,len(payload))==payload
            with socket.create_connection(('127.0.0.1',ports[1]),timeout=30) as vless:
                header=b'\x00'+uuid.UUID(row['uuid']).bytes+b'\x00\x01'+struct.pack('!H',echo.server_address[1])+b'\x01\x7f\x00\x00\x01'
                payload=b'VLESS through the other DNS zone\n'*200
                vless.sendall(header+payload)
                assert read_exact(vless,2)==b'\x00\x00'
                assert read_exact(vless,len(payload))==payload
            assert transport.is_active() and router.poll() is None
            channel.sendall(b'SSH still works'); assert read_exact(channel,15)==b'SSH still works'
            channel.close()
            response=subprocess.run([core,'api','statsquery','--server=unix://'+str(tmp_path/'stats.sock'),'-pattern=user>>>'],check=True,capture_output=True,text=True,timeout=5)
            stats={x['name']:int(x.get('value',0)) for x in json.loads(response.stdout)['stat']}
            assert stats[f"user>>>{row['uuid']}-dnstt@noway.local>>>traffic>>>downlink"]==len(payload)
        finally:
            if transport: transport.close()
            for proc in reversed(processes):
                if proc.poll() is None: proc.terminate()
            for proc in reversed(processes):
                try: proc.wait(timeout=8)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=3)
            echo.shutdown(); echo.server_close(); log.close()
