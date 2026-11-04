"""Real TLS, WebSocket framing and pipe backpressure (no network mocks)."""
import os, sys, socket, socketserver, ssl, subprocess, tempfile, threading, select, time
import pytest
from pathlib import Path
from wsproto import WSConnection, ConnectionType
from wsproto.events import Request, AcceptConnection, BytesMessage, CloseConnection, Ping
ADAPTER=str(Path(__file__).resolve().parents[1]/'src/ssh_ws_client.py')
@pytest.mark.parametrize("remote_close", [False, True])
def test_tls_full_duplex_under_backpressure(tmp_path, remote_close):
    d=str(tmp_path)
    base=Path(d); cert=base/'cert.pem'; key=base/'key.pem'
    subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=vpn.example.com','-addext','subjectAltName=DNS:vpn.example.com'],check=True,capture_output=True)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key)
    welcome=b'SSH-2.0-transport-stress\r\n'
    errors=[]
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with context.wrap_socket(self.request,server_side=True) as peer:
                    peer.settimeout(12); peer.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1); peer.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,16384); peer.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,65536); ws=WSConnection(ConnectionType.SERVER); received=0
                    while True:
                        data=peer.recv(65536)
                        if not data: return
                        ws.receive_data(data)
                        for event in ws.events():
                            if isinstance(event,Request):
                                peer.sendall(ws.send(AcceptConnection())+ws.send(BytesMessage(data=welcome)))
                            elif isinstance(event,BytesMessage):
                                received += len(event.data)
                                peer.sendall(ws.send(Ping(payload=b'probe')) + ws.send(BytesMessage(data=event.data)))
                                if remote_close and received == 8*1024*1024:
                                    peer.sendall(ws.send(CloseConnection(code=1000)))
                                    return
                            elif isinstance(event,Ping): peer.sendall(ws.send(event.response()))
                            elif isinstance(event,CloseConnection): return
            except (OSError,ValueError) as exc: errors.append(str(exc))
    class Server(socketserver.ThreadingTCPServer): daemon_threads=True
    with Server(('127.0.0.1',0),Handler) as server:
        threading.Thread(target=server.serve_forever,daemon=True).start()
        payload=os.urandom(8*1024*1024); completed=0
        for case in range(1):
            proc=subprocess.Popen([sys.executable,ADAPTER,'--host','vpn.example.com','--address','127.0.0.1','--port',str(server.server_address[1])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,env={**os.environ,'SSL_CERT_FILE':str(cert)})
            def send():
                try:
                    for offset in range(0,len(payload),65536):
                        view=memoryview(payload)[offset:offset+65536]
                        while view: view=view[os.write(proc.stdin.fileno(),view):]
                except (OSError,ValueError): pass
            writer=threading.Thread(target=send,daemon=True); writer.start()
            result=bytearray(); deadline=time.monotonic()+35
            while len(result)<len(payload)+len(welcome) and time.monotonic()<deadline:
                if select.select([proc.stdout],[],[],.2)[0]:
                    data=os.read(proc.stdout.fileno(),65536)
                    if not data: break
                    result.extend(data)
                if proc.poll() is not None: break
            valid=result==welcome+payload
            if remote_close and valid:
                assert proc.wait(timeout=5) == 0, proc.stderr.read().decode(errors="replace")
            if proc.poll() is None: proc.terminate()
            proc.wait(timeout=3); writer.join(2)
            if not valid:
                print({'case':case,'bytes':len(result),'stderr':proc.stderr.read().decode(errors='replace'),'server_errors':errors[-3:]},flush=True)
                raise AssertionError("Full duplex TLS transfer stalled or corrupted")
            completed+=1
        server.shutdown()
        print({'completed':completed,'payload_bytes_each':len(payload),'verified':True},flush=True)
