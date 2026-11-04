"""Optional real-core tests. Set XRAY_TEST_BINARY to a checksum-verified Xray binary."""
from __future__ import annotations

import json
import base64
import os
import socket
import socketserver
import struct
import subprocess
import threading
import time
import uuid
import re
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote

import pytest

from xray_manager import DEFAULT_DNS, PROTOCOLS, XHTTP_PATH, client_config, server_config, share_link

CORE = os.environ.get("XRAY_TEST_BINARY", "")
pytestmark = pytest.mark.skipif(not CORE, reason="XRAY_TEST_BINARY is not set")


# Kernel bind(0) may immediately return the same released ephemeral port.
# Xray can share TCP listeners, so duplicate fixture ports may silently route an
# XHTTP request into a WS inbound rather than failing at startup.
_ALLOCATED_PORTS = set()


def free_port():
    for _ in range(100):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in _ALLOCATED_PORTS:
            _ALLOCATED_PORTS.add(port)
            return port
    raise RuntimeError("Could not allocate a distinct native-test port")


def record():
    return {"name": "real_core_test", "uuid": str(uuid.uuid4()), "trojan_password": uuid.uuid4().hex,
            "protocols": list(PROTOCOLS), "enabled": True, "expiry": (date.today() + timedelta(days=1)).isoformat()}


def encryption_identity(tmp_path, monkeypatch):
    from reality_transport import vless_encryption
    monkeypatch.setattr(vless_encryption, 'KEY_FILE', tmp_path / 'vless-encryption.json')
    run = lambda args, **kw: subprocess.run(args, check=True, capture_output=True, text=True, timeout=kw['timeout'])
    vless_encryption.initialize(run, CORE)


def start_core(path: Path):
    log = path.with_suffix(".log").open("w+")
    proc = subprocess.Popen([CORE, "run", "-config", str(path)], stdout=log, stderr=log)
    return proc, log


def wait_port(port, process):
    for _ in range(120):
        if process.poll() is not None:
            raise AssertionError("Xray exited before opening its listener")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                return
        except OSError:
            time.sleep(.025)
    raise AssertionError("Xray listener did not become ready")


def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise AssertionError("Connection closed unexpectedly")
        data += chunk
    return data


def test_generated_configs_accepted_by_real_xray(tmp_path, monkeypatch):
    encryption_identity(tmp_path, monkeypatch)
    row = record()
    cases = {"server": server_config({"dns": DEFAULT_DNS}, [row]), "no-accounts": server_config({"dns": DEFAULT_DNS}, [])}
    cases.update({protocol: client_config(protocol, row, "vpn.example.com", DEFAULT_DNS) for protocol in PROTOCOLS})
    cases["xhttp-server"] = server_config({"dns": DEFAULT_DNS, "xhttp_enabled": True}, [row])
    cases["xhttp-client"] = client_config("vless-xhttp", row, "vpn.example.com", DEFAULT_DNS)
    cases["non-tls-client"] = client_config("vless-non-tls", row, "vpn.example.com", DEFAULT_DNS)
    cases["non-tls-server"] = server_config({"dns": DEFAULT_DNS, "vless_non_tls_enabled": True}, [row])
    for name, config in cases.items():
        path = tmp_path / f"{name}.json"; path.write_text(json.dumps(config))
        result = subprocess.run([CORE, "run", "-test", "-config", str(path)], capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr


def test_real_core_hot_add_keeps_existing_stream(tmp_path):
    import copy
    import xray_runtime
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                while data := self.request.recv(65536): self.request.sendall(data)
            except OSError:
                pass
    echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    echo.daemon_threads = True
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    first, second = record(), record()
    cfg = server_config({"dns": DEFAULT_DNS}, [first])
    inbound = cfg["inbounds"][0]
    inbound.update(port=free_port(), streamSettings={"network": "raw", "security": "none"})
    cfg["inbounds"] = [inbound]
    api_socket = tmp_path / "hot.sock"; cfg["api"]["listen"] = str(api_socket)
    cfg["routing"]["rules"] = []
    cfg["outbounds"][0]["settings"]["finalRules"] = [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": str(echo.server_address[1])}]
    path = tmp_path / "hot.json"; path.write_text(json.dumps(cfg))
    process, log = start_core(path)
    def login(row, payload):
        peer = socket.create_connection(("127.0.0.1", inbound["port"]), timeout=5)
        peer.settimeout(5)
        peer.sendall(b"\x00" + uuid.UUID(row["uuid"]).bytes + b"\x00\x01" + struct.pack("!H", echo.server_address[1]) + b"\x01\x7f\x00\x00\x01" + payload)
        assert read_exact(peer, 2) == b"\x00\x00"
        assert read_exact(peer, len(payload)) == payload
        return peer
    try:
        wait_port(inbound["port"], process)
        with login(first, b"before") as existing:
            added = copy.deepcopy(inbound)
            added["settings"]["clients"] = [{"id": second["uuid"], "email": second["uuid"] + "-vless@noway.local", "level": 0}]
            run = lambda args, **kw: subprocess.run(args, check=True, capture_output=True, text=True, timeout=kw["timeout"])
            xray_runtime.add(run, CORE, "unix://" + str(api_socket), [added], tmp_path)
            assert process.poll() is None
            existing.sendall(b"after-hot-add")
            assert read_exact(existing, 13) == b"after-hot-add"
            with login(second, b"new-user"): pass
    finally:
        process.terminate(); process.wait(timeout=5); log.close()
        echo.shutdown(); echo.server_close()


def test_real_reality_config_and_forwarding(tmp_path, monkeypatch):
    import xray_manager as xray
    import reality_transport
    monkeypatch.setattr(reality_transport, "KEY_FILE", tmp_path / "reality-keys.json")
    monkeypatch.setattr(xray, "DOMAIN_FILE", tmp_path / "domain")
    xray.DOMAIN_FILE.write_text("vpn.example.com")
    run = lambda args, **kw: subprocess.run(args, check=True, capture_output=True, text=True, timeout=kw["timeout"])
    reality_transport.initialize(run, CORE)
    import ssl
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=vpn.example.com", "-addext", "subjectAltName=DNS:vpn.example.com"], check=True, capture_output=True, timeout=20)
    class HTTPFixture(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            body = b"REALITY-forwarding-ok"
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    origin = ThreadingHTTPServer(("127.0.0.1", 0), HTTPFixture)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["h2", "http/1.1"])
    origin.socket = context.wrap_socket(origin.socket, server_side=True)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    destination = ThreadingHTTPServer(("127.0.0.1", 0), HTTPFixture)
    threading.Thread(target=destination.serve_forever, daemon=True).start()
    number = free_port(); row = record()
    cfg = server_config({"dns": DEFAULT_DNS, "reality_enabled": True, "reality_port": number}, [row])
    cfg["inbounds"] = [cfg["inbounds"][-1]]
    cfg["api"]["listen"] = str(tmp_path / "reality.sock")
    cfg["inbounds"][0]["streamSettings"]["realitySettings"]["target"] = f"127.0.0.1:{origin.server_port}"
    cfg["routing"]["rules"] = []
    cfg["outbounds"][0]["settings"]["finalRules"] = [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": str(destination.server_port)}]
    client = reality_transport.client(row, "vpn.example.com", number)
    client["outbounds"][0]["settings"]["vnext"][0]["address"] = "127.0.0.1"
    client_port = free_port(); client["inbounds"][0]["port"] = client_port
    paths = [tmp_path / "reality-server.json", tmp_path / "reality-client.json"]
    for path, data in zip(paths, (cfg, client)):
        path.write_text(json.dumps(data))
        result = run([CORE, "run", "-test", "-config", str(path)], timeout=20)
    processes = []
    try:
        for path in paths: processes.append(start_core(path))
        wait_port(number, processes[0][0]); wait_port(client_port, processes[1][0])
        with socket.create_connection(("127.0.0.1", client_port), timeout=10) as peer:
            peer.settimeout(15)
            peer.sendall(b"\x05\x01\x00"); assert read_exact(peer, 2) == b"\x05\x00"
            peer.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", destination.server_port))
            assert read_exact(peer, 10)[:2] == b"\x05\x00"
            peer.sendall(b"GET / HTTP/1.0\r\nHost: fixture\r\n\r\n")
            response = bytearray()
            while b"REALITY-forwarding-ok" not in response:
                part = peer.recv(65536)
                if not part: break
                response.extend(part)
            assert b"REALITY-forwarding-ok" in response
        public = reality_transport.link(row, "vpn.example.com", number)
        assert reality_transport.keys()["private"] not in public
    except Exception as exc:
        logs = "\n".join(path.read_text() for path in tmp_path.glob("*.log"))
        raise AssertionError(logs) from exc
    finally:
        for process, log in reversed(processes):
            process.terminate(); process.wait(timeout=5); log.close()
        origin.shutdown(); origin.server_close(); destination.shutdown(); destination.server_close()


def imported_profile_from_uri(link):
    """Independent client-style URI decoding; deliberately does not call client_config."""
    protocol, encoded = link.split("://", 1)
    plain = False
    if protocol == "vmess":
        data = json.loads(base64.b64decode(encoded, validate=True))
        assert data["net"] == "ws" and data["tls"] == "tls" and data["aid"] == "0"
        address, port, credential = data["add"], int(data["port"]), {"id": data["id"], "security": data["scy"]}
        host, path, server_name = data["host"], data["path"], data["sni"]
        alpn = data.get("alpn", "http/1.1").split(",")
    else:
        url = urlsplit(link); query = parse_qs(url.query, strict_parsing=True)
        assert query["type"][0] in ("ws", "xhttp") and query["security"][0] in ("tls", "none")
        plain = query["security"] == ["none"]
        address, port = url.hostname, url.port
        host, path, server_name = query["host"][0], query["path"][0], query.get("sni", [""])[0]
        alpn = query.get("alpn", ["http/1.1"])[0].split(",")
        credential = {"password": unquote(url.username)} if protocol == "trojan" else {"id": unquote(url.username), "encryption": query["encryption"][0]}
    outbound_settings = {"servers": [{"address": address, "port": port, **credential}]} if protocol == "trojan" else {"vnext": [{"address": address, "port": port, "users": [credential]}]}
    stream = {"network": "ws", "security": "tls", "wsSettings": {"path": path, "host": host},
              "tlsSettings": {"serverName": server_name, "allowInsecure": False, "alpn": alpn}}
    if plain:
        stream["security"] = "none"; stream.pop("tlsSettings")
    if protocol != "vmess" and query["type"] == ["xhttp"]:
        stream.pop("wsSettings"); stream["network"] = "xhttp"
        stream["xhttpSettings"] = {"path": path, "host": host, "mode": query["mode"][0]}
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
            "outbounds": [{"protocol": protocol, "settings": outbound_settings,
                           "streamSettings": stream}]}


@pytest.mark.parametrize("source", ["json", "import_link", "xhttp_link", "cloudfront_json", "cloudfront_link", "cloudfront_xhttp", "bunny_json", "bunny_xhttp", "plain_json", "plain_link"])
def test_real_vless_vmess_trojan_over_verified_tls_websocket(tmp_path, source, monkeypatch):
    from cloudfront_fixture import enable_origin, edge_server
    cdn = source.startswith(("cloudfront", "bunny"))
    provider = "bunny" if source.startswith("bunny") else "cloudfront"
    xhttp = "xhttp" in source
    plain = source.startswith('plain_')
    if plain:
        encryption_identity(tmp_path, monkeypatch)
        import xray_manager
        monkeypatch.setattr(xray_manager, 'settings', lambda: {'enabled': True, 'vless_non_tls_enabled': True})
    secret = enable_origin(tmp_path, monkeypatch, provider) if cdn else ""
    domain = "d123example.cloudfront.net" if cdn else "vpn.example.com"
    prefix = "/" + provider if cdn else ""
    """Exercise SOCKS -> Xray -> verified TLS/Nginx -> Xray -> local HTTP.

    Only this test config permits its loopback HTTP destination; production
    profiles keep private targets blocked. All transports use the actual gateway.
    """
    nginx = os.environ.get("NGINX_TEST_BINARY")
    if not nginx:
        pytest.skip("TLS gateway integration requires NGINX_TEST_BINARY")
    row = record(); server_cfg = server_config({"dns": DEFAULT_DNS, "xhttp_enabled": xhttp, "vless_non_tls_enabled": plain}, [row])
    api_socket = tmp_path / "stats.sock"
    server_cfg["api"]["listen"] = str(api_socket)
    server_cfg["log"]["loglevel"] = "debug"
    ports = {path: free_port() for _, path in PROTOCOLS.values()}
    if plain: ports['/vless-non-tls'] = free_port()
    if xhttp: ports[XHTTP_PATH] = free_port()
    for inbound in server_cfg["inbounds"]:
        stream = inbound["streamSettings"]
        inbound["port"] = ports['/vless-non-tls' if inbound['tag'] == 'noway-vless-non-tls' else XHTTP_PATH if inbound["tag"] == "noway-xhttp" else "/" + inbound["protocol"]]

    class HTTPFixture(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            body = b"NOWAY verified transport test"
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    http = ThreadingHTTPServer(("127.0.0.1", 0), HTTPFixture)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    server_cfg["routing"]["rules"].insert(0, {"type": "field", "ip": ["127.0.0.1"], "port": str(http.server_port), "outboundTag": "direct"})
    server_cfg["outbounds"][0]["settings"]["finalRules"] = [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": str(http.server_port)}]
    class UDPEcho(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request; sock.sendto(data, self.client_address)
    udp = socketserver.UDPServer(("127.0.0.1", 0), UDPEcho)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    server_cfg["routing"]["rules"].insert(0, {"type": "field", "ip": ["127.0.0.1"], "network": "udp", "port": str(udp.server_address[1]), "outboundTag": "direct"})
    server_cfg["outbounds"][0]["settings"]["finalRules"].append({"action": "allow", "network": "udp", "ip": ["127.0.0.1"], "port": str(udp.server_address[1])})

    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=vpn.example.com", "-addext", "subjectAltName=DNS:vpn.example.com,DNS:d123example.cloudfront.net"], check=True, capture_output=True, timeout=20)
    path = tmp_path / "server.json"; path.write_text(json.dumps(server_cfg))
    server_proc, server_log = start_core(path)
    front_proc = front_log = None
    try:
        for backend_port in ports.values():
            wait_port(backend_port, server_proc)
        from paneld import nginx_text
        front_port, http_port = free_port(), free_port()
        site = nginx_text("vpn.example.com", True)
        site = re.sub(r"^\s*listen \[::\]:[^\n]*\n", "", site, flags=re.MULTILINE)
        site = site.replace("listen 80;", f"listen 127.0.0.1:{http_port};").replace("listen 443 ssl http2;", f"listen 127.0.0.1:{front_port} ssl http2;")
        site = site.replace("/etc/letsencrypt/live/vpn.example.com/fullchain.pem", str(cert)).replace("/etc/letsencrypt/live/vpn.example.com/privkey.pem", str(key))
        site = site.replace("X-Forwarded-For $remote_addr;", "X-Forwarded-For 198.51.100.42;")
        for protocol, (port, endpoint_path) in PROTOCOLS.items():
            site = site.replace(f"127.0.0.1:{port}", f"127.0.0.1:{ports[endpoint_path]}")
        if plain:
            site = site.replace('127.0.0.1:10005', f"127.0.0.1:{ports['/vless-non-tls']}")
        if xhttp:
            site = site.replace("127.0.0.1:10004", f"127.0.0.1:{ports[XHTTP_PATH]}")
        if cdn:
            edge_port = free_port()
            site += edge_server(edge_port, front_port, cert, key, secret, provider)
        config = tmp_path / "nginx.conf"
        user = "user root root;\n" if os.geteuid() == 0 else ""
        temp_paths = "\n".join(f"{part}_temp_path {tmp_path}/{part};" for part in ("client_body", "proxy", "fastcgi", "scgi", "uwsgi"))
        config.write_text(user + f"master_process off;\npid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/nginx-error.log;\nevents {{}}\nhttp {{access_log off;\n{temp_paths}\n{site}\n}}")
        front_log = (tmp_path / "nginx-console.log").open("w")
        front_proc = subprocess.Popen([nginx, "-p", str(tmp_path), "-c", str(config), "-g", "daemon off;"], stdout=front_log, stderr=front_log)
        wait_port(front_port, front_proc)
        for protocol in (["vless-non-tls"] if plain else ["vless-xhttp"] if xhttp else PROTOCOLS):
            cfg = client_config(protocol, row, domain, DEFAULT_DNS, prefix) if source in ("json", "cloudfront_json", "bunny_json", "plain_json") else imported_profile_from_uri(share_link(protocol, row, domain, prefix))
            cfg["log"]["loglevel"] = "debug"
            proxy = cfg["outbounds"][0]
            if not plain: proxy["streamSettings"]["tlsSettings"]["certificates"] = [{"certificateFile": str(cert), "usage": "verify"}]
            transport_settings = proxy["streamSettings"].get("wsSettings", proxy["streamSettings"].get("xhttpSettings"))
            transport_settings.setdefault("headers", {}).update({"X-Forwarded-For": "203.0.113.66", "X-Noway-Gateway": "client-spoof"})
            endpoint = proxy["settings"]["servers" if protocol == "trojan" else "vnext"][0]
            endpoint.update({"address": "127.0.0.1", "port": http_port if plain else edge_port if cdn else front_port})
            port = free_port(); cfg["inbounds"][0]["port"] = port
            config_path = tmp_path / f"{protocol}-client.json"; config_path.write_text(json.dumps(cfg))
            proc, log = start_core(config_path)
            try:
                wait_port(port, proc)
                with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
                    sock.sendall(b"\x05\x01\x00"); assert read_exact(sock, 2) == b"\x05\x00"
                    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", http.server_port))
                    answer = read_exact(sock, 4); assert answer[:2] == b"\x05\x00", (protocol, answer)
                    read_exact(sock, 6 if answer[3] == 1 else 18)
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: test.local\r\n\r\n")
                    response = b""
                    while b"NOWAY verified transport test" not in response:
                        data = sock.recv(65536)
                        if not data: break
                        response += data
                    assert b"NOWAY verified transport test" in response, protocol
                # A complete TCP transfer must match the core's integer payload
                # counters byte-for-byte, including the HTTP bytes, excluding TLS.
                email = f"{row['uuid']}-{'vless' if plain else 'xhttp' if protocol == 'vless-xhttp' else protocol}@noway.local"
                measured = subprocess.run([CORE, "api", "statsquery", "--server=unix://" + str(api_socket), "-pattern=user>>>"], check=True, capture_output=True, text=True, timeout=5)
                counters = {item["name"]: int(item.get("value", 0)) for item in json.loads(measured.stdout).get("stat", [])}
                assert counters[f"user>>>{email}>>>traffic>>>uplink"] == len(b"GET / HTTP/1.0\r\nHost: test.local\r\n\r\n")
                assert counters[f"user>>>{email}>>>traffic>>>downlink"] == len(response)
                # Exercise a real SOCKS5 UDP association through the same TLS
                # transport. Only the fixture's loopback UDP port is allowed.
                with socket.create_connection(("127.0.0.1", port), timeout=10) as control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as packet:
                    control.sendall(b"\x05\x01\x00"); assert read_exact(control, 2) == b"\x05\x00"
                    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                    reply = read_exact(control, 10); assert reply[:4] == b"\x05\x00\x00\x01"
                    relay_port = struct.unpack("!H", reply[-2:])[0]
                    packet.settimeout(8)
                    payload = b"NOWAY verified UDP forwarding"
                    packet.sendto(b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.server_address[1]) + payload, ("127.0.0.1", relay_port))
                    answer, _ = packet.recvfrom(65536); assert answer.endswith(payload)
                    measured = subprocess.run([CORE, "api", "statsquery", "--server=unix://" + str(api_socket), "-pattern=user>>>"], check=True, capture_output=True, text=True, timeout=5)
                    values = json.loads(measured.stdout).get("stat", [])
                    assert any(int(x.get("value", 0)) > 0 and row["uuid"] in x["name"] for x in values)
                    online = subprocess.run([CORE, "api", "statsonlineiplist", "--server=unix://" + str(api_socket), "-all"], check=True, capture_output=True, text=True, timeout=5)
                    assert "198.51.100.42" in online.stdout, online.stdout
                    assert "203.0.113.66" not in online.stdout
            except Exception as exc:
                log.flush(); server_log.flush(); front_log.flush()
                logs = "\n".join(f"{p.name}:\n{p.read_text()}" for p in tmp_path.glob("*.log"))
                raise AssertionError(f"{protocol} transport failed:\n{logs}") from exc
            finally:
                proc.terminate(); proc.wait(timeout=5); log.close()
    finally:
        if front_proc is not None:
            front_proc.terminate(); front_proc.wait(timeout=5); front_log.close()
        server_proc.terminate(); server_proc.wait(timeout=5); server_log.close()
        http.shutdown(); http.server_close(); udp.shutdown(); udp.server_close()
