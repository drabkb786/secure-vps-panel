"""Parse generated Nginx sites with a real binary, without installing a live site."""
import os
import subprocess
import socket

import pytest

import paneld

NGINX = os.environ.get("NGINX_TEST_BINARY", "")
pytestmark = pytest.mark.skipif(not NGINX, reason="NGINX_TEST_BINARY is not set")


@pytest.mark.parametrize("tls", [False, True])
def test_real_nginx_accepts_generated_routes(tmp_path, tls, monkeypatch):
    cert, key = tmp_path / "fullchain.pem", tmp_path / "privkey.pem"
    if tls:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=vpn.example.com"], check=True, capture_output=True, timeout=20)
    monkeypatch.setattr(paneld, "ipv6_enabled", lambda: False)
    site = paneld.nginx_text("vpn.example.com", tls)
    for port, suffix in ((80, ""), (443, " ssl http2")):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); test_port = sock.getsockname()[1]
        site = site.replace(f"listen {port}{suffix};", f"listen 127.0.0.1:{test_port}{suffix};")
    site = site.replace("/etc/letsencrypt/live/vpn.example.com/fullchain.pem", str(cert)).replace("/etc/letsencrypt/live/vpn.example.com/privkey.pem", str(key))
    # Keep all routes; use fixture certificates, paths and loopback high ports.
    config = tmp_path / "nginx.conf"
    user = "user root root;\n" if os.geteuid() == 0 else ""
    config.write_text(user + f"pid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/error.log;\nevents {{}}\nhttp {{\naccess_log off;\n" +
                      "\n".join(f"{name}_temp_path {tmp_path}/{name};" for name in ("client_body", "proxy", "fastcgi", "scgi", "uwsgi")) + "\n" + site + "\n}\n")
    result = subprocess.run([NGINX, "-t", "-p", str(tmp_path), "-c", str(config)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


def test_cloudfront_origin_guard_and_no_admin_forwarding(tmp_path, monkeypatch):
    import http.client
    import ssl
    import time
    from cloudfront_fixture import enable_origin
    secret = enable_origin(tmp_path, monkeypatch)
    monkeypatch.setattr(paneld, "ipv6_enabled", lambda: False)
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
    def free():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); return sock.getsockname()[1]
    port, plain = free(), free()
    site = paneld.nginx_text("vpn.example.com", True).replace("listen 80;", f"listen 127.0.0.1:{plain};").replace("listen 443 ssl http2;", f"listen 127.0.0.1:{port} ssl;")
    site = site.replace("/etc/letsencrypt/live/vpn.example.com/fullchain.pem", str(cert)).replace("/etc/letsencrypt/live/vpn.example.com/privkey.pem", str(key))
    config = tmp_path / "nginx.conf"
    config.write_text(f"master_process off; pid {tmp_path}/nginx.pid; error_log {tmp_path}/error.log; events {{}} http {{ access_log off; " + site + " }")
    process = subprocess.Popen([NGINX, "-p", str(tmp_path), "-c", str(config), "-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1): break
            except OSError: time.sleep(.03)
        context = ssl.create_default_context(cafile=str(cert))
        def request(path, value=None, tls=True):
            conn = http.client.HTTPSConnection("localhost", port, context=context, timeout=3) if tls else http.client.HTTPConnection("localhost", plain, timeout=3)
            conn.request("GET", path, headers={"X-Noway-Origin-Verify": value} if value is not None else {})
            response = conn.getresponse(); result = response.status, response.read(), dict(response.getheaders()); conn.close(); return result
        for path in ("/cloudfront/health", "/cloudfront/vless", "/cloudfront/vmess", "/cloudfront/trojan", "/cloudfront/ssh/ws"):
            assert request(path)[0] == 403
            assert request(path, "wrong")[0] == 403
            assert request(path, secret, tls=False)[0] == 403
        for path in ("/panel/", "/panel/api/state", "/panel/sub/" + "A" * 43, "/vless", "/ssh/raw", "/", "/cloudfront/../panel/"):
            assert request(path, secret)[0] == 403
        status, body, headers = request("/cloudfront/health", secret)
        assert status == 200 and body == b"noway-cloudfront-origin-v1\n" and headers["X-Noway-CloudFront-Health"] == "1"
        assert request("/cloudfront/unknown")[0] == 404
    finally:
        process.terminate(); process.wait(timeout=5)
