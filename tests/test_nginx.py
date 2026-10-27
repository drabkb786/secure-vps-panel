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
