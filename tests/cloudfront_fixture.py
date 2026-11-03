"""Local TLS edge simulation, NOT a test against the AWS CloudFront service."""
import secrets
import cdn_manager as cdn
from common import atomic_write_json


def enable_origin(tmp_path, monkeypatch, provider="cloudfront"):
    if provider == "bunny":
        import bunny_manager
        monkeypatch.setattr(bunny_manager, "CONFIG_FILE", tmp_path / "bunny.json")
        secret = secrets.token_urlsafe(32)
        atomic_write_json(bunny_manager.CONFIG_FILE, {"enabled": True, "origin": "vpn.example.com", "endpoint": "d123example.cloudfront.net", "secret": secret})
        return secret

    monkeypatch.setattr(cdn, "CONFIG_FILE", tmp_path / "cloudfront.json")
    secret = secrets.token_urlsafe(32)
    atomic_write_json(cdn.CONFIG_FILE, {"enabled": True, "origin": "vpn.example.com", "endpoint": "d123example.cloudfront.net", "secret": secret})
    return secret


def edge_server(port, origin_port, cert, key, secret, provider="cloudfront"):
    headers = "\n".join(f"proxy_set_header {name} $http_{name.lower().replace('-', '_')};" for name in ("Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions", "Referer", "Content-Type", "X-Padding"))
    verify = "X-Noway-Bunny-Verify" if provider == "bunny" else "X-Noway-Origin-Verify"
    viewer = "X-Noway-Bunny-Viewer-IP" if provider == "bunny" else "X-Noway-Viewer-IP"
    return f'''server {{
        listen 127.0.0.1:{port} ssl http2;
        server_name d123example.cloudfront.net;
        ssl_certificate {cert}; ssl_certificate_key {key};
        location / {{
            proxy_pass https://127.0.0.1:{origin_port};
            proxy_ssl_server_name on; proxy_ssl_name vpn.example.com;
            proxy_ssl_verify on; proxy_ssl_trusted_certificate {cert};
            proxy_http_version 1.1; proxy_buffering off; proxy_request_buffering off;
            proxy_pass_request_headers off;
            proxy_set_header Host vpn.example.com;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $abdulbasit_connection_upgrade;
            proxy_set_header {verify} {secret};
            proxy_set_header {viewer} 198.51.100.42;
            {headers}
        }}
    }}'''
