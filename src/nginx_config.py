#!/usr/bin/env python3
"""Render the panel-owned Nginx configuration."""

from __future__ import annotations

from typing import Any

from common import validate_domain, validate_origin_secret
from protocols import normalize_protocol_settings


def _ws_proxy(port: int, path: str, indent: str = "        ") -> str:
    return (
        f"{indent}proxy_pass http://127.0.0.1:{port}{path};\n"
        f"{indent}proxy_http_version 1.1;\n"
        f"{indent}proxy_set_header Upgrade $http_upgrade;\n"
        f"{indent}proxy_set_header Connection $abdulbasit_connection_upgrade;\n"
        f"{indent}proxy_set_header Host $host;\n"
        f"{indent}proxy_set_header X-Real-IP $remote_addr;\n"
        f"{indent}proxy_set_header X-Forwarded-For $remote_addr;\n"
        f"{indent}proxy_buffering off;\n"
        f"{indent}proxy_read_timeout 3600s;\n"
        f"{indent}proxy_send_timeout 3600s;\n"
        f"{indent}limit_conn abdulbasit_per_ip 20;\n"
    )


def _xray_locations(settings: dict[str, Any], cloudfront_secret: str = "") -> str:
    chunks: list[str] = []
    for protocol in ("vmess", "vless", "trojan"):
        item = settings[protocol]
        path = item["path"]
        chunks.append(
            f"    location = {path} {{\n"
            + (
                '        if ($http_x_abdulbasit_origin_verify != "") { return 404; }\n'
                if cloudfront_secret
                else ""
            )
            + _ws_proxy(int(item["port"]), path)
            + "    }\n"
        )
        if cloudfront_secret:
            cf_path = "/cloudfront" + path
            chunks.append(
                f"    location = {cf_path} {{\n"
                f'        if ($http_x_abdulbasit_origin_verify != "{cloudfront_secret}") {{ return 403; }}\n'
                + _ws_proxy(int(item["port"]), path)
                + "    }\n"
            )
    return "\n".join(chunks)


def _dashboard_location(*, reject_cloudfront: bool) -> str:
    origin_guard = (
        '        if ($http_x_abdulbasit_origin_verify != "") { return 404; }\n'
        if reject_cloudfront
        else ""
    )
    return (
        "\n    location ^~ /panel/ {\n"
        + origin_guard
        + """        proxy_pass http://127.0.0.1:9080/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /panel;
        proxy_buffering off;
        client_max_body_size 64k;
        limit_req zone=abdulbasit_panel burst=30 nodelay;
    }
"""
    )


def render_nginx_config(
    domain: str,
    *,
    tls: bool,
    ipv6: bool,
    cdn_config: dict[str, Any] | None = None,
    protocol_settings: dict[str, Any] | None = None,
    dashboard: bool = True,
) -> str:
    domain = validate_domain(domain)
    settings = normalize_protocol_settings(protocol_settings)
    cloudfront_secret = ""
    profiles = (cdn_config or {}).get("profiles", {})
    cloudfront = profiles.get("cloudfront") if isinstance(profiles, dict) else None
    if isinstance(cloudfront, dict) and cloudfront.get("enabled"):
        cloudfront_secret = validate_origin_secret(
            str(cloudfront.get("origin_secret", ""))
        )

    v6_http = "    listen [::]:80;\n" if ipv6 else ""
    v6_tls = "    listen [::]:443 ssl;\n" if ipv6 else ""
    tls_locations = _xray_locations(settings, cloudfront_secret)
    dashboard_location = (
        _dashboard_location(reject_cloudfront=bool(cloudfront_secret))
        if dashboard
        else ""
    )
    cloudfront_fallback_guard = (
        '        if ($http_x_abdulbasit_origin_verify != "") { return 404; }\n'
        if cloudfront_secret
        else ""
    )

    tls_block = ""
    if tls:
        tls_block = f"""
server {{
    listen 443 ssl;
{v6_tls}    server_name {domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security \"max-age=31536000\" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    server_tokens off;
    client_header_timeout 10s;
    client_body_timeout 10s;
    client_max_body_size 1k;

    location = /healthz {{
        default_type application/json;
        add_header Cache-Control \"no-store\";
        return 200 '{{\"ok\":true,\"service\":\"abdulbasit-panel\"}}';
    }}

{tls_locations}
{dashboard_location}
    location / {{
{cloudfront_fallback_guard}        proxy_pass http://127.0.0.1:2082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $abdulbasit_connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        limit_conn abdulbasit_per_ip 20;
        limit_req zone=abdulbasit_requests burst=20 nodelay;
    }}
}}
"""

    return f"""# Managed by Abdul Basit VPS Panel. Manual edits may be overwritten.
map $http_upgrade $abdulbasit_connection_upgrade {{
    default upgrade;
    '' close;
}}

limit_conn_zone $binary_remote_addr zone=abdulbasit_per_ip:10m;
limit_req_zone $binary_remote_addr zone=abdulbasit_requests:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=abdulbasit_panel:10m rate=60r/m;

server {{
    listen 80;
{v6_http}    server_name {domain};

    server_tokens off;
    client_header_timeout 10s;
    client_body_timeout 10s;
    client_max_body_size 1k;

    location ^~ /.well-known/acme-challenge/ {{
        root /var/www/letsencrypt;
        default_type text/plain;
        try_files $uri =404;
    }}

    location / {{
        proxy_pass http://127.0.0.1:2082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $abdulbasit_connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        limit_conn abdulbasit_per_ip 20;
        limit_req zone=abdulbasit_requests burst=20 nodelay;
    }}
}}
{tls_block}"""
