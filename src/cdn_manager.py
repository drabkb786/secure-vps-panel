"""CloudFront WS delivery: private origin guard, reproducible AWS setup and probes.

No AWS credentials are stored or used here. See docs/cloudfront.md for sources,
trust boundaries, deployment and the difference between probes and tunnel tests.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import ssl
import time
import gateway_identity
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from common import BASE_DIR, DOMAIN_FILE, ValidationError, atomic_write, atomic_write_json, read_json, read_text, validate_domain

CONFIG_FILE = BASE_DIR / "cloudfront.json"
CERT_ROOT = Path("/etc/letsencrypt/live")
HEADER = "X-Noway-Origin-Verify"
PREFIX = "/cloudfront"
PATHS = {p: PREFIX + "/" + p for p in ("vless", "vmess", "trojan")}
PATHS.update(ssh=PREFIX + "/ssh/ws", health=PREFIX + "/health", xhttp=PREFIX + "/xhttp/")
PATHS["ssh_cgi"] = PREFIX + "/cdn-cgi"
PRICE_CLASSES = {"PriceClass_All", "PriceClass_200", "PriceClass_100"}


def endpoint(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"d[a-z0-9]{5,62}\.cloudfront\.net", value):
        raise ValidationError("Use the distribution hostname: d….cloudfront.net (no URL, path or port)")
    return value


def settings() -> dict:
    cfg = read_json(CONFIG_FILE, None) if CONFIG_FILE.exists() else {}
    if not isinstance(cfg, dict):
        raise ValidationError("CloudFront settings are invalid; restore the private configuration")
    cfg = {"enabled": False, "endpoint": "", "price_class": "PriceClass_All", **cfg}
    if cfg["enabled"]:
        validate_domain(cfg.get("origin", ""))
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", cfg.get("secret", "")):
            raise ValidationError("CloudFront origin secret is invalid")
    if cfg["endpoint"]:
        endpoint(cfg["endpoint"])
    if cfg["price_class"] not in PRICE_CLASSES:
        raise ValidationError("Unknown CloudFront price class")
    return cfg


def delivery(route: str, domain: str) -> tuple[str, str]:
    if route == "direct":
        return domain, ""
    if route == "bunny":
        import bunny_manager
        cfg = bunny_manager.settings()
        if not cfg["enabled"] or cfg.get("origin") != domain:
            raise ValidationError("Configure Bunny delivery for this origin first")
        return cfg["endpoint"], bunny_manager.PREFIX
    if route != "cloudfront":
        raise ValidationError("Choose direct, cloudfront or bunny delivery")
    cfg = settings()
    if not cfg["enabled"] or not cfg["endpoint"] or cfg.get("origin") != domain:
        raise ValidationError("Prepare CloudFront and attach its distribution hostname first")
    return cfg["endpoint"], PREFIX


def nginx_maps(cfg: dict) -> str:
    # Every secret-bearing request outside the dedicated path allowlist is denied.
    paths = "    ~^/cloudfront/xhttp/ 1;\n" + "\n".join(f'    {path} 1;' for path in PATHS.values())
    secret = cfg["secret"] if cfg["enabled"] else "disabled"
    return f'''
map $http_x_noway_origin_verify $noway_cf_verified {{
    default 0;
    "{secret}" {1 if cfg['enabled'] else 0};
}}
map $http_x_noway_origin_verify $noway_cf_header_present {{
    default 1;
    "" 0;
}}
map $uri $noway_cf_path {{
    default 0;
{paths}
}}
map "$noway_cf_header_present:$noway_cf_path" $noway_cf_forbidden {{
    default 0;
    "1:0" 1;
}}
map $http_x_noway_viewer_ip $noway_cf_viewer_ip {{
    default "";
    ~^[0-9.]+$ $http_x_noway_viewer_ip;
    ~^[0-9A-Fa-f:]+$ $http_x_noway_viewer_ip;
}}
'''


def nginx_locations(cfg: dict, secure: bool) -> str:
    text = "    location /cloudfront/ { return 404; }\n"
    for name, path in PATHS.items():
        selector = "^~" if name == "xhttp" else "="
        if not cfg["enabled"] or not secure:
            text += f"    location {selector} {path} {{ return 403; }}\n"
            continue
        text += f'''    location {selector} {path} {{
        if ($noway_cf_verified = 0) {{ return 403; }}
        if ($noway_cf_viewer_ip = "") {{ return 503; }}
        access_log off;
        error_log /dev/null crit;
'''
        if name == "health":
            text += '        default_type text/plain;\n        add_header X-Noway-CloudFront-Health 1 always;\n        return 200 "noway-cloudfront-origin-v1\\n";\n    }\n'
            continue
        port = {"vless": 10001, "vmess": 10002, "trojan": 10003, "ssh": 2082, "ssh_cgi": 2082, "xhttp": 10004}[name]
        target = "/cdn-cgi" if name == "ssh_cgi" else "/ssh/ws" if name == "ssh" else gateway_identity.backend_path(name)
        upgrade = "" if name == "xhttp" else "$abdulbasit_connection_upgrade"
        text += f'''        client_max_body_size 32m;
        proxy_pass http://127.0.0.1:{port}{target};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "{upgrade}";
        proxy_set_header X-Noway-Origin-Verify "";
        proxy_set_header X-Forwarded-For $noway_cf_viewer_ip;
        proxy_set_header X-Real-IP $noway_cf_viewer_ip;
        proxy_set_header X-Noway-Gateway 1;
        proxy_set_header Cookie "";
        proxy_set_header Authorization "";
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_socket_keepalive on;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
'''
    return text


def template() -> dict:
    """Original CloudFormation from AWS documented resource schemas, not vendor code."""
    ref = lambda name: {"Ref": name}
    paths = json.dumps(list(PATHS.values()), separators=(",", ":"))
    function = "function handler(event) { var r = event.request; var paths = " + paths + "; var xhttp = r.uri.indexOf('/cloudfront/xhttp/') === 0; if (xhttp ? (r.method !== 'GET' && r.method !== 'POST') : ((r.method !== 'GET' && r.method !== 'HEAD') || paths.indexOf(r.uri) === -1)) { return {statusCode: 403, statusDescription: 'Forbidden'}; } r.headers['x-noway-viewer-ip'] = {value: event.viewer.ip}; return r; }"
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "NOWAY CloudFront WebSocket gateway; AWS usage charges apply. No admin or subscription delivery.",
        "Parameters": {
            "OriginDomain": {"Type": "String", "AllowedPattern": r"[a-z0-9][a-z0-9.-]+[a-z0-9]", "Description": "Public DNS-only VPS hostname with a valid TLS certificate"},
            "OriginSecret": {"Type": "String", "NoEcho": True, "AllowedPattern": "[A-Za-z0-9_-]{43}", "Description": "Private panel-generated origin header; never put in a client profile"},
            "PriceClass": {"Type": "String", "Default": "PriceClass_All", "AllowedValues": sorted(PRICE_CLASSES), "Description": "All edge regions for coverage; actual cost and speed vary"},
        },
        "Resources": {
            "OriginPolicy": {"Type": "AWS::CloudFront::OriginRequestPolicy", "Properties": {"OriginRequestPolicyConfig": {
                "Name": {"Fn::Sub": "${AWS::StackName}-ws"},
                "HeadersConfig": {"HeaderBehavior": "whitelist", "Headers": ["Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol", "Sec-WebSocket-Accept", "Sec-WebSocket-Extensions", "Referer", "Content-Type", "X-Padding", "X-Noway-Viewer-IP"]},
                "CookiesConfig": {"CookieBehavior": "none"}, "QueryStringsConfig": {"QueryStringBehavior": "all"},
            }}},
            "RouteGuard": {"Type": "AWS::CloudFront::Function", "Properties": {
                "Name": {"Fn::Sub": "${AWS::StackName}-routes"}, "AutoPublish": True,
                "FunctionCode": function, "FunctionConfig": {"Comment": "Allow only NOWAY tunnel and health routes", "Runtime": "cloudfront-js-2.0"},
            }},
            "Distribution": {"Type": "AWS::CloudFront::Distribution", "Properties": {"DistributionConfig": {
                "Enabled": True, "IPV6Enabled": True, "HttpVersion": "http2and3", "PriceClass": ref("PriceClass"),
                "Comment": "NOWAY WS gateway; SSH uses RFC6455 binary framing",
                "Origins": [{"Id": "VPS", "DomainName": ref("OriginDomain"),
                             "OriginCustomHeaders": [{"HeaderName": HEADER, "HeaderValue": ref("OriginSecret")}],
                             "CustomOriginConfig": {"HTTPSPort": 443, "OriginProtocolPolicy": "https-only", "OriginSSLProtocols": ["TLSv1.2"], "OriginReadTimeout": 60, "OriginKeepaliveTimeout": 60}}],
                "DefaultCacheBehavior": {"TargetOriginId": "VPS", "ViewerProtocolPolicy": "https-only", "AllowedMethods": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"], "CachedMethods": ["GET", "HEAD"], "Compress": False,
                                         "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad", "OriginRequestPolicyId": ref("OriginPolicy"),
                                         "FunctionAssociations": [{"EventType": "viewer-request", "FunctionARN": {"Fn::GetAtt": ["RouteGuard", "FunctionMetadata.FunctionARN"]}}]},
                "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
            }}},
        },
        "Outputs": {"DistributionDomain": {"Value": {"Fn::GetAtt": ["Distribution", "DomainName"]}}, "DistributionId": {"Value": ref("Distribution")}},
    }


def probe(host: str, path: str, websocket: bool, provider="cloudfront") -> dict:
    """TLS-verified probe, pinned public address; never follow redirects or send secrets."""
    (endpoint if provider == "cloudfront" else validate_domain)(host)
    started = time.monotonic()
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if not answers or any(not ipaddress.ip_address(row[4][0]).is_global for row in answers):
            raise ValueError("non-public DNS")
        family, kind, proto, _, address = answers[0]
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        with socket.socket(family, kind, proto) as raw:
            raw.settimeout(6)
            raw.connect(address)
            with context.wrap_socket(raw, server_hostname=host) as conn:
                headers = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                headers += f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n" if websocket else "Connection: close\r\n"
                conn.sendall((headers + "\r\n").encode())
                data = b""
                deadline = time.monotonic() + 6
                while b"\r\n\r\n" not in data and len(data) < 16384:
                    conn.settimeout(max(.01, deadline - time.monotonic()))
                    chunk = conn.recv(min(4096, 16384 - len(data)))
                    if not chunk: break
                    data += chunk
                    if time.monotonic() >= deadline: break
                head, sep, body = data.partition(b"\r\n\r\n")
                lines = head.decode("iso-8859-1").split("\r\n")
                status = int(lines[0].split()[1])
                fields = {k.lower(): v.strip() for line in lines[1:] if ":" in line for k, v in [line.split(":", 1)]}
                edge = "x-amz-cf-id" in fields and "cloudfront" in fields.get("via", "").lower()
                if provider == "bunny":
                    edge = fields.get("server", "").lower().startswith("bunnycdn") and "cdn-pullzone" in fields
                if websocket:
                    accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                    ok = bool(sep) and status == 101 and fields.get("sec-websocket-accept") == accept and fields.get("upgrade", "").lower() == "websocket"
                else:
                    # Marker header avoids assumptions about chunked/body packet boundaries.
                    ok = bool(sep) and status == 200 and fields.get("x-noway-" + provider + "-health") == "1"
                return {"ok": ok and edge, "http_status": status, "cloudfront_headers": edge if provider == "cloudfront" else False, "edge_headers": edge, "elapsed_ms": round((time.monotonic() - started) * 1000)}
    except (OSError, ValueError, IndexError):
        return {"ok": False, "error": "DNS, TLS or connection check failed", "elapsed_ms": round((time.monotonic() - started) * 1000)}


def probe_paths(endpoint, paths, provider="cloudfront"):
    """Bound parallel read-only probes; persist the combined report once."""
    routes = [(name, path) for name, path in paths.items() if name != "xhttp"]
    def check(route):
        name, path = route
        result = probe(endpoint, path, name != "health") if provider == "cloudfront" else probe(endpoint, path, name != "health", provider=provider)
        return name, result
    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="cdn-probe") as pool:
        return dict(pool.map(check, routes))


class Manager:
    def __init__(self, install_nginx):
        self.install_nginx = install_nginx

    def status(self, _=None):
        cfg = settings()
        return {k: cfg.get(k) for k in ("enabled", "endpoint", "origin", "price_class", "last_check")} | {
            "stage": "attached" if cfg["enabled"] and cfg["endpoint"] else "prepared" if cfg["enabled"] else "disabled",
            "paths": PATHS, "ssh_url": f"wss://{cfg['endpoint']}{PATHS['ssh']}" if cfg["enabled"] and cfg["endpoint"] else "",
            "notice": "AWS charges apply. Run the endpoint check after distribution deployment. A handshake check does not test account login or throughput.",
        }

    def configure(self, params):
        enabled = params.get("enabled")
        if not isinstance(enabled, bool): raise ValidationError("enabled must be a boolean")
        cfg = settings()
        domain = validate_domain(read_text(DOMAIN_FILE))
        if enabled:
            if not all((CERT_ROOT / domain / f).is_file() for f in ("fullchain.pem", "privkey.pem")):
                raise ValidationError("Set the origin domain and issue a valid TLS certificate first")
            host = params.get("endpoint", cfg["endpoint"])
            if not isinstance(host, str): raise ValidationError("Distribution hostname must be text")
            if host: endpoint(host)
            price = params.get("price_class", cfg["price_class"])
            if price not in PRICE_CLASSES: raise ValidationError("Unknown CloudFront price class")
            cfg.update(origin=domain, endpoint=host, price_class=price)
            cfg.setdefault("secret", secrets.token_urlsafe(32))
        cfg["enabled"] = enabled
        cfg.pop("last_check", None)
        old = CONFIG_FILE.read_text() if CONFIG_FILE.exists() else None
        atomic_write_json(CONFIG_FILE, cfg)
        try:
            self.install_nginx(domain)
        except Exception:
            if old is None: CONFIG_FILE.unlink(missing_ok=True)
            else: atomic_write(CONFIG_FILE, old)
            # Nginx installer restores its previous file and runtime configuration.
            raise RuntimeError("CloudFront change rolled back: Nginx validation or reload failed") from None
        return self.status()

    def setup(self, _=None):
        cfg = settings()
        if not cfg["enabled"]: raise ValidationError("Prepare the CloudFront origin first")
        parameters = [{"ParameterKey": k, "ParameterValue": v} for k, v in (("OriginDomain", cfg["origin"]), ("OriginSecret", cfg["secret"]), ("PriceClass", cfg["price_class"]))]
        return {"files": {"cloudfront.json": json.dumps(template(), indent=2) + "\n", "parameters.private.json": json.dumps(parameters, indent=2) + "\n",
                          "README.txt": "PRIVATE SETUP: parameters.private.json contains your origin secret. Keep this ZIP private; do not commit it.\nAWS usage charges apply. Use aws cloudformation create-stack --stack-name noway-ws --template-body file://cloudfront.json --parameters file://parameters.private.json\nWait for CREATE_COMPLETE and Distribution Status=Deployed. Attach DistributionDomain in the panel, then run endpoint checks and a real client transfer.\nSee docs/cloudfront.md in the source repository.\n"}}

    def check(self, _=None):
        cfg = settings()
        if not cfg["enabled"] or not cfg["endpoint"]: raise ValidationError("Attach a distribution hostname first")
        checks = probe_paths(cfg["endpoint"], PATHS)
        report = {"checked_at": datetime.now(timezone.utc).isoformat(), "endpoint": cfg["endpoint"], "ok": all(c["ok"] for c in checks.values()), "checks": checks,
                  "scope": "TLS, CloudFront response headers, origin health and WebSocket upgrades; account authentication and speed not tested"}
        cfg["last_check"] = report
        atomic_write_json(CONFIG_FILE, cfg)
        return report
