#!/usr/bin/env python3
"""Privileged, narrow command daemon for Abdul Basit VPS Panel.

The Telegram bot never runs as root. It can only request allow-listed operations
through this UNIX socket. Every parameter is validated again in this daemon.
"""
from __future__ import annotations

import grp
import json
import logging
import os
import pwd
import re
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable

import diagnostics
import web_auth
import xray_manager
import operations
import slowdns
import cdn_manager
import bunny_manager
import ssh_profiles
import gateway_identity
import ssh_identity
from common import validate_max_ips

from common import (
    ADMIN_IDS_FILE,
    BASE_DIR,
    BOT_TOKEN_FILE,
    CERTBOT_EMAIL_FILE,
    DOMAIN_FILE,
    SOCKET_PATH,
    SUPER_ADMIN_FILE,
    USERS_DIR,
    ValidationError,
    atomic_write,
    atomic_write_json,
    calculate_expiry,
    ensure_secure_permissions,
    is_secure_regular_file,
    read_json,
    read_text,
    validate_bot_token,
    validate_days,
    validate_domain,
    validate_password,
    validate_ssh_password,
    validate_quota,
    validate_service,
    validate_sessions,
    validate_telegram_id,
    validate_username,
)

LOG = logging.getLogger("abdulbasit-paneld")
OP_LOCK = threading.RLock()
CONNECTION_SLOTS = threading.BoundedSemaphore(20)
MAX_REQUEST = 512 * 1024
NGINX_CONFIG = Path("/etc/nginx/conf.d/abdulbasit-vpn.conf")
ACME_ROOT = Path("/var/www/letsencrypt")
SERVICE_MAP = {
    "nginx": "nginx",
    "haproxy": "abdulbasit-haproxy",
    "dropbear": "dropbear",
    "abdulbasit-sshd": "abdulbasit-sshd",
    "abdulbasit-ws": "abdulbasit-ws",
    "abdulbasit-session-enforcer": "abdulbasit-session-enforcer",
    "abdulbasit-bot": "abdulbasit-bot",
    "abdulbasit-paneld": "abdulbasit-paneld",
    "abdulbasit-web": "abdulbasit-web",
    "abdulbasit-xray": "abdulbasit-xray",
}
SERVICE_MAP["abdulbasit-dnstt"] = "abdulbasit-dnstt.service"


def binary(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"Required command not found: {name}")
    return path


def run(args: list[str], *, input_text: str | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    LOG.info("Executing allow-listed command: %s", " ".join(args[:2]))
    completed = subprocess.run(
        args,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env={"PATH": "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    if completed.returncode != 0:
        detail_lines = (completed.stderr or completed.stdout or "").strip().splitlines()
        detail = detail_lines[-1][:500] if detail_lines else f"exit status {completed.returncode}"
        raise RuntimeError(f"{Path(args[0]).name} failed: {detail}")
    return completed


def set_group_readable(path: Path) -> None:
    try:
        gid = grp.getgrnam("abdulbasit").gr_gid
        os.chown(path, 0, gid)
        os.chmod(path, 0o640)
    except (KeyError, FileNotFoundError):
        pass


def user_file(username: str) -> Path:
    return USERS_DIR / f"{validate_username(username)}.json"


def managed_user(username: str) -> dict[str, Any]:
    path = user_file(username)
    if not is_secure_regular_file(path):
        raise ValidationError("Managed user metadata is missing or unsafe")
    data = read_json(path)
    if not isinstance(data, dict):
        raise ValidationError("Managed user does not exist")
    return data


def get_shadow_expiry(username: str) -> str | None:
    try:
        result = run([binary("chage"), "-l", username])
    except (subprocess.CalledProcessError, RuntimeError):
        return None
    for line in result.stdout.splitlines():
        if line.lower().startswith("account expires"):
            value = line.split(":", 1)[1].strip()
            if value.lower() == "never":
                return None
            try:
                return datetime.strptime(value, "%b %d, %Y").date().isoformat()
            except ValueError:
                return None
    return None


def create_user(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    password = validate_ssh_password(str(params.get("password", "")))
    days = validate_days(params.get("days"))
    max_sessions = validate_sessions(params.get("max_sessions"))
    quota_gb = validate_quota(params.get("quota_gb", "Unlimited"))
    max_ips = validate_max_ips(params.get("max_ips", 0))
    if quota_gb is not None:
        raise ValidationError("SSH byte quotas are not supported by this SSH accounting backend. Use Unlimited, or a metered Xray profile; no unenforced quota will be saved.")

    if user_file(username).exists():
        raise ValidationError("This managed username already exists")
    try:
        pwd.getpwnam(username)
        raise ValidationError("A system account with this username already exists")
    except KeyError:
        pass

    expiry = calculate_expiry(days)
    import ssh_backend
    groups = ["--groups", ssh_backend.GROUP] if ssh_backend.group_required() else []
    run([
        binary("useradd"), "--no-create-home", "--shell", "/usr/local/lib/abdulbasit/tunnel-shell",
        "--expiredate", expiry, "--user-group", *groups, username,
    ])
    try:
        run([binary("chpasswd")], input_text=f"{username}:{password}\n")
    except Exception:
        subprocess.run([binary("userdel"), "--force", username], capture_output=True, text=True, check=False)
        raise

    metadata = {
        "username": username,
        "expiry": expiry,
        "max_sessions": max_sessions,
        "max_ips": max_ips,
        "quota_gb": quota_gb,
        "quota_enforced": False,
        "enabled": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_json(user_file(username), metadata, 0o600)
    return {"user": metadata, "warning": "SSH byte usage is unavailable. IP limits use unique verified sources; unknown/SlowDNS sources cannot use an IP-limited account. Enforcement checks every five seconds."}


def delete_user(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    managed_user(username)
    import ssh_sessions as dropbear_sessions
    try:
        uid = pwd.getpwnam(username).pw_uid
        current = dropbear_sessions.snapshot(USERS_DIR)["sessions"].get(uid, [])
        dropbear_sessions.terminate([p.pid for p in current], uid, USERS_DIR)
    except KeyError:
        pass
    subprocess.run([binary("pkill"), "-TERM", "-u", username], capture_output=True, text=True, check=False)
    result = subprocess.run([binary("userdel"), "--force", username], capture_output=True, text=True, check=False)
    if result.returncode not in (0, 6):
        raise RuntimeError(result.stderr.strip() or "Failed to delete user")
    user_file(username).unlink(missing_ok=True)
    return {"username": username}


def renew_user(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    days = validate_days(params.get("days"))
    data = managed_user(username)
    expiry = calculate_expiry(days, str(data.get("expiry") or ""))
    run([binary("usermod"), "--expiredate", expiry, username])
    if data.get("enabled", True):
        subprocess.run([binary("passwd"), "--unlock", username], capture_output=True, text=True, check=False)
    else:
        run([binary("usermod"), "--expiredate", "1970-01-02", username])
    data["expiry"] = expiry
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    atomic_write_json(user_file(username), data, 0o600)
    return {"username": username, "expiry": expiry}


def set_sessions(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    limit = validate_sessions(params.get("max_sessions"))
    data = managed_user(username)
    data["max_sessions"] = limit
    if "max_ips" in params:
        data["max_ips"] = validate_max_ips(params["max_ips"])
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    atomic_write_json(user_file(username), data, 0o600)
    return {"username": username, "max_sessions": limit, "max_ips": data.get("max_ips", 0)}


def set_user_lock(params):
    username = validate_username(str(params.get("username", "")))
    enabled = params.get("enabled")
    if not isinstance(enabled, bool): raise ValidationError("enabled must be a boolean")
    data = managed_user(username)
    if enabled and date.fromisoformat(data["expiry"]) <= date.today():
        raise ValidationError("Renew the expired SSH account before unlocking")
    previous_enabled = data.get("enabled", True)
    run([binary("usermod"), "--unlock" if enabled else "--lock", "--expiredate", data["expiry"] if enabled else "1970-01-02", username])
    data["enabled"] = enabled
    try:
        atomic_write_json(user_file(username), data)
    except Exception:
        run([binary("usermod"), "--unlock" if previous_enabled else "--lock", "--expiredate", data["expiry"] if previous_enabled else "1970-01-02", username])
        raise
    if not enabled:
        from session_enforcer import terminate
        uid = pwd.getpwnam(username).pw_uid
        terminate(session_processes().get(username, []), uid)
    return {"username": username, "enabled": enabled}


def set_quota(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    quota = validate_quota(params.get("quota_gb", "Unlimited"))
    if quota is not None:
        raise ValidationError("SSH byte quotas are unavailable; refusing to save a limit that cannot be enforced. Use a metered Xray profile.")
    data = managed_user(username)
    data["quota_gb"] = quota
    data["quota_enforced"] = False
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    atomic_write_json(user_file(username), data, 0o600)
    return {"username": username, "quota_gb": quota, "quota_enforced": False}


def list_users(_: dict[str, Any]) -> dict[str, Any]:
    users: list[dict[str, Any]] = []
    for path in sorted(USERS_DIR.glob("*.json")):
        data = read_json(path)
        if not isinstance(data, dict):
            continue
        username = str(data.get("username", path.stem))
        try:
            info = pwd.getpwnam(username)
            exists = True
            uid = info.pw_uid
        except KeyError:
            exists = False
            uid = None
        item = dict(data)
        item.update(quota_enforced=False, usage_available=False)
        item.update({"exists": exists, "uid": uid, "shadow_expiry": get_shadow_expiry(username) if exists else None})
        users.append(item)
    return {"users": users}


def session_processes() -> dict[str, list[int]]:
    import ssh_sessions as dropbear_sessions
    state = dropbear_sessions.snapshot(USERS_DIR)
    return {state["users"][uid]: [p.pid for p in rows] for uid, rows in state["sessions"].items()}


def list_sessions(_: dict[str, Any]) -> dict[str, Any]:
    import ssh_sessions as dropbear_sessions
    observed = dropbear_sessions.snapshot(USERS_DIR)
    sessions = {observed["users"][uid]: [p.pid for p in rows] for uid, rows in observed["sessions"].items()}
    ips = ssh_identity.session_ips(sessions)
    return {"sessions": [{"username": name, "count": len(pids), "pids": pids,
                          "ips": sorted({ips[pid] for pid in pids if ips.get(pid)}),
                          "unknown_ip_sessions": sum(not ips.get(pid) for pid in pids)}
                         for name, pids in sorted(sessions.items()) if pids],
            "ssh_attribution": {"journal_available": observed["journal_ok"],
                                "unattributed_root_processes": observed["unattributed_root_processes"],
                                "note": "Unattributed root processes can include pre-authentication sessions. Older Dropbear builds depend on trusted journal records."}}


def ipv6_enabled() -> bool:
    try:
        return socket.has_ipv6 and Path("/proc/net/if_inet6").read_text(encoding="ascii").strip() != ""
    except OSError:
        return False


def domain_conflicts(domain: str) -> list[str]:
    conflicts: list[str] = []
    roots = [Path("/etc/nginx/conf.d"), Path("/etc/nginx/sites-enabled")]
    pattern = re.compile(r"^\s*server_name\s+[^;]*\b" + re.escape(domain) + r"\b", re.IGNORECASE | re.MULTILINE)
    managed = NGINX_CONFIG.resolve(strict=False)
    for root in roots:
        if not root.exists():
            continue
        for path in root.glob("*.conf") if root.name == "conf.d" else root.iterdir():
            try:
                if path.resolve(strict=False) == managed or not path.is_file():
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if pattern.search(text):
                conflicts.append(str(path))
    return sorted(set(conflicts))


def nginx_text(domain: str, tls: bool, *, multiplexed: bool | None = None) -> str:
    """Keep legacy SSH upgrades; route browsers and real Xray WebSockets separately."""
    cdn = cdn_manager.settings()
    bunny = bunny_manager.settings()
    network = xray_manager.settings()
    import ssh_backend
    multiplexed = ssh_backend.haproxy_enabled() if multiplexed is None else multiplexed
    def locations(secure: bool) -> str:
        blocks = """
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type text/plain;
        try_files $uri =404;
    }
    location = /panel { return 302 /panel/; }
    location ^~ /panel/sub/ {
        access_log off;
        error_log /dev/null crit;
        proxy_pass http://127.0.0.1:9090;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Noway-Gateway 1;
        proxy_set_header Connection "";
        proxy_read_timeout 30s;
        proxy_buffering off;
    }
    location /panel/ {
        proxy_pass http://127.0.0.1:9090;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Noway-Gateway 1;
        proxy_set_header Connection "";
        proxy_read_timeout 240s;
        proxy_buffering off;
    }
"""
        if secure:
            blocks += """
    location ^~ /xhttp/ {
        proxy_pass http://127.0.0.1:10004;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Noway-Gateway 1;
        proxy_set_header Connection "";
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        client_max_body_size 32m;
    }
"""
        else:
            blocks += "    location ^~ /xhttp/ { return 403; }\n"
        for protocol, (port, path) in xray_manager.PROTOCOLS.items():
            if secure or (protocol == "vless" and network.get("enabled") and network.get("vless_non_tls_enabled")):
                if not secure:
                    port = xray_manager.vless_encryption.PORT
                blocks += f"""
    location = {path} {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $abdulbasit_connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Noway-Gateway 1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        limit_conn abdulbasit_per_ip 40;
    }}
"""
            else:
                blocks += f"    location = {path} {{ return 403; }}\n"
        for ssh_path in ("/ssh/ws", "/ssh/raw"):
            blocks += f"""
    location = {ssh_path} {{
        proxy_pass http://127.0.0.1:2082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $abdulbasit_connection_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Noway-Gateway 1;
        proxy_socket_keepalive on;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        limit_conn abdulbasit_per_ip 40;
    }}
"""
        blocks += """
    location / {
        proxy_pass http://$abdulbasit_root_upstream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $abdulbasit_connection_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Noway-Gateway 1;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_socket_keepalive on;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        limit_conn abdulbasit_per_ip 40;
    }
"""
        for protocol, (port, _) in {**xray_manager.PROTOCOLS, "xhttp": (10004, "/xhttp/")}.items():
            blocks = blocks.replace(f"proxy_pass http://127.0.0.1:{port};", f"proxy_pass http://127.0.0.1:{port}{gateway_identity.backend_path(protocol)};")
        blocks = blocks.replace("proxy_pass http://127.0.0.1:10005;", f"proxy_pass http://127.0.0.1:10005{gateway_identity.backend_path('vless')};")
        return blocks + cdn_manager.nginx_locations(cdn, secure) + bunny_manager.nginx_locations(bunny, secure)

    def server(secure: bool) -> str:
        port = (8081 if secure else 8080) if multiplexed else (443 if secure else 80)
        suffix = " ssl http2" if secure else ""
        if multiplexed: suffix += " proxy_protocol"
        ipv6 = f"    listen [::]:{port}{suffix};\n" if not multiplexed and ipv6_enabled() else ""
        address = f"127.0.0.1:{port}" if multiplexed else str(port)
        verified_proxy = (f'    set_real_ip_from 127.0.0.1;\n    real_ip_header proxy_protocol;\n'
                          f'    if ($proxy_protocol_tlv_unique_id != "{ssh_backend.haproxy_secret()}") {{ return 403; }}\n') if multiplexed else ""
        certificates = f"""
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
""" if secure else ""
        return f"""
server {{
    listen {address}{suffix};
{ipv6}    server_name {domain};
{verified_proxy}
    server_tokens off;
    proxy_headers_hash_bucket_size 128;
    if ($noway_cf_forbidden) {{ return 403; }}
    if ($noway_bunny_forbidden) {{ return 403; }}
    client_header_timeout 10s;
    client_body_timeout 10s;
    client_max_body_size 16k;
{certificates}
{locations(secure)}
}}
"""
    return """# Managed by NOWAY VPS Panel. Manual edits may be overwritten.
map $http_upgrade $abdulbasit_connection_upgrade {
    default upgrade;
    '' close;
}
map $http_upgrade $abdulbasit_root_upstream {
    default 127.0.0.1:9090;
    ~*websocket 127.0.0.1:2082;
}
limit_conn_zone $binary_remote_addr zone=abdulbasit_per_ip:10m;
""" + cdn_manager.nginx_maps(cdn) + bunny_manager.nginx_maps(bunny) + (server(False) + (server(True) if tls else "")).replace("X-Noway-Gateway 1;", gateway_identity.header_name() + " 1;")


def install_nginx_config(domain: str) -> bool:
    cert_dir = Path("/etc/letsencrypt/live") / domain
    tls = (cert_dir / "fullchain.pem").is_file() and (cert_dir / "privkey.pem").is_file()
    NGINX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    old = NGINX_CONFIG.read_text(encoding="utf-8") if NGINX_CONFIG.exists() else None
    atomic_write(NGINX_CONFIG, nginx_text(domain, tls), 0o600)
    try:
        run([binary("nginx"), "-t"])
        run([binary("systemctl"), "reload-or-restart", "nginx"])
    except Exception:
        if old is None:
            NGINX_CONFIG.unlink(missing_ok=True)
        else:
            atomic_write(NGINX_CONFIG, old, 0o600)
        subprocess.run([binary("nginx"), "-t"], capture_output=True, text=True, check=False)
        subprocess.run([binary("systemctl"), "reload-or-restart", "nginx"], capture_output=True, text=True, check=False)
        raise
    return tls


def set_domain(params: dict[str, Any]) -> dict[str, Any]:
    domain = validate_domain(str(params.get("domain", "")))
    conflicts = domain_conflicts(domain)
    if conflicts:
        raise ValidationError("Domain already appears in another Nginx config: " + ", ".join(conflicts[:3]))
    ACME_ROOT.mkdir(parents=True, exist_ok=True)
    previous = read_text(DOMAIN_FILE)
    if bunny_manager.settings()["enabled"] and domain != previous:
        raise ValidationError("Disable Bunny before changing its origin domain")
    if cdn_manager.settings()["enabled"] and domain != previous:
        raise ValidationError("Disable CloudFront before changing its origin domain")
    if xray_manager.settings()["enabled"] and previous and domain != previous:
        raise ValidationError("Disable Xray before changing its domain, then issue SSL and enable it again")
    tls = install_nginx_config(domain)
    atomic_write(DOMAIN_FILE, domain + "\n", 0o640)
    set_group_readable(DOMAIN_FILE)
    return {"domain": domain, "tls": tls}


def issue_cert(params: dict[str, Any]) -> dict[str, Any]:
    domain = validate_domain(str(params.get("domain") or read_text(DOMAIN_FILE)))
    if domain != read_text(DOMAIN_FILE):
        raise ValidationError("Set this domain first before issuing its certificate")
    ACME_ROOT.mkdir(parents=True, exist_ok=True)
    install_nginx_config(domain)
    email = read_text(CERTBOT_EMAIL_FILE)
    args = [
        binary("certbot"), "certonly", "--webroot", "--webroot-path", str(ACME_ROOT),
        "--domain", domain, "--non-interactive", "--agree-tos", "--keep-until-expiring",
    ]
    if email:
        args.extend(["--email", email])
    else:
        args.append("--register-unsafely-without-email")
    run(args, timeout=180)
    tls = install_nginx_config(domain)
    if not tls:
        raise RuntimeError("Certbot completed but certificate files were not found")
    return {"domain": domain, "tls": True}


def restart_service(params: dict[str, Any]) -> dict[str, Any]:
    service = validate_service(str(params.get("service", "")))
    if service == "haproxy":
        import ssh_backend
        if not ssh_backend.haproxy_enabled():
            raise ValidationError("Migrate the public gateway to HAProxy first")
        run(["/usr/sbin/haproxy", "-c", "-f", "/etc/abdulbasit-haproxy/haproxy.cfg"])
    if service == "abdulbasit-paneld":
        raise ValidationError("The panel daemon cannot restart itself through the API")
    if service == "abdulbasit-xray" and not xray_manager.settings()["enabled"]:
        raise ValidationError("Enable Xray before restarting it")
    if service == "abdulbasit-dnstt" and not slowdns.settings()["enabled"]:
        raise ValidationError("Configure and enable SlowDNS first")
    if service == "abdulbasit-xray":
        XRAY.configure({"enabled": True})
        return {"service": service}
    unit = SERVICE_MAP[service]
    run([binary("systemctl"), "restart", unit])
    return {"service": service}


def service_status(_: dict[str, Any]) -> dict[str, Any]:
    import ssh_backend
    selected = {label: unit for label, unit in SERVICE_MAP.items()
                if (label not in {"dropbear", "abdulbasit-sshd"} or label == ssh_backend.unit())
                and (label != "haproxy" or ssh_backend.haproxy_enabled())}
    result = subprocess.run([binary("systemctl"), "show", "--property=Id,ActiveState", *selected.values()],
                            capture_output=True, text=True, check=False, timeout=5)
    states = {}
    for block in result.stdout.split("\n\n"):
        fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        states[fields.get("Id", "").removesuffix(".service")] = fields.get("ActiveState", "unknown")
    return {"services": {label: states.get(unit.removesuffix(".service"), "unknown") for label, unit in selected.items()},
            "domain": read_text(DOMAIN_FILE, "Not set"), "ssh_backend": ssh_backend.name()}


def configure_bot(params: dict[str, Any]) -> dict[str, Any]:
    token = validate_bot_token(str(params.get("token", "")))
    super_admin = validate_telegram_id(params.get("super_admin"))
    atomic_write(BOT_TOKEN_FILE, token + "\n", 0o640)
    atomic_write(SUPER_ADMIN_FILE, super_admin + "\n", 0o640)
    set_group_readable(BOT_TOKEN_FILE)
    set_group_readable(SUPER_ADMIN_FILE)
    if not ADMIN_IDS_FILE.exists():
        atomic_write(ADMIN_IDS_FILE, "", 0o640)
    set_group_readable(ADMIN_IDS_FILE)
    run([binary("systemctl"), "enable", "--now", "abdulbasit-bot"])
    run([binary("systemctl"), "restart", "abdulbasit-bot"])
    return {"super_admin": super_admin}


def list_admins(_: dict[str, Any]) -> dict[str, Any]:
    super_admin = read_text(SUPER_ADMIN_FILE)
    admins = []
    if ADMIN_IDS_FILE.exists():
        for line in ADMIN_IDS_FILE.read_text(encoding="utf-8").splitlines():
            try:
                value = validate_telegram_id(line)
            except ValidationError:
                continue
            if value not in admins and value != super_admin:
                admins.append(value)
    return {"super_admin": super_admin, "admins": sorted(admins)}


def add_admin(params: dict[str, Any]) -> dict[str, Any]:
    admin_id = validate_telegram_id(params.get("admin_id"))
    data = list_admins({})
    if admin_id == data["super_admin"]:
        return data
    admins = sorted(set(data["admins"] + [admin_id]))
    atomic_write(ADMIN_IDS_FILE, "".join(f"{item}\n" for item in admins), 0o640)
    set_group_readable(ADMIN_IDS_FILE)
    return {"super_admin": data["super_admin"], "admins": admins}


def remove_admin(params: dict[str, Any]) -> dict[str, Any]:
    admin_id = validate_telegram_id(params.get("admin_id"))
    data = list_admins({})
    if admin_id == data["super_admin"]:
        raise ValidationError("The super admin cannot be removed from the admin list")
    admins = [item for item in data["admins"] if item != admin_id]
    atomic_write(ADMIN_IDS_FILE, "".join(f"{item}\n" for item in admins), 0o640)
    set_group_readable(ADMIN_IDS_FILE)
    return {"super_admin": data["super_admin"], "admins": admins}


XRAY = xray_manager.Manager(run, gateway_apply=lambda: install_nginx_config(validate_domain(read_text(DOMAIN_FILE))))
SLOWDNS = slowdns.Manager(run)
OPS = operations.Manager(run, XRAY, service_status, install_nginx_config)


def dashboard_status(params: dict[str, Any]) -> dict[str, Any]:
    stat = shutil.disk_usage("/")
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        mem[key] = int(value.strip().split()[0]) * 1024
    return {**service_status(params), **XRAY.status(params), **list_users(params), **list_sessions(params),
            "slowdns": SLOWDNS.status({}), "bunny": BUNNY.status(), "cloudfront": CLOUDFRONT.status(), "traffic": {"sampled_at": xray_manager.traffic.state().get("sampled_at"), "scope": "Xray payload bytes; SSH byte metering unavailable", "sample_interval_seconds": 5},
            "system": {"hostname": socket.gethostname(), "load": list(os.getloadavg()),
                       "cpu_count": os.cpu_count(), "uptime_seconds": float(Path("/proc/uptime").read_text().split()[0]),
                       "disk_total": stat.total, "disk_used": stat.used,
                       "memory_total": mem.get("MemTotal", 0), "memory_available": mem.get("MemAvailable", 0)}}


CLOUDFRONT = cdn_manager.Manager(install_nginx_config)
BUNNY = bunny_manager.Manager(install_nginx_config)

HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "bunny_status": BUNNY.status,
    "bunny_configure": BUNNY.configure,
    "bunny_setup": BUNNY.setup,
    "bunny_check": BUNNY.check,
    "cloudfront_status": CLOUDFRONT.status,
    "cloudfront_configure": CLOUDFRONT.configure,
    "cloudfront_setup": CLOUDFRONT.setup,
    "cloudfront_check": CLOUDFRONT.check,
    "ssh_export": lambda params: ssh_profiles.export(params, managed_user),
    "create_user": create_user,
    "delete_user": delete_user,
    "renew_user": renew_user,
    "set_sessions": set_sessions,
    "set_quota": set_quota,
    "list_users": list_users,
    "list_sessions": list_sessions,
    "set_domain": set_domain,
    "issue_cert": issue_cert,
    "restart_service": restart_service,
    "service_status": service_status,
    "configure_bot": configure_bot,
    "list_admins": list_admins,
    "add_admin": add_admin,
    "remove_admin": remove_admin,
    "configure_web": web_auth.configure,
    "web_auth": web_auth.authenticate,
    "web_revision": lambda _: {"revision": web_auth.revision()},
    "dashboard_status": dashboard_status,
    "diagnostics": diagnostics.report,
    "dns_lookup": diagnostics.dns_lookup,
    "dns_set": XRAY.set_dns,
    "xray_status": XRAY.status,
    "xray_configure": XRAY.configure,
    "xray_create": XRAY.create,
    "xray_update": XRAY.update,
    "xray_export": XRAY.export,
    "xray_sync": XRAY.sync,
    "subscription_rotate": XRAY.subscription_rotate,
    "subscription_revoke": XRAY.subscription_revoke,
    "subscription_get": XRAY.subscription_get,
    "backup_export": XRAY.backup_export,
    "backup_restore": XRAY.backup_restore,
    "set_user_lock": set_user_lock,
    "traffic_sample": XRAY.collect_usage,
    "live_connections": OPS.connections,
    "packet_test": OPS.packet_test,
    "live_logs": OPS.logs,
    "doctor": OPS.doctor,
    "restart_managed": OPS.restart_all,
    "config_view": OPS.config_view,
    "banner_get": OPS.banner_get,
    "banner_set": OPS.banner_set,
    "memory_report": OPS.memory,
    "slowdns_status": SLOWDNS.status,
    "slowdns_configure": SLOWDNS.configure,
    "slowdns_check": SLOWDNS.check,
}

WEB_COMMANDS = {"ssh_export", "bunny_status", "bunny_configure", "bunny_setup", "bunny_check", "cloudfront_status", "cloudfront_configure", "cloudfront_setup", "cloudfront_check", "web_auth", "web_revision", "dashboard_status", "diagnostics", "dns_lookup", "dns_set",
                "xray_status", "xray_configure", "xray_create", "xray_update", "xray_export", "subscription_rotate", "subscription_revoke", "subscription_get", "backup_export",
                "create_user", "delete_user", "renew_user", "set_sessions", "set_quota", "list_users",
                "list_sessions", "service_status", "restart_service", "set_domain", "issue_cert"}
WEB_COMMANDS.update({"set_user_lock", "traffic_sample", "live_connections", "packet_test", "live_logs", "doctor", "restart_managed", "config_view", "banner_get", "banner_set", "memory_report", "slowdns_status", "slowdns_configure", "slowdns_check"})


def authorize_command(uid: int, command: str, params: dict) -> None:
    if uid == 0:
        return
    if command in {"configure_web", "backup_restore"}:
        raise ValidationError("Credential resets and backup restoration require the root CLI")
    try:
        is_web = uid == pwd.getpwnam("abdulbasit-web").pw_uid
    except KeyError:
        is_web = False
    if is_web:
        if command not in WEB_COMMANDS:
            raise ValidationError("Command is unavailable to the web service")
        if command not in {"web_auth", "web_revision", "subscription_get"} and params.pop("_web_revision", None) != web_auth.revision():
            raise ValidationError("Web session was revoked; sign in again")
        if command == "restart_service" and params.get("service") in {"abdulbasit-web", "abdulbasit-bot"}:
            raise ValidationError("Restart the web/bot service from the root CLI")


def allowed_peer(uid: int) -> bool:
    if uid == 0:
        return True
    for name in ("abdulbasit-bot", "abdulbasit-web"):
        try:
            if uid == pwd.getpwnam(name).pw_uid:
                return True
        except KeyError:
            pass
    return False


def peer_uid(conn: socket.socket) -> int:
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def handle_connection(conn: socket.socket) -> None:
    with conn:
        conn.settimeout(10)
        uid = peer_uid(conn)
        if not allowed_peer(uid):
            LOG.warning("Rejected UNIX socket peer uid=%s", uid)
            return
        data = bytearray()
        while b"\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data.extend(chunk)
            if len(data) > MAX_REQUEST:
                conn.sendall(b'{"ok":false,"error":"Request too large"}\n')
                return
        try:
            request_data = json.loads(bytes(data).split(b"\n", 1)[0].decode("utf-8"))
            command = request_data.get("command")
            params = request_data.get("params", {})
            if not isinstance(command, str) or command not in HANDLERS:
                raise ValidationError("Unknown command")
            if len(data) > 16 * 1024 and command != "backup_restore":
                raise ValidationError("Request too large")
            if not isinstance(params, dict):
                raise ValidationError("Parameters must be an object")
            # Bounded observational commands cannot mutate account/config state.
            # Run them outside the writer lock so a 15-second ping or journal
            # read does not delay quota enforcement or user creation.
            independent = command in {"packet_test", "dns_lookup", "live_logs", "memory_report", "service_status",
                                      "web_auth", "web_revision",
                                      "diagnostics", "slowdns_check", "slowdns_status", "live_connections",
                                      "dashboard_status", "list_users", "list_sessions", "xray_status",
                                      "bunny_status", "cloudfront_status", "config_view"}
            if independent:
                # Atomic credential files can be read without holding a writer
                # lock. A running Certbot/restart must not stall status queries.
                authorize_command(uid, command, params)
                result = HANDLERS[command](params)
            else:
                with OP_LOCK:
                    authorize_command(uid, command, params)
                    result = HANDLERS[command](params)
            response = {"ok": True, **result}
        except (ValidationError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            LOG.warning("Command failed: %s", exc)
            response = {"ok": False, "error": str(exc)}
        except Exception:
            LOG.exception("Unhandled panel daemon error")
            response = {"ok": False, "error": "Internal panel error; check journalctl -u abdulbasit-paneld"}
        conn.sendall(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")


def handle_connection_with_slot(conn: socket.socket) -> None:
    try:
        handle_connection(conn)
    finally:
        CONNECTION_SLOTS.release()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ensure_secure_permissions()
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    SOCKET_PATH.unlink(missing_ok=True)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCKET_PATH))
    try:
        gid = grp.getgrnam("abdulbasit").gr_gid
        os.chown(SOCKET_PATH, 0, gid)
    except KeyError:
        pass
    os.chmod(SOCKET_PATH, 0o660)
    server.listen(20)
    server.settimeout(1)
    LOG.info("Panel daemon listening on %s", SOCKET_PATH)

    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())

    while not stopping.is_set():
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        if not CONNECTION_SLOTS.acquire(blocking=False):
            try:
                conn.sendall(b'{"ok":false,"error":"Panel daemon is busy"}\n')
            except OSError:
                pass
            conn.close()
            continue
        threading.Thread(target=handle_connection_with_slot, args=(conn,), daemon=True).start()
    server.close()
    SOCKET_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
