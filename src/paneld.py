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
    validate_quota,
    validate_service,
    validate_sessions,
    validate_telegram_id,
    validate_username,
)

LOG = logging.getLogger("abdulbasit-paneld")
OP_LOCK = threading.RLock()
CONNECTION_SLOTS = threading.BoundedSemaphore(20)
MAX_REQUEST = 16 * 1024
NGINX_CONFIG = Path("/etc/nginx/conf.d/abdulbasit-vpn.conf")
ACME_ROOT = Path("/var/www/letsencrypt")
SERVICE_MAP = {
    "nginx": "nginx",
    "dropbear": "dropbear",
    "abdulbasit-ws": "abdulbasit-ws",
    "abdulbasit-session-enforcer": "abdulbasit-session-enforcer",
    "abdulbasit-bot": "abdulbasit-bot",
    "abdulbasit-paneld": "abdulbasit-paneld",
}


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
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
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
    password = validate_password(str(params.get("password", "")))
    days = validate_days(params.get("days"))
    max_sessions = validate_sessions(params.get("max_sessions"))
    quota_gb = validate_quota(params.get("quota_gb", "Unlimited"))

    if user_file(username).exists():
        raise ValidationError("This managed username already exists")
    try:
        pwd.getpwnam(username)
        raise ValidationError("A system account with this username already exists")
    except KeyError:
        pass

    expiry = calculate_expiry(days)
    run([
        binary("useradd"), "--no-create-home", "--shell", "/bin/false",
        "--expiredate", expiry, "--user-group", username,
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
        "quota_gb": quota_gb,
        "quota_enforced": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_json(user_file(username), metadata, 0o600)
    return {"user": metadata, "warning": "GB quota is stored as metadata only; the old inaccurate /proc I/O quota enforcement was removed."}


def delete_user(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    managed_user(username)
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
    subprocess.run([binary("passwd"), "--unlock", username], capture_output=True, text=True, check=False)
    data["expiry"] = expiry
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    atomic_write_json(user_file(username), data, 0o600)
    return {"username": username, "expiry": expiry}


def set_sessions(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    limit = validate_sessions(params.get("max_sessions"))
    data = managed_user(username)
    data["max_sessions"] = limit
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    atomic_write_json(user_file(username), data, 0o600)
    return {"username": username, "max_sessions": limit}


def set_quota(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    quota = validate_quota(params.get("quota_gb", "Unlimited"))
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
        item.update({"exists": exists, "uid": uid, "shadow_expiry": get_shadow_expiry(username) if exists else None})
        users.append(item)
    return {"users": users}


def session_processes() -> dict[str, list[int]]:
    result = run([binary("ps"), "-eo", "pid=,euid=,comm="])
    by_uid: dict[int, list[int]] = {}
    for line in result.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        pid_text, uid_text, comm = parts
        if "dropbear" not in comm.lower():
            continue
        try:
            by_uid.setdefault(int(uid_text), []).append(int(pid_text))
        except ValueError:
            continue
    sessions: dict[str, list[int]] = {}
    for path in USERS_DIR.glob("*.json"):
        data = read_json(path, {})
        username = str(data.get("username", path.stem))
        try:
            uid = pwd.getpwnam(username).pw_uid
        except KeyError:
            continue
        sessions[username] = sorted(by_uid.get(uid, []))
    return sessions


def list_sessions(_: dict[str, Any]) -> dict[str, Any]:
    sessions = session_processes()
    return {"sessions": [{"username": name, "count": len(pids), "pids": pids} for name, pids in sorted(sessions.items()) if pids]}


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


def nginx_text(domain: str, tls: bool) -> str:
    v6_http = "    listen [::]:80;\n" if ipv6_enabled() else ""
    v6_tls = "    listen [::]:443 ssl;\n" if ipv6_enabled() else ""
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

    server_tokens off;
    client_header_timeout 10s;
    client_body_timeout 10s;
    client_max_body_size 1k;

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
"""
    return f"""# Managed by Abdul Basit VPS Panel. Manual edits may be overwritten.
map $http_upgrade $abdulbasit_connection_upgrade {{
    default upgrade;
    '' close;
}}

limit_conn_zone $binary_remote_addr zone=abdulbasit_per_ip:10m;
limit_req_zone $binary_remote_addr zone=abdulbasit_requests:10m rate=30r/m;

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


def install_nginx_config(domain: str) -> bool:
    cert_dir = Path("/etc/letsencrypt/live") / domain
    tls = (cert_dir / "fullchain.pem").is_file() and (cert_dir / "privkey.pem").is_file()
    NGINX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    old = NGINX_CONFIG.read_text(encoding="utf-8") if NGINX_CONFIG.exists() else None
    atomic_write(NGINX_CONFIG, nginx_text(domain, tls), 0o644)
    try:
        run([binary("nginx"), "-t"])
        run([binary("systemctl"), "reload-or-restart", "nginx"])
    except Exception:
        if old is None:
            NGINX_CONFIG.unlink(missing_ok=True)
        else:
            atomic_write(NGINX_CONFIG, old, 0o644)
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
    atomic_write(DOMAIN_FILE, domain + "\n", 0o640)
    set_group_readable(DOMAIN_FILE)
    tls = install_nginx_config(domain)
    return {"domain": domain, "tls": tls}


def issue_cert(params: dict[str, Any]) -> dict[str, Any]:
    domain = validate_domain(str(params.get("domain") or read_text(DOMAIN_FILE)))
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
    if service == "abdulbasit-paneld":
        raise ValidationError("The panel daemon cannot restart itself through the API")
    unit = SERVICE_MAP[service]
    run([binary("systemctl"), "restart", unit])
    return {"service": service}


def service_status(_: dict[str, Any]) -> dict[str, Any]:
    statuses: dict[str, str] = {}
    for label, unit in SERVICE_MAP.items():
        result = subprocess.run([binary("systemctl"), "is-active", unit], capture_output=True, text=True, check=False)
        statuses[label] = result.stdout.strip() or "unknown"
    return {"services": statuses, "domain": read_text(DOMAIN_FILE, "Not set")}


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


HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
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
}


def allowed_peer(uid: int) -> bool:
    if uid == 0:
        return True
    try:
        return uid == pwd.getpwnam("abdulbasit-bot").pw_uid
    except KeyError:
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
            if not isinstance(params, dict):
                raise ValidationError("Parameters must be an object")
            with OP_LOCK:
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
