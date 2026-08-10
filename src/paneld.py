#!/usr/bin/env python3
"""Privileged, narrow command daemon for Abdul Basit VPS Panel.

The Telegram bot never runs as root. It can only request allow-listed operations
through this UNIX socket. Every parameter is validated again in this daemon.
"""

from __future__ import annotations

import base64
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cdn_manager import (
    configure_profile,
    disable_profile,
    empty_cdn_config,
    public_config,
)
from common import (
    ADMIN_IDS_FILE,
    BOT_TOKEN_FILE,
    CDN_FILE,
    CERTBOT_EMAIL_FILE,
    DASHBOARD_AUTH_FILE,
    DNSTT_DIR,
    DNSTT_FILE,
    DOMAIN_FILE,
    EXPORTS_DIR,
    SOCKET_PATH,
    SUPER_ADMIN_FILE,
    USERS_DIR,
    XRAY_USAGE_PENDING_FILE,
    ValidationError,
    atomic_write,
    atomic_write_json,
    calculate_expiry,
    ensure_secure_permissions,
    is_secure_regular_file,
    read_json,
    read_text,
    state_lock,
    validate_bot_token,
    validate_cdn_provider,
    validate_days,
    validate_domain,
    validate_password,
    validate_protocol,
    validate_protocols,
    validate_quota,
    validate_service,
    validate_sessions,
    validate_telegram_id,
    validate_username,
)
from dashboard_auth import create_auth_config
from dnstt_config import (
    build_config as build_dnstt_config,
)
from dnstt_config import (
    client_profile as dnstt_client_profile,
)
from dnstt_config import (
    conflicting_udp53_lines,
    dns_records,
)
from exporter import export_bundle
from nginx_config import render_nginx_config
from protocols import (
    disable_protocol as disable_user_protocol,
)
from protocols import (
    enable_protocols,
    protocol_email,
    usage_summary,
)
from protocols import (
    rotate_protocol as rotate_user_protocol,
)
from xray_runtime import deploy_config, load_users

LOG = logging.getLogger("abdulbasit-paneld")
OP_LOCK = threading.RLock()
CONNECTION_SLOTS = threading.BoundedSemaphore(20)
MAX_REQUEST = 16 * 1024
NGINX_CONFIG = Path("/etc/nginx/conf.d/abdulbasit-vpn.conf")
ACME_ROOT = Path("/var/www/letsencrypt")
LETSENCRYPT_LIVE = Path("/etc/letsencrypt/live")
SERVICE_MAP = {
    "nginx": "nginx",
    "dropbear": "dropbear",
    "abdulbasit-ws": "abdulbasit-ws",
    "abdulbasit-session-enforcer": "abdulbasit-session-enforcer",
    "abdulbasit-bot": "abdulbasit-bot",
    "abdulbasit-paneld": "abdulbasit-paneld",
    "abdulbasit-xray": "abdulbasit-xray",
    "abdulbasit-dashboard": "abdulbasit-dashboard",
    "abdulbasit-usage": "abdulbasit-usage.timer",
    "abdulbasit-dnstt": "abdulbasit-dnstt",
}


def binary(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"Required command not found: {name}")
    return path


def run(
    args: list[str], *, input_text: str | None = None, timeout: int = 60
) -> subprocess.CompletedProcess[str]:
    LOG.info("Executing allow-listed command: %s", " ".join(args[:2]))
    completed = subprocess.run(
        args,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    )
    if completed.returncode != 0:
        detail_lines = (completed.stderr or completed.stdout or "").strip().splitlines()
        detail = (
            detail_lines[-1][:500]
            if detail_lines
            else f"exit status {completed.returncode}"
        )
        raise RuntimeError(f"{Path(args[0]).name} failed: {detail}")
    return completed


def set_group_readable(path: Path) -> None:
    try:
        gid = grp.getgrnam("abdulbasit").gr_gid
        os.chown(path, 0, gid)
        os.chmod(path, 0o640)
    except (KeyError, FileNotFoundError):
        pass


def set_dashboard_readable(path: Path) -> None:
    try:
        gid = grp.getgrnam("abdulbasit-dashboard").gr_gid
        os.chown(path, 0, gid)
        os.chmod(path, 0o640)
    except (KeyError, FileNotFoundError):
        pass


def set_dnstt_readable(path: Path) -> None:
    try:
        gid = grp.getgrnam("abdulbasit-dnstt").gr_gid
        os.chown(path, 0, gid)
        os.chmod(path, 0o640)
    except (KeyError, FileNotFoundError):
        pass


def set_dnstt_key_permissions(path: Path, mode: int = 0o640) -> None:
    try:
        os.chown(path, 0, grp.getgrnam("abdulbasit-dnstt").gr_gid)
    except (KeyError, FileNotFoundError):
        pass
    os.chmod(path, mode)


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


def user_has_xray(data: dict[str, Any]) -> bool:
    protocols = data.get("protocols", {})
    return isinstance(protocols, dict) and any(
        isinstance(protocols.get(name), dict) and protocols[name].get("enabled")
        for name in ("vmess", "vless", "trojan")
    )


def user_has_ssh(data: dict[str, Any]) -> bool:
    protocols = data.get("protocols", {})
    ssh = protocols.get("ssh") if isinstance(protocols, dict) else None
    return isinstance(ssh, dict) and bool(ssh.get("enabled"))


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
    protocols = validate_protocols(params.get("protocols", ["ssh"]))

    if user_file(username).exists():
        raise ValidationError("This managed username already exists")
    try:
        pwd.getpwnam(username)
        raise ValidationError("A system account with this username already exists")
    except KeyError:
        pass

    expiry = calculate_expiry(days)
    run(
        [
            binary("useradd"),
            "--no-create-home",
            "--shell",
            "/bin/false",
            "--expiredate",
            expiry,
            "--user-group",
            username,
        ]
    )
    try:
        run([binary("chpasswd")], input_text=f"{username}:{password}\n")
    except Exception:
        subprocess.run(
            [binary("userdel"), "--force", username],
            capture_output=True,
            text=True,
            check=False,
        )
        raise

    metadata = enable_protocols(
        {
            "username": username,
            "expiry": expiry,
            "max_sessions": max_sessions,
            "quota_gb": quota_gb,
            "quota_enforced": any(
                item in {"vmess", "vless", "trojan"} for item in protocols
            ),
            "quota_scope": "xray-only",
            "usage_bytes": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
        protocols,
    )
    try:
        with state_lock():
            atomic_write_json(user_file(username), metadata, 0o600)
            if any(item in {"vmess", "vless", "trojan"} for item in protocols):
                deploy_config()
    except Exception:
        user_file(username).unlink(missing_ok=True)
        subprocess.run(
            [binary("userdel"), "--force", username],
            capture_output=True,
            text=True,
            check=False,
        )
        raise
    return {
        "user": metadata,
        "warning": "Data quota is enforced for Xray protocols; SSH/DNSTT bytes are not counted in this quota.",
    }


def delete_user(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    data = managed_user(username)
    with state_lock():
        remaining = [
            item for item in load_users() if str(item.get("username")) != username
        ]
        has_xray = user_has_xray(data)
        if has_xray:
            deploy_config(remaining)
        subprocess.run(
            [binary("pkill"), "-TERM", "-u", username],
            capture_output=True,
            text=True,
            check=False,
        )
        result = subprocess.run(
            [binary("userdel"), "--force", username],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode not in (0, 6):
            if has_xray:
                deploy_config()
            raise RuntimeError(result.stderr.strip() or "Failed to delete user")
        user_file(username).unlink(missing_ok=True)
        export_dir = EXPORTS_DIR / username
        if export_dir.is_dir():
            for path in export_dir.iterdir():
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            export_dir.rmdir()
    return {"username": username}


def renew_user(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    days = validate_days(params.get("days"))
    with state_lock():
        data = managed_user(username)
        old_expiry = str(data.get("expiry") or "")
        expiry = calculate_expiry(days, old_expiry)
        run([binary("usermod"), "--expiredate", expiry, username])
        data["expiry"] = expiry
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        old = user_file(username).read_text(encoding="utf-8")
        try:
            atomic_write_json(user_file(username), data, 0o600)
            if user_has_xray(data):
                deploy_config()
        except Exception:
            atomic_write(user_file(username), old, 0o600)
            if old_expiry:
                try:
                    run([binary("usermod"), "--expiredate", old_expiry, username])
                except Exception:
                    LOG.exception("Failed to roll back Linux expiry for %s", username)
            raise
    return {"username": username, "expiry": expiry}


def set_sessions(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    limit = validate_sessions(params.get("max_sessions"))
    with state_lock():
        data = managed_user(username)
        data["max_sessions"] = limit
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        atomic_write_json(user_file(username), data, 0o600)
    return {"username": username, "max_sessions": limit}


def set_quota(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    quota = validate_quota(params.get("quota_gb", "Unlimited"))
    with state_lock():
        data = managed_user(username)
        data["quota_gb"] = quota
        data["quota_enforced"] = user_has_xray(data)
        data["quota_scope"] = "xray-only"
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        old = user_file(username).read_text(encoding="utf-8")
        atomic_write_json(user_file(username), data, 0o600)
        try:
            if user_has_xray(data):
                deploy_config()
        except Exception:
            atomic_write(user_file(username), old, 0o600)
            raise
    return {
        "username": username,
        "quota_gb": quota,
        "quota_enforced": user_has_xray(data),
        "quota_scope": "xray-only",
    }


def store_user_update_locked(
    username: str, data: dict[str, Any], *, sync_xray: bool
) -> None:
    path = user_file(username)
    old = path.read_text(encoding="utf-8")
    atomic_write_json(path, data, 0o600)
    try:
        if sync_xray:
            deploy_config()
    except Exception:
        atomic_write(path, old, 0o600)
        raise


def discard_pending_usage_locked(username: str) -> None:
    if not XRAY_USAGE_PENDING_FILE.exists():
        return
    pending = read_json(XRAY_USAGE_PENDING_FILE)
    if not isinstance(pending, dict) or not isinstance(pending.get("totals"), dict):
        raise RuntimeError(
            "Xray usage pending journal is invalid; inspect it before resetting usage"
        )
    totals = pending["totals"]
    totals.pop(protocol_email(username), None)
    if totals:
        atomic_write_json(XRAY_USAGE_PENDING_FILE, pending, 0o600)
    else:
        XRAY_USAGE_PENDING_FILE.unlink()


def enable_protocol(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    protocols = validate_protocols(params.get("protocols", []))
    with state_lock():
        old = managed_user(username)
        data = enable_protocols(old, protocols)
        if any(item in {"vmess", "vless", "trojan"} for item in protocols):
            data["quota_enforced"] = True
            data["quota_scope"] = "xray-only"
        unlock_ssh = "ssh" in protocols and not user_has_ssh(old)
        if unlock_ssh:
            run([binary("passwd"), "--unlock", username])
        try:
            store_user_update_locked(
                username, data, sync_xray=any(item != "ssh" for item in protocols)
            )
        except Exception:
            if unlock_ssh:
                subprocess.run(
                    [binary("passwd"), "--lock", username],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            raise
    return {"username": username, "protocols": protocols}


def disable_protocol(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    protocol = validate_protocol(str(params.get("protocol", "")))
    with state_lock():
        old = managed_user(username)
        data = disable_user_protocol(old, protocol)
        if protocol != "ssh" and not user_has_xray(data):
            data["quota_enforced"] = False
        if protocol == "ssh":
            run([binary("passwd"), "--lock", username])
        try:
            store_user_update_locked(username, data, sync_xray=protocol != "ssh")
        except Exception:
            if protocol == "ssh":
                subprocess.run(
                    [binary("passwd"), "--unlock", username],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            raise
        if protocol == "ssh":
            subprocess.run(
                [binary("pkill"), "-TERM", "-u", username],
                capture_output=True,
                text=True,
                check=False,
            )
    return {"username": username, "protocol": protocol, "enabled": False}


def rotate_protocol(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    protocol = validate_protocol(str(params.get("protocol", "")))
    with state_lock():
        data = rotate_user_protocol(managed_user(username), protocol)
        store_user_update_locked(username, data, sync_xray=True)
    return {"username": username, "protocol": protocol, "rotated": True}


def reset_usage(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    with state_lock():
        data = managed_user(username)
        pending_old = (
            XRAY_USAGE_PENDING_FILE.read_text(encoding="utf-8")
            if XRAY_USAGE_PENDING_FILE.exists()
            else None
        )
        data["usage_bytes"] = 0
        data["usage_reset_at"] = datetime.now(timezone.utc).isoformat()
        data.pop("usage_last_transaction", None)
        data.pop("quota_exceeded_at", None)
        data.pop("access_blocked", None)
        data.pop("access_blocked_reason", None)
        data.pop("access_blocked_at", None)
        try:
            discard_pending_usage_locked(username)
            store_user_update_locked(username, data, sync_xray=user_has_xray(data))
        except Exception:
            if pending_old is None:
                XRAY_USAGE_PENDING_FILE.unlink(missing_ok=True)
            else:
                atomic_write(XRAY_USAGE_PENDING_FILE, pending_old, 0o600)
            raise
    return {"username": username, "usage_bytes": 0}


def configure_cdn(params: dict[str, Any]) -> dict[str, Any]:
    provider = validate_cdn_provider(str(params.get("provider", "")))
    domain = read_text(DOMAIN_FILE)
    if not domain:
        raise ValidationError(
            "Configure the panel domain and TLS certificate before configuring a CDN"
        )
    origin = validate_domain(str(params.get("origin") or domain))
    if origin != validate_domain(domain):
        raise ValidationError(
            "CDN origin must match the panel TLS domain; configure that hostname with set-domain first"
        )
    cert_dir = LETSENCRYPT_LIVE / domain
    if (
        not (cert_dir / "fullchain.pem").is_file()
        or not (cert_dir / "privkey.pem").is_file()
    ):
        raise ValidationError(
            "Issue a valid TLS certificate for the panel domain before configuring a CDN"
        )
    old_data = read_json(CDN_FILE, empty_cdn_config())
    data = configure_profile(
        old_data,
        provider=provider,
        endpoint=str(params.get("endpoint", "")),
        origin=origin,
        enabled=True,
        origin_secret=str(params.get("origin_secret", "")),
    )
    old_text = CDN_FILE.read_text(encoding="utf-8") if CDN_FILE.exists() else None
    with state_lock():
        atomic_write_json(CDN_FILE, data, 0o600)
        try:
            if domain:
                install_nginx_config(domain)
        except Exception:
            if old_text is None:
                CDN_FILE.unlink(missing_ok=True)
            else:
                atomic_write(CDN_FILE, old_text, 0o600)
            raise
    configured = data["profiles"][provider]
    return {
        "profile": configured,
        "cloudformation": "infra/cloudfront-websocket.yml"
        if provider == "cloudfront"
        else None,
    }


def remove_cdn(params: dict[str, Any]) -> dict[str, Any]:
    provider = validate_cdn_provider(str(params.get("provider", "")))
    old_text = CDN_FILE.read_text(encoding="utf-8") if CDN_FILE.exists() else None
    data = disable_profile(read_json(CDN_FILE, empty_cdn_config()), provider)
    with state_lock():
        atomic_write_json(CDN_FILE, data, 0o600)
        try:
            domain = read_text(DOMAIN_FILE)
            if domain:
                install_nginx_config(domain)
        except Exception:
            if old_text is None:
                CDN_FILE.unlink(missing_ok=True)
            else:
                atomic_write(CDN_FILE, old_text, 0o600)
            raise
    return {"cdn": public_config(data)}


def list_cdn(_: dict[str, Any]) -> dict[str, Any]:
    return {"cdn": public_config(read_json(CDN_FILE, empty_cdn_config()))}


def export_dir(username: str) -> Path:
    return EXPORTS_DIR / validate_username(username)


def generate_exports(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    protocol = validate_protocol(str(params.get("protocol", "")))
    provider = validate_cdn_provider(str(params.get("provider", "direct")))
    if protocol == "ssh":
        raise ValidationError(
            "SSH/DNSTT exports use the dedicated DNSTT export command"
        )
    domain = read_text(DOMAIN_FILE)
    if not domain:
        raise ValidationError("Configure the panel domain before generating files")
    files = export_bundle(
        managed_user(username),
        protocol,
        domain=domain,
        provider=provider,
        cdn_config=read_json(CDN_FILE, empty_cdn_config()),
    )
    target_dir = export_dir(username)
    target_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(target_dir, 0o700)
    with state_lock():
        for name, content in files.items():
            atomic_write(target_dir / name, content, 0o600)
    return {
        "username": username,
        "protocol": protocol,
        "provider": provider,
        "files": sorted(files),
    }


def list_exports(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    target_dir = export_dir(username)
    files = []
    if target_dir.is_dir() and not target_dir.is_symlink():
        files = sorted(
            path.name
            for path in target_dir.iterdir()
            if path.is_file() and not path.is_symlink()
        )
    return {"username": username, "files": files}


def safe_export_path(username: str, filename: str) -> Path:
    if not re.fullmatch(r"[a-z0-9][A-Za-z0-9_.-]{0,199}", filename):
        raise ValidationError("Invalid export filename")
    path = export_dir(username) / filename
    if not is_secure_regular_file(path):
        raise ValidationError("Export file does not exist or is unsafe")
    return path


def get_export(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    filename = str(params.get("filename", ""))
    path = safe_export_path(username, filename)
    data = path.read_bytes()
    if len(data) > 256 * 1024:
        raise ValidationError("Export file is too large")
    return {
        "username": username,
        "filename": filename,
        "content_base64": base64.b64encode(data).decode("ascii"),
    }


def delete_export(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    filename = str(params.get("filename", ""))
    path = safe_export_path(username, filename)
    path.unlink()
    return {"username": username, "filename": filename, "deleted": True}


def configure_dnstt(params: dict[str, Any]) -> dict[str, Any]:
    dnstt = binary("dnstt-server")
    DNSTT_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DNSTT_DIR, 0o750)
    private_key = DNSTT_DIR / "server.key"
    public_key = DNSTT_DIR / "server.pub"
    rotate = bool(params.get("rotate_keys"))

    # Validate every non-key field before generating or replacing key material.
    provisional = build_dnstt_config(
        zone=str(params.get("zone", "")),
        nameserver=str(params.get("nameserver", "")),
        listen_ip=str(params.get("listen_ip", "")),
        public_key="0" * 64,
        private_key_file=str(private_key),
        target_port=params.get("target_port", 109),
    )

    listeners = subprocess.run(
        [binary("ss"), "-lunp", "sport = :53"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    conflicts = conflicting_udp53_lines(listeners, str(provisional["listen_ip"]))
    if conflicts:
        raise ValidationError(
            "UDP port 53 is occupied; configure DNSTT on a dedicated public IP or stop the conflicting DNS service"
        )

    for path in (private_key, public_key):
        if path.exists() and not is_secure_regular_file(path):
            raise ValidationError(f"Unsafe DNSTT key path: {path.name}")

    replace_keys = rotate or not private_key.is_file() or not public_key.is_file()
    generated_private: Path | None = None
    generated_public: Path | None = None
    temporary_keys: tempfile.TemporaryDirectory[str] | None = None
    if replace_keys:
        temporary_keys = tempfile.TemporaryDirectory(
            prefix=".keys.", dir=str(DNSTT_DIR)
        )
        temporary_dir = Path(temporary_keys.name)
        generated_private = temporary_dir / "server.key"
        generated_public = temporary_dir / "server.pub"
        run(
            [
                dnstt,
                "-gen-key",
                "-privkey-file",
                str(generated_private),
                "-pubkey-file",
                str(generated_public),
            ]
        )
        if not is_secure_regular_file(generated_private) or not is_secure_regular_file(
            generated_public
        ):
            temporary_keys.cleanup()
            raise RuntimeError("DNSTT key generator did not create safe key files")
        key_text = generated_public.read_text(encoding="ascii").strip()
    else:
        key_text = public_key.read_text(encoding="ascii").strip()

    config = build_dnstt_config(
        zone=str(provisional["zone"]),
        nameserver=str(provisional["nameserver"]),
        listen_ip=str(provisional["listen_ip"]),
        public_key=key_text,
        private_key_file=str(private_key),
        target_port=provisional["target_port"],
    )
    config["enabled"] = True

    old_text = DNSTT_FILE.read_text(encoding="utf-8") if DNSTT_FILE.exists() else None
    old_private = (
        private_key.read_text(encoding="ascii") if private_key.is_file() else None
    )
    old_public = (
        public_key.read_text(encoding="ascii") if public_key.is_file() else None
    )
    keys_installed = False
    try:
        if (
            replace_keys
            and generated_private is not None
            and generated_public is not None
        ):
            set_dnstt_key_permissions(generated_private)
            set_dnstt_key_permissions(generated_public)
            keys_installed = True
            os.replace(generated_private, private_key)
            os.replace(generated_public, public_key)
        set_dnstt_key_permissions(private_key)
        set_dnstt_key_permissions(public_key)
        atomic_write_json(DNSTT_FILE, config, 0o640)
        set_dnstt_readable(DNSTT_FILE)
        run([binary("systemctl"), "restart", "abdulbasit-dnstt"])
    except Exception:
        if old_text is None:
            DNSTT_FILE.unlink(missing_ok=True)
        else:
            atomic_write(DNSTT_FILE, old_text, 0o640)
            set_dnstt_readable(DNSTT_FILE)
        if keys_installed:
            if old_private is None:
                private_key.unlink(missing_ok=True)
            else:
                atomic_write(private_key, old_private, 0o640)
                set_dnstt_key_permissions(private_key)
            if old_public is None:
                public_key.unlink(missing_ok=True)
            else:
                atomic_write(public_key, old_public, 0o640)
                set_dnstt_key_permissions(public_key)
        subprocess.run(
            [binary("systemctl"), "restart", "abdulbasit-dnstt"],
            capture_output=True,
            text=True,
            check=False,
        )
        raise
    finally:
        if temporary_keys is not None:
            temporary_keys.cleanup()
    public = {key: value for key, value in config.items() if key != "private_key_file"}
    return {"dnstt": public, "dns_records": dns_records(config)}


def list_dnstt(_: dict[str, Any]) -> dict[str, Any]:
    config = read_json(DNSTT_FILE, {})
    if not isinstance(config, dict):
        config = {}
    public = {key: value for key, value in config.items() if key != "private_key_file"}
    return {"dnstt": public, "dns_records": dns_records(config) if config else []}


def export_dnstt(params: dict[str, Any]) -> dict[str, Any]:
    username = validate_username(str(params.get("username", "")))
    managed_user(username)
    config = read_json(DNSTT_FILE)
    if not isinstance(config, dict) or not config.get("enabled"):
        raise ValidationError("DNSTT is not configured and enabled")
    profile = dnstt_client_profile(config, username)
    target_dir = export_dir(username)
    target_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(target_dir, 0o700)
    filename = f"{username}-dnstt-ssh.json"
    atomic_write_json(target_dir / filename, profile, 0o600)
    return {
        "username": username,
        "files": [filename],
        "dns_records": dns_records(config),
    }


def disable_dnstt(_: dict[str, Any]) -> dict[str, Any]:
    run([binary("systemctl"), "stop", "abdulbasit-dnstt"])
    config = read_json(DNSTT_FILE, {})
    if isinstance(config, dict):
        config["enabled"] = False
        config["updated_at"] = datetime.now(timezone.utc).isoformat()
        atomic_write_json(DNSTT_FILE, config, 0o640)
        set_dnstt_readable(DNSTT_FILE)
    return {"enabled": False}


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
        raw_protocols = item.get("protocols", {})
        item["protocols"] = (
            {
                name: {"enabled": bool(value.get("enabled"))}
                for name, value in raw_protocols.items()
                if isinstance(value, dict)
            }
            if isinstance(raw_protocols, dict)
            else {}
        )
        item["usage"] = usage_summary(data)
        item.update(
            {
                "exists": exists,
                "uid": uid,
                "shadow_expiry": get_shadow_expiry(username) if exists else None,
            }
        )
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
    return {
        "sessions": [
            {"username": name, "count": len(pids), "pids": pids}
            for name, pids in sorted(sessions.items())
            if pids
        ]
    }


def ipv6_enabled() -> bool:
    try:
        return (
            socket.has_ipv6
            and Path("/proc/net/if_inet6").read_text(encoding="ascii").strip() != ""
        )
    except OSError:
        return False


def domain_conflicts(domain: str) -> list[str]:
    conflicts: list[str] = []
    roots = [Path("/etc/nginx/conf.d"), Path("/etc/nginx/sites-enabled")]
    pattern = re.compile(
        r"^\s*server_name\s+[^;]*\b" + re.escape(domain) + r"\b",
        re.IGNORECASE | re.MULTILINE,
    )
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
    return render_nginx_config(
        domain,
        tls=tls,
        ipv6=ipv6_enabled(),
        cdn_config=read_json(CDN_FILE, empty_cdn_config()),
        dashboard=True,
    )


def install_nginx_config(domain: str) -> bool:
    cert_dir = LETSENCRYPT_LIVE / domain
    tls = (cert_dir / "fullchain.pem").is_file() and (
        cert_dir / "privkey.pem"
    ).is_file()
    NGINX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    old = NGINX_CONFIG.read_text(encoding="utf-8") if NGINX_CONFIG.exists() else None
    # CloudFront origin verification may be embedded in this file.
    atomic_write(NGINX_CONFIG, nginx_text(domain, tls), 0o600)
    try:
        run([binary("nginx"), "-t"])
        run([binary("systemctl"), "reload-or-restart", "nginx"])
    except Exception:
        if old is None:
            NGINX_CONFIG.unlink(missing_ok=True)
        else:
            atomic_write(NGINX_CONFIG, old, 0o600)
        subprocess.run(
            [binary("nginx"), "-t"], capture_output=True, text=True, check=False
        )
        subprocess.run(
            [binary("systemctl"), "reload-or-restart", "nginx"],
            capture_output=True,
            text=True,
            check=False,
        )
        raise
    return tls


def set_domain(params: dict[str, Any]) -> dict[str, Any]:
    domain = validate_domain(str(params.get("domain", "")))
    current_domain = read_text(DOMAIN_FILE)
    if current_domain and current_domain != domain:
        cdn = read_json(CDN_FILE, empty_cdn_config())
        profiles = cdn.get("profiles", {}) if isinstance(cdn, dict) else {}
        enabled = sorted(
            name
            for name, profile in profiles.items()
            if isinstance(profile, dict) and profile.get("enabled")
        )
        if enabled:
            raise ValidationError(
                "Disable active CDN profiles before changing the panel domain: "
                + ", ".join(enabled)
            )
    conflicts = domain_conflicts(domain)
    if conflicts:
        raise ValidationError(
            "Domain already appears in another Nginx config: "
            + ", ".join(conflicts[:3])
        )
    ACME_ROOT.mkdir(parents=True, exist_ok=True)
    old = DOMAIN_FILE.read_text(encoding="utf-8") if DOMAIN_FILE.exists() else None
    atomic_write(DOMAIN_FILE, domain + "\n", 0o640)
    set_group_readable(DOMAIN_FILE)
    try:
        tls = install_nginx_config(domain)
    except Exception:
        if old is None:
            DOMAIN_FILE.unlink(missing_ok=True)
        else:
            atomic_write(DOMAIN_FILE, old, 0o640)
            set_group_readable(DOMAIN_FILE)
        raise
    return {"domain": domain, "tls": tls}


def issue_cert(params: dict[str, Any]) -> dict[str, Any]:
    configured_domain = read_text(DOMAIN_FILE)
    if not configured_domain:
        raise ValidationError("Configure the panel domain before issuing a certificate")
    configured_domain = validate_domain(configured_domain)
    domain = validate_domain(str(params.get("domain") or configured_domain))
    if domain != configured_domain:
        raise ValidationError(
            "Certificate hostname must match the configured panel domain; run set-domain first"
        )
    ACME_ROOT.mkdir(parents=True, exist_ok=True)
    install_nginx_config(domain)
    email = read_text(CERTBOT_EMAIL_FILE)
    args = [
        binary("certbot"),
        "certonly",
        "--webroot",
        "--webroot-path",
        str(ACME_ROOT),
        "--domain",
        domain,
        "--non-interactive",
        "--agree-tos",
        "--keep-until-expiring",
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
        result = subprocess.run(
            [binary("systemctl"), "is-active", unit],
            capture_output=True,
            text=True,
            check=False,
        )
        statuses[label] = result.stdout.strip() or "unknown"
    required = [
        "nginx",
        "dropbear",
        "abdulbasit-ws",
        "abdulbasit-session-enforcer",
        "abdulbasit-paneld",
        "abdulbasit-xray",
        "abdulbasit-usage",
    ]
    if DASHBOARD_AUTH_FILE.is_file():
        required.append("abdulbasit-dashboard")
    if BOT_TOKEN_FILE.is_file():
        required.append("abdulbasit-bot")
    dnstt = read_json(DNSTT_FILE, {})
    if isinstance(dnstt, dict) and dnstt.get("enabled"):
        required.append("abdulbasit-dnstt")
    return {
        "services": statuses,
        "required_services": required,
        "domain": read_text(DOMAIN_FILE, "Not set"),
        "cdn": public_config(read_json(CDN_FILE, empty_cdn_config())),
    }


def configure_bot(params: dict[str, Any]) -> dict[str, Any]:
    token = validate_bot_token(str(params.get("token", "")))
    super_admin = validate_telegram_id(params.get("super_admin"))
    paths = (BOT_TOKEN_FILE, SUPER_ADMIN_FILE, ADMIN_IDS_FILE)
    old = {
        path: path.read_text(encoding="utf-8") if path.exists() else None
        for path in paths
    }
    with state_lock():
        try:
            atomic_write(BOT_TOKEN_FILE, token + "\n", 0o640)
            atomic_write(SUPER_ADMIN_FILE, super_admin + "\n", 0o640)
            if not ADMIN_IDS_FILE.exists():
                atomic_write(ADMIN_IDS_FILE, "", 0o640)
            for path in paths:
                set_group_readable(path)
            run([binary("systemctl"), "restart", "abdulbasit-bot"])
        except Exception:
            for path, content in old.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, content, 0o640)
                    set_group_readable(path)
            subprocess.run(
                [
                    binary("systemctl"),
                    "restart" if old[BOT_TOKEN_FILE] is not None else "stop",
                    "abdulbasit-bot",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            raise
    return {"super_admin": super_admin}


def configure_dashboard(params: dict[str, Any]) -> dict[str, Any]:
    config = create_auth_config(
        str(params.get("username", "")), str(params.get("password", ""))
    )
    old = (
        DASHBOARD_AUTH_FILE.read_text(encoding="utf-8")
        if DASHBOARD_AUTH_FILE.exists()
        else None
    )
    with state_lock():
        try:
            atomic_write_json(DASHBOARD_AUTH_FILE, config, 0o640)
            set_dashboard_readable(DASHBOARD_AUTH_FILE)
            run([binary("systemctl"), "restart", "abdulbasit-dashboard"])
        except Exception:
            if old is None:
                DASHBOARD_AUTH_FILE.unlink(missing_ok=True)
            else:
                atomic_write(DASHBOARD_AUTH_FILE, old, 0o640)
                set_dashboard_readable(DASHBOARD_AUTH_FILE)
            subprocess.run(
                [
                    binary("systemctl"),
                    "restart" if old is not None else "stop",
                    "abdulbasit-dashboard",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            raise
    return {"username": config["username"], "path": "/panel/"}


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
    "enable_protocol": enable_protocol,
    "disable_protocol": disable_protocol,
    "rotate_protocol": rotate_protocol,
    "reset_usage": reset_usage,
    "list_users": list_users,
    "list_sessions": list_sessions,
    "set_domain": set_domain,
    "issue_cert": issue_cert,
    "configure_cdn": configure_cdn,
    "remove_cdn": remove_cdn,
    "list_cdn": list_cdn,
    "generate_exports": generate_exports,
    "list_exports": list_exports,
    "get_export": get_export,
    "delete_export": delete_export,
    "configure_dnstt": configure_dnstt,
    "list_dnstt": list_dnstt,
    "export_dnstt": export_dnstt,
    "disable_dnstt": disable_dnstt,
    "restart_service": restart_service,
    "service_status": service_status,
    "configure_bot": configure_bot,
    "configure_dashboard": configure_dashboard,
    "list_admins": list_admins,
    "add_admin": add_admin,
    "remove_admin": remove_admin,
}

DASHBOARD_COMMANDS = frozenset(
    {
        "create_user",
        "delete_user",
        "renew_user",
        "set_sessions",
        "set_quota",
        "enable_protocol",
        "disable_protocol",
        "rotate_protocol",
        "reset_usage",
        "list_users",
        "service_status",
        "configure_cdn",
        "remove_cdn",
        "list_cdn",
        "generate_exports",
        "list_exports",
        "get_export",
        "delete_export",
        "configure_dnstt",
        "list_dnstt",
        "export_dnstt",
        "disable_dnstt",
    }
)
BOT_COMMANDS = frozenset(
    {
        "create_user",
        "delete_user",
        "renew_user",
        "set_sessions",
        "set_quota",
        "enable_protocol",
        "disable_protocol",
        "rotate_protocol",
        "reset_usage",
        "list_users",
        "list_sessions",
        "service_status",
        "set_domain",
        "issue_cert",
        "list_cdn",
        "generate_exports",
        "list_exports",
        "get_export",
        "delete_export",
        "list_dnstt",
        "export_dnstt",
        "restart_service",
        "list_admins",
        "add_admin",
        "remove_admin",
    }
)


def peer_role(uid: int) -> str | None:
    if uid == 0:
        return "root"
    for username, role in (
        ("abdulbasit-bot", "bot"),
        ("abdulbasit-dashboard", "dashboard"),
    ):
        try:
            if uid == pwd.getpwnam(username).pw_uid:
                return role
        except KeyError:
            continue
    return None


def command_allowed(role: str, command: str) -> bool:
    if role == "root":
        return command in HANDLERS
    if role == "bot":
        return command in BOT_COMMANDS
    if role == "dashboard":
        return command in DASHBOARD_COMMANDS
    return False


def parameters_allowed(role: str, command: str, params: dict[str, Any]) -> bool:
    if role == "bot" and command == "restart_service":
        return str(params.get("service", "")) in {"nginx", "abdulbasit-ws"}
    if role == "bot" and command == "issue_cert":
        return not str(params.get("domain", "")).strip()
    return True


def allowed_peer(uid: int) -> bool:
    return peer_role(uid) is not None


def peer_uid(conn: socket.socket) -> int:
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def handle_connection(conn: socket.socket) -> None:
    with conn:
        conn.settimeout(10)
        uid = peer_uid(conn)
        role = peer_role(uid)
        if role is None:
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
            if not command_allowed(role, command):
                raise ValidationError("Command is not allowed for this panel client")
            if not isinstance(params, dict):
                raise ValidationError("Parameters must be an object")
            if not parameters_allowed(role, command, params):
                raise ValidationError(
                    "Command parameters are not allowed for this panel client"
                )
            with OP_LOCK:
                result = HANDLERS[command](params)
            response = {"ok": True, **result}
        except (
            ValidationError,
            RuntimeError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as exc:
            LOG.warning("Command failed: %s", exc)
            response = {"ok": False, "error": str(exc)}
        except Exception:
            LOG.exception("Unhandled panel daemon error")
            response = {
                "ok": False,
                "error": "Internal panel error; check journalctl -u abdulbasit-paneld",
            }
        conn.sendall(
            json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
            + b"\n"
        )


def handle_connection_with_slot(conn: socket.socket) -> None:
    try:
        handle_connection(conn)
    finally:
        CONNECTION_SLOTS.release()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    ensure_secure_permissions()
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    SOCKET_PATH.unlink(missing_ok=True)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCKET_PATH))
    try:
        gid = grp.getgrnam("abdulbasit-clients").gr_gid
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
        threading.Thread(
            target=handle_connection_with_slot, args=(conn,), daemon=True
        ).start()
    server.close()
    SOCKET_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
