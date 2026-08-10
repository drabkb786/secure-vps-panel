#!/usr/bin/env python3
"""Shared validation and atomic-file helpers for Abdul Basit VPS Panel."""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from datetime import date, timedelta
from pathlib import Path
from typing import Any

PROJECT_OWNER = "Abdul Basit"
PROJECT_GITHUB = "https://github.com/drabkb786/secure-vps-panel"
DEFAULT_SUPER_ADMIN_ID = "6408975845"

BASE_DIR = Path("/etc/abdulbasit")
USERS_DIR = BASE_DIR / "users"
DOMAIN_FILE = BASE_DIR / "domain.conf"
BOT_TOKEN_FILE = BASE_DIR / "bot_token.conf"
SUPER_ADMIN_FILE = BASE_DIR / "super_admin.conf"
ADMIN_IDS_FILE = BASE_DIR / "admin_ids.conf"
CERTBOT_EMAIL_FILE = BASE_DIR / "certbot_email.conf"
SOCKET_PATH = Path("/run/abdulbasit/paneld.sock")
STATE_LOCK_FILE = Path("/run/abdulbasit/state.lock")
XRAY_DIR = BASE_DIR / "xray"
XRAY_CONFIG_FILE = XRAY_DIR / "config.json"
XRAY_SYNC_PENDING_FILE = XRAY_DIR / "sync.pending"
XRAY_USAGE_PENDING_FILE = XRAY_DIR / "usage.pending.json"
CDN_FILE = BASE_DIR / "cdn.json"
DNSTT_FILE = BASE_DIR / "dnstt.json"
DNSTT_DIR = BASE_DIR / "dnstt"
DASHBOARD_AUTH_FILE = BASE_DIR / "dashboard_auth.json"
EXPORTS_DIR = BASE_DIR / "exports"

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$"
)
TELEGRAM_ID_RE = re.compile(r"^[1-9][0-9]{4,19}$")
BOT_TOKEN_RE = re.compile(r"^[0-9]{6,12}:[A-Za-z0-9_-]{30,80}$")
HTTP_PATH_RE = re.compile(r"^/[A-Za-z0-9._~%/@+-]{0,127}$")
ORIGIN_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{24,128}$")
PROTOCOLS = frozenset({"ssh", "vmess", "vless", "trojan"})
CDN_PROVIDERS = frozenset({"direct", "cloudflare", "cloudfront"})

RESERVED_USERS = {
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "nobody",
    "systemd-network",
    "systemd-timesync",
    "messagebus",
    "syslog",
    "_apt",
    "tss",
    "uuidd",
    "tcpdump",
    "sshd",
    "landscape",
    "pollinate",
    "abdulbasit-bot",
    "abdulbasit-dashboard",
    "abdulbasit-xray",
    "abdulbasit-dnstt",
}


class ValidationError(ValueError):
    """Raised when user-controlled input fails validation."""


def validate_username(value: str) -> str:
    value = value.strip().lower()
    if not USERNAME_RE.fullmatch(value):
        raise ValidationError(
            "Username must be 1-31 chars: lowercase letters, digits, _ or -, and start with a letter/_"
        )
    if value in RESERVED_USERS:
        raise ValidationError("This username is reserved")
    return value


def validate_password(value: str) -> str:
    if any(ch in value for ch in ("\x00", "\n", "\r")):
        raise ValidationError("Password contains an unsupported control character")
    if len(value) < 12:
        raise ValidationError("Password must contain at least 12 characters")
    if len(value) > 128:
        raise ValidationError("Password is too long (maximum 128 characters)")
    return value


def validate_days(value: Any, *, minimum: int = 1, maximum: int = 3650) -> int:
    try:
        days = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValidationError("Days must be a whole number") from exc
    if not minimum <= days <= maximum:
        raise ValidationError(f"Days must be between {minimum} and {maximum}")
    return days


def validate_sessions(value: Any) -> int:
    try:
        sessions = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValidationError("Session limit must be a whole number") from exc
    if not 1 <= sessions <= 20:
        raise ValidationError("Session limit must be between 1 and 20")
    return sessions


def validate_quota(value: Any) -> float | None:
    text = str(value).strip().lower()
    if text in {"", "unlimited", "none", "0"}:
        return None
    try:
        quota = float(text)
    except (TypeError, ValueError) as exc:
        raise ValidationError("Quota must be a number in GB or Unlimited") from exc
    if not 0.1 <= quota <= 100000:
        raise ValidationError("Quota must be between 0.1 and 100000 GB")
    return round(quota, 3)


def validate_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValidationError("Enter a valid hostname such as vpn.example.com")
    try:
        domain.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValidationError(
            "Internationalized domains must be entered in ASCII/Punycode form"
        ) from exc
    return domain


def validate_telegram_id(value: Any) -> str:
    telegram_id = str(value).strip()
    if not TELEGRAM_ID_RE.fullmatch(telegram_id):
        raise ValidationError("Telegram ID must be a numeric user ID")
    return telegram_id


def validate_bot_token(value: str) -> str:
    token = value.strip()
    if not BOT_TOKEN_RE.fullmatch(token):
        raise ValidationError("Telegram bot token format is invalid")
    return token


def validate_protocol(value: str) -> str:
    protocol = str(value).strip().lower()
    if protocol not in PROTOCOLS:
        raise ValidationError("Protocol must be one of: ssh, vmess, vless, trojan")
    return protocol


def validate_protocols(value: Any) -> list[str]:
    if isinstance(value, str):
        items = [item.strip() for item in value.split(",") if item.strip()]
    elif isinstance(value, (list, tuple, set)):
        items = [str(item).strip() for item in value if str(item).strip()]
    else:
        raise ValidationError("Protocols must be a comma-separated string or list")
    if not items:
        raise ValidationError("Select at least one protocol")
    return sorted(set(validate_protocol(item) for item in items))


def validate_cdn_provider(value: str) -> str:
    provider = str(value).strip().lower()
    if provider not in CDN_PROVIDERS:
        raise ValidationError("CDN provider must be direct, cloudflare, or cloudfront")
    return provider


def validate_http_path(value: str) -> str:
    path = str(value).strip()
    if (
        not HTTP_PATH_RE.fullmatch(path)
        or "//" in path
        or "/../" in path
        or path.endswith("/..")
    ):
        raise ValidationError(
            "Path must start with / and contain only URL path characters"
        )
    return path


def validate_origin_secret(value: str) -> str:
    secret = str(value).strip()
    if not ORIGIN_SECRET_RE.fullmatch(secret):
        raise ValidationError("Origin secret must be 24-128 URL-safe characters")
    return secret


def validate_ip_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValidationError("Enter a valid IPv4 or IPv6 address") from exc
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        raise ValidationError(
            "DNSTT must bind to a specific public or private interface address"
        )
    return str(address)


def validate_port(value: Any, *, minimum: int = 1, maximum: int = 65535) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValidationError("Port must be a whole number") from exc
    if not minimum <= port <= maximum:
        raise ValidationError(f"Port must be between {minimum} and {maximum}")
    return port


def validate_service(value: str) -> str:
    allowed = {
        "nginx",
        "dropbear",
        "abdulbasit-ws",
        "abdulbasit-session-enforcer",
        "abdulbasit-bot",
        "abdulbasit-paneld",
        "abdulbasit-xray",
        "abdulbasit-dashboard",
        "abdulbasit-usage",
        "abdulbasit-dnstt",
    }
    if value not in allowed:
        raise ValidationError("Service is not in the allowed service list")
    return value


def calculate_expiry(days: int, current: str | None = None) -> str:
    base = date.today()
    if current:
        try:
            existing = date.fromisoformat(current)
            if existing > base:
                base = existing
        except ValueError:
            pass
    return (base + timedelta(days=days)).isoformat()


def read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return default


def read_json(path: Path, default: Any = None) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent), text=True
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def atomic_write_json(path: Path, data: Any, mode: int = 0o600) -> None:
    atomic_write(
        path,
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        mode,
    )


@contextmanager
def state_lock() -> Any:
    """Serialize metadata/config mutations across panel services."""
    STATE_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_LOCK_FILE.open("a+", encoding="utf-8") as handle:
        os.chmod(STATE_LOCK_FILE, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def ensure_secure_permissions() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    USERS_DIR.mkdir(parents=True, exist_ok=True)
    XRAY_DIR.mkdir(parents=True, exist_ok=True)
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    DNSTT_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(BASE_DIR, 0o750)
    os.chmod(USERS_DIR, 0o750)
    os.chmod(XRAY_DIR, 0o750)
    os.chmod(EXPORTS_DIR, 0o750)
    os.chmod(DNSTT_DIR, 0o750)
    for path in (
        DOMAIN_FILE,
        BOT_TOKEN_FILE,
        SUPER_ADMIN_FILE,
        ADMIN_IDS_FILE,
        CERTBOT_EMAIL_FILE,
        DNSTT_FILE,
        DASHBOARD_AUTH_FILE,
        XRAY_CONFIG_FILE,
    ):
        if path.exists():
            os.chmod(path, 0o640)
    if CDN_FILE.exists():
        os.chmod(CDN_FILE, 0o600)
    if XRAY_USAGE_PENDING_FILE.exists():
        os.chmod(XRAY_USAGE_PENDING_FILE, 0o600)
    for path in USERS_DIR.glob("*.json"):
        os.chmod(path, 0o600)


def is_secure_regular_file(path: Path) -> bool:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode)
