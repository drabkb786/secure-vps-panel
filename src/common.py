#!/usr/bin/env python3
"""Shared validation and atomic-file helpers for Abdul Basit VPS Panel."""
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from decimal import Decimal, InvalidOperation
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

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$")
TELEGRAM_ID_RE = re.compile(r"^[1-9][0-9]{4,19}$")
BOT_TOKEN_RE = re.compile(r"^[0-9]{6,12}:[A-Za-z0-9_-]{30,80}$")

RESERVED_USERS = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
    "nobody", "systemd-network", "systemd-timesync", "messagebus", "syslog",
    "_apt", "tss", "uuidd", "tcpdump", "sshd", "landscape", "pollinate",
    "abdulbasit-bot",
    "abdulbasit-web", "abdulbasit-xray",
    "abdulbasit-dnstt",
}


class ValidationError(ValueError):
    """Raised when user-controlled input fails validation."""


def validate_username(value: str) -> str:
    value = value.strip().lower()
    if not USERNAME_RE.fullmatch(value):
        raise ValidationError("Username must be 1-31 chars: lowercase letters, digits, _ or -, and start with a letter/_")
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


def validate_ssh_password(value: str) -> str:
    if not isinstance(value, str) or not 3 <= len(value) <= 128:
        raise ValidationError("SSH password must contain 3-128 characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValidationError("Password contains an unsupported control character")
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
        quota = Decimal(text)
    except (TypeError, InvalidOperation) as exc:
        raise ValidationError("Quota must be a number in GB or Unlimited") from exc
    if not quota.is_finite() or not Decimal("0.1") <= quota <= Decimal("100000"):
        raise ValidationError("Quota must be between 0.1 and 100000 GB")
    if quota != quota.quantize(Decimal("0.001")):
        raise ValidationError("Quota supports at most three decimal places; no silent rounding")
    return float(quota)


def validate_max_ips(value: Any) -> int:
    if str(value).strip().lower() in {"", "none", "unlimited", "0"}:
        return 0
    return validate_sessions(value)


def quota_bytes(account: dict) -> int | None:
    """Legacy quotas retain their binary capacity; new profiles explicitly use GB."""
    quota = validate_quota(account.get("quota_gb"))
    if quota is None:
        return None
    unit = account.get("quota_unit", "GiB")
    if unit not in {"GB", "GiB"}:
        raise ValidationError("Quota unit must be GB or GiB")
    return int(Decimal(str(quota)) * (1000 ** 3 if unit == "GB" else 1024 ** 3))

def validate_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValidationError("Enter a valid hostname such as vpn.example.com")
    try:
        domain.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValidationError("Internationalized domains must be entered in ASCII/Punycode form") from exc
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


def validate_service(value: str) -> str:
    allowed = {"nginx", "haproxy", "dropbear", "abdulbasit-sshd", "abdulbasit-ws", "abdulbasit-session-enforcer", "abdulbasit-bot", "abdulbasit-paneld", "abdulbasit-web", "abdulbasit-xray", "abdulbasit-dnstt"}
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
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def atomic_write_json(path: Path, data: Any, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", mode)


def ensure_secure_permissions() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    USERS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(BASE_DIR, 0o750)
    os.chmod(USERS_DIR, 0o750)
    for path in (DOMAIN_FILE, BOT_TOKEN_FILE, SUPER_ADMIN_FILE, ADMIN_IDS_FILE, CERTBOT_EMAIL_FILE):
        if path.exists():
            os.chmod(path, 0o640)
    for path in USERS_DIR.glob("*.json"):
        os.chmod(path, 0o600)


def is_secure_regular_file(path: Path) -> bool:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode)
