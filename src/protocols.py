#!/usr/bin/env python3
"""Pure multi-protocol account and Xray configuration helpers."""

from __future__ import annotations

import copy
import secrets
import uuid
from datetime import date, datetime, timezone
from typing import Any, Iterable

from common import (
    ValidationError,
    validate_http_path,
    validate_protocols,
    validate_username,
)

XRAY_API = "127.0.0.1:21085"
XRAY_INBOUNDS = {
    "vmess": {"port": 21001, "tag": "vmess-in", "path": "/vmess"},
    "vless": {"port": 21002, "tag": "vless-in", "path": "/vless"},
    "trojan": {"port": 21003, "tag": "trojan-in", "path": "/trojan"},
}


def protocol_email(username: str) -> str:
    return f"{validate_username(username)}@users.abdulbasit.invalid"


def random_password() -> str:
    return secrets.token_urlsafe(24)


def normalize_protocol_settings(
    value: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    raw = value or {}
    settings: dict[str, dict[str, Any]] = {}
    for protocol, default in XRAY_INBOUNDS.items():
        item = raw.get(protocol, {}) if isinstance(raw, dict) else {}
        path = validate_http_path(str(item.get("path", default["path"])))
        settings[protocol] = {
            "port": int(default["port"]),
            "tag": str(default["tag"]),
            "path": path,
        }
    return settings


def enable_protocols(user: dict[str, Any], requested: Any) -> dict[str, Any]:
    """Return a copy with server-generated credentials for requested protocols."""
    result = copy.deepcopy(user)
    username = validate_username(str(result.get("username", "")))
    protocols = validate_protocols(requested)
    current = result.get("protocols")
    if not isinstance(current, dict):
        current = {}

    for protocol in protocols:
        item = current.get(protocol)
        if not isinstance(item, dict):
            item = {}
        item["enabled"] = True
        item.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        if protocol in {"vmess", "vless"}:
            item.setdefault("id", str(uuid.uuid4()))
            item["email"] = protocol_email(username)
        elif protocol == "trojan":
            item.setdefault("password", random_password())
            item["email"] = protocol_email(username)
        elif protocol == "ssh":
            item = {"enabled": True, "created_at": item["created_at"]}
        current[protocol] = item

    result["protocols"] = current
    result.setdefault("usage_bytes", 0)
    result["updated_at"] = datetime.now(timezone.utc).isoformat()
    return result


def disable_protocol(user: dict[str, Any], protocol: str) -> dict[str, Any]:
    protocol = validate_protocols([protocol])[0]
    result = copy.deepcopy(user)
    current = result.get("protocols", {})
    if not isinstance(current, dict) or protocol not in current:
        raise ValidationError(f"{protocol} is not configured for this user")
    current[protocol]["enabled"] = False
    current[protocol]["disabled_at"] = datetime.now(timezone.utc).isoformat()
    result["protocols"] = current
    result["updated_at"] = datetime.now(timezone.utc).isoformat()
    return result


def rotate_protocol(user: dict[str, Any], protocol: str) -> dict[str, Any]:
    protocol = validate_protocols([protocol])[0]
    if protocol == "ssh":
        raise ValidationError(
            "SSH password rotation uses the Linux account password workflow"
        )
    result = copy.deepcopy(user)
    current = result.get("protocols", {})
    item = current.get(protocol) if isinstance(current, dict) else None
    if not isinstance(item, dict) or not item.get("enabled"):
        raise ValidationError(f"{protocol} is not enabled for this user")
    if protocol in {"vmess", "vless"}:
        item["id"] = str(uuid.uuid4())
    else:
        item["password"] = random_password()
    item["rotated_at"] = datetime.now(timezone.utc).isoformat()
    result["updated_at"] = item["rotated_at"]
    return result


def quota_limit_bytes(user: dict[str, Any]) -> int | None:
    value = user.get("quota_gb")
    if value is None:
        return None
    try:
        return int(float(value) * 1_000_000_000)
    except (TypeError, ValueError):
        return None


def expired(user: dict[str, Any], today: date | None = None) -> bool:
    today = today or date.today()
    try:
        return date.fromisoformat(str(user.get("expiry", ""))) < today
    except ValueError:
        return False


def quota_exceeded(user: dict[str, Any]) -> bool:
    limit = quota_limit_bytes(user)
    if limit is None:
        return False
    try:
        return int(user.get("usage_bytes", 0)) >= limit
    except (TypeError, ValueError):
        return False


def active_for_xray(user: dict[str, Any]) -> bool:
    return not expired(user) and not quota_exceeded(user)


def _protocol_users(
    users: Iterable[dict[str, Any]], protocol: str
) -> list[dict[str, Any]]:
    """Return Xray inbound client objects for one protocol."""
    protocol_users: list[dict[str, Any]] = []
    for user in sorted(users, key=lambda item: str(item.get("username", ""))):
        if not active_for_xray(user):
            continue
        protocols = user.get("protocols", {})
        item = protocols.get(protocol) if isinstance(protocols, dict) else None
        if not isinstance(item, dict) or not item.get("enabled"):
            continue
        email = str(item.get("email") or protocol_email(str(user.get("username", ""))))
        if protocol in {"vmess", "vless"}:
            client = {"id": str(item["id"]), "email": email, "level": 0}
            if protocol == "vmess":
                client["alterId"] = 0
            protocol_users.append(client)
        else:
            protocol_users.append(
                {"password": str(item["password"]), "email": email, "level": 0}
            )
    return protocol_users


def render_xray_config(
    users: Iterable[dict[str, Any]],
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the complete deterministic server configuration."""
    users = list(users)
    inbound_settings = normalize_protocol_settings(settings)
    inbounds: list[dict[str, Any]] = []
    for protocol in ("vmess", "vless", "trojan"):
        spec = inbound_settings[protocol]
        protocol_users = _protocol_users(users, protocol)
        protocol_settings: dict[str, Any] = {"clients": protocol_users}
        if protocol == "vless":
            protocol_settings["decryption"] = "none"
        inbounds.append(
            {
                "listen": "127.0.0.1",
                "port": spec["port"],
                "protocol": protocol,
                "settings": protocol_settings,
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {"path": spec["path"]},
                },
                "tag": spec["tag"],
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": True,
                },
            }
        )

    return {
        "log": {"loglevel": "warning"},
        "api": {
            "tag": "api",
            "listen": XRAY_API,
            "services": ["HandlerService", "StatsService"],
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                    "handshake": 8,
                    "connIdle": 300,
                    "uplinkOnly": 2,
                    "downlinkOnly": 5,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
            },
        },
        "inbounds": inbounds,
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
            ],
        },
    }


def usage_summary(user: dict[str, Any]) -> dict[str, Any]:
    used = max(0, int(user.get("usage_bytes", 0) or 0))
    limit = quota_limit_bytes(user)
    return {
        "used_bytes": used,
        "limit_bytes": limit,
        "remaining_bytes": None if limit is None else max(0, limit - used),
        "quota_exceeded": limit is not None and used >= limit,
        "expired": expired(user),
    }
