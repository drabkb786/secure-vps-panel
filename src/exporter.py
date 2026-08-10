#!/usr/bin/env python3
"""Generate links and open client profiles without proprietary file locking."""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote, urlencode

from cdn_manager import target_for
from common import (
    ValidationError,
    validate_cdn_provider,
    validate_protocol,
    validate_username,
)


def _credential(user: dict[str, Any], protocol: str) -> dict[str, Any]:
    protocol = validate_protocol(protocol)
    if protocol == "ssh":
        raise ValidationError(
            "SSH credentials are not stored; use the username and administrator-supplied password"
        )
    protocols = user.get("protocols", {})
    item = protocols.get(protocol) if isinstance(protocols, dict) else None
    if not isinstance(item, dict) or not item.get("enabled"):
        raise ValidationError(f"{protocol} is not enabled for this user")
    return item


def connection_target(
    user: dict[str, Any],
    protocol: str,
    *,
    domain: str,
    provider: str,
    cdn_config: dict[str, Any] | None,
    protocol_settings: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = validate_protocol(protocol)
    if protocol == "ssh":
        raise ValidationError("Use the SSH export helper for SSH profiles")
    credential = _credential(user, protocol)
    target = target_for(
        domain=domain,
        protocol=protocol,
        provider=validate_cdn_provider(provider),
        cdn_config=cdn_config,
        protocol_settings=protocol_settings,
    )
    return credential, target


def share_link(
    user: dict[str, Any],
    protocol: str,
    *,
    domain: str,
    provider: str = "direct",
    cdn_config: dict[str, Any] | None = None,
    protocol_settings: dict[str, Any] | None = None,
) -> str:
    username = validate_username(str(user.get("username", "")))
    credential, target = connection_target(
        user,
        protocol,
        domain=domain,
        provider=provider,
        cdn_config=cdn_config,
        protocol_settings=protocol_settings,
    )
    label = quote(f"{username}-{protocol}-{provider}")
    query = urlencode(
        {
            "encryption": "none" if protocol == "vless" else "auto",
            "security": "tls",
            "sni": target["sni"],
            "type": "ws",
            "host": target["host"],
            "path": target["path"],
        }
    )

    if protocol == "vmess":
        vmess = {
            "v": "2",
            "ps": f"{username}-{provider}",
            "add": target["address"],
            "port": str(target["port"]),
            "id": str(credential["id"]),
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": target["host"],
            "path": target["path"],
            "tls": "tls",
            "sni": target["sni"],
            "alpn": "http/1.1",
        }
        raw = json.dumps(vmess, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        return "vmess://" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if protocol == "vless":
        return f"vless://{quote(str(credential['id']))}@{target['address']}:{target['port']}?{query}#{label}"
    query = urlencode(
        {
            key: value
            for key, value in {
                "security": "tls",
                "sni": target["sni"],
                "type": "ws",
                "host": target["host"],
                "path": target["path"],
            }.items()
        }
    )
    return f"trojan://{quote(str(credential['password']))}@{target['address']}:{target['port']}?{query}#{label}"


def client_json(
    user: dict[str, Any],
    protocol: str,
    *,
    domain: str,
    provider: str = "direct",
    cdn_config: dict[str, Any] | None = None,
    protocol_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    username = validate_username(str(user.get("username", "")))
    credential, target = connection_target(
        user,
        protocol,
        domain=domain,
        provider=provider,
        cdn_config=cdn_config,
        protocol_settings=protocol_settings,
    )
    outbound_settings: dict[str, Any]
    if protocol == "vmess":
        outbound_settings = {
            "vnext": [
                {
                    "address": target["address"],
                    "port": target["port"],
                    "users": [
                        {
                            "id": credential["id"],
                            "alterId": 0,
                            "security": "auto",
                            "level": 0,
                        }
                    ],
                }
            ]
        }
    elif protocol == "vless":
        outbound_settings = {
            "vnext": [
                {
                    "address": target["address"],
                    "port": target["port"],
                    "users": [
                        {
                            "id": credential["id"],
                            "encryption": "none",
                            "level": 0,
                        }
                    ],
                }
            ]
        }
    else:
        outbound_settings = {
            "servers": [
                {
                    "address": target["address"],
                    "port": target["port"],
                    "password": credential["password"],
                }
            ]
        }

    return {
        "remarks": f"{username}-{protocol}-{provider}",
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "tag": "local-socks",
            }
        ],
        "outbounds": [
            {
                "protocol": protocol,
                "settings": outbound_settings,
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {"serverName": target["sni"], "alpn": ["http/1.1"]},
                    "wsSettings": {"path": target["path"], "host": target["host"]},
                },
                "tag": "secure-proxy",
            },
            {"protocol": "freedom", "tag": "direct"},
        ],
    }


def websocket_payload(target: dict[str, Any]) -> str:
    """NetMod/DarkTunnel-style payload for the configured, authorized endpoint."""
    return (
        f"GET {target['path']} HTTP/1.1[crlf]"
        f"Host: {target['host']}[crlf]"
        "Upgrade: websocket[crlf]"
        "Connection: Upgrade[crlf][crlf]"
    )


def netmod_json(
    user: dict[str, Any],
    protocol: str,
    *,
    domain: str,
    provider: str,
    cdn_config: dict[str, Any] | None,
    protocol_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _, target = connection_target(
        user,
        protocol,
        domain=domain,
        provider=provider,
        cdn_config=cdn_config,
        protocol_settings=protocol_settings,
    )
    return {
        "format": "netmod-open-json-v1",
        "note": "Open JSON profile; no proprietary NetMod lock/encryption is applied.",
        "name": f"{validate_username(str(user.get('username', '')))}-{protocol}-{provider}",
        "protocol": protocol,
        "share_link": share_link(
            user,
            protocol,
            domain=domain,
            provider=provider,
            cdn_config=cdn_config,
            protocol_settings=protocol_settings,
        ),
        "server": target,
        "payload": websocket_payload(target),
        "xray": client_json(
            user,
            protocol,
            domain=domain,
            provider=provider,
            cdn_config=cdn_config,
            protocol_settings=protocol_settings,
        ),
    }


def dark_tunnel_json(
    user: dict[str, Any],
    protocol: str,
    *,
    domain: str,
    provider: str,
    cdn_config: dict[str, Any] | None,
    protocol_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile = netmod_json(
        user,
        protocol,
        domain=domain,
        provider=provider,
        cdn_config=cdn_config,
        protocol_settings=protocol_settings,
    )
    profile["format"] = "dark-tunnel-open-json-v1"
    profile["note"] = (
        "Import the included Xray JSON/link; proprietary .dark locking is intentionally not used."
    )
    return profile


def export_bundle(
    user: dict[str, Any],
    protocol: str,
    *,
    domain: str,
    provider: str,
    cdn_config: dict[str, Any] | None,
    protocol_settings: dict[str, Any] | None = None,
) -> dict[str, str]:
    username = validate_username(str(user.get("username", "")))
    stem = f"{username}-{protocol}-{provider}"
    _, target = connection_target(
        user,
        protocol,
        domain=domain,
        provider=provider,
        cdn_config=cdn_config,
        protocol_settings=protocol_settings,
    )
    return {
        f"{stem}.link.txt": share_link(
            user,
            protocol,
            domain=domain,
            provider=provider,
            cdn_config=cdn_config,
            protocol_settings=protocol_settings,
        )
        + "\n",
        f"{stem}.xray.json": json.dumps(
            client_json(
                user,
                protocol,
                domain=domain,
                provider=provider,
                cdn_config=cdn_config,
                protocol_settings=protocol_settings,
            ),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        f"{stem}.nm.json": json.dumps(
            netmod_json(
                user,
                protocol,
                domain=domain,
                provider=provider,
                cdn_config=cdn_config,
                protocol_settings=protocol_settings,
            ),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        f"{stem}.dark.json": json.dumps(
            dark_tunnel_json(
                user,
                protocol,
                domain=domain,
                provider=provider,
                cdn_config=cdn_config,
                protocol_settings=protocol_settings,
            ),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        f"{stem}.payload.txt": websocket_payload(target) + "\n",
    }
