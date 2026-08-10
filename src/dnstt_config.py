#!/usr/bin/env python3
"""DNSTT configuration validation and client profile generation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from common import ValidationError, validate_domain, validate_ip_address, validate_port


def host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def conflicting_udp53_lines(ss_output: str, listen_ip: str) -> list[str]:
    """Find non-DNSTT UDP/53 listeners that overlap the requested bind IP."""
    target = validate_ip_address(listen_ip)
    conflicts: list[str] = []
    for line in str(ss_output).splitlines():
        if "dnstt-server" in line:
            continue
        local = next(
            (
                token
                for token in line.split()
                if token.endswith(":53") or token.endswith("]:53")
            ),
            "",
        )
        if not local:
            continue
        host = local.rsplit(":", 1)[0].strip("[]")
        host = host.split("%", 1)[0]
        wildcard = host in {"*", "0.0.0.0", "::"}
        if wildcard or host == target:
            conflicts.append(line)
    return conflicts


def build_config(
    *,
    zone: str,
    nameserver: str,
    listen_ip: str,
    public_key: str,
    private_key_file: str,
    target_host: str = "127.0.0.1",
    target_port: int = 109,
) -> dict[str, Any]:
    zone = validate_domain(zone)
    nameserver = validate_domain(nameserver)
    listen_ip = validate_ip_address(listen_ip)
    target_port = validate_port(target_port)
    if nameserver == zone or nameserver.endswith("." + zone):
        raise ValidationError(
            "DNSTT nameserver hostname must not be inside the tunnel zone"
        )
    key = str(public_key).strip().lower()
    if len(key) != 64 or any(ch not in "0123456789abcdef" for ch in key):
        raise ValidationError("DNSTT public key must be 64 hexadecimal characters")
    if target_host != "127.0.0.1":
        raise ValidationError("DNSTT target is restricted to loopback")
    return {
        "zone": zone,
        "nameserver": nameserver,
        "listen_ip": listen_ip,
        "listen_port": 53,
        "target_host": target_host,
        "target_port": target_port,
        "private_key_file": private_key_file,
        "public_key": key,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def dns_records(config: dict[str, Any]) -> list[dict[str, str]]:
    address_type = "AAAA" if ":" in str(config["listen_ip"]) else "A"
    return [
        {
            "type": address_type,
            "name": str(config["nameserver"]),
            "value": str(config["listen_ip"]),
        },
        {"type": "NS", "name": str(config["zone"]), "value": str(config["nameserver"])},
    ]


def client_profile(config: dict[str, Any], username: str) -> dict[str, Any]:
    return {
        "format": "dnstt-ssh-open-profile-v1",
        "zone": config["zone"],
        "nameserver": config["nameserver"],
        "public_key": config["public_key"],
        "local_listen": "127.0.0.1:7000",
        "ssh": {"host": "127.0.0.1", "port": 7000, "username": username},
        "client_examples": {
            "udp": (
                f"dnstt-client -udp {config['nameserver']}:53 -pubkey {config['public_key']} "
                f"{config['zone']} 127.0.0.1:7000"
            ),
            "doh": (
                "dnstt-client -doh https://YOUR_AUTHORIZED_RESOLVER/dns-query "
                f"-pubkey {config['public_key']} {config['zone']} 127.0.0.1:7000"
            ),
        },
        "note": "Connect your SSH client to 127.0.0.1:7000 after starting dnstt-client.",
    }
