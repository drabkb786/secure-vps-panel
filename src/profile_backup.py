"""Versioned Xray-profile backup validation. Never restores OS files or executables."""
from __future__ import annotations

import re
import uuid
from datetime import date, datetime, timezone

from common import ValidationError, validate_domain, validate_password, validate_username, validate_max_ips, quota_bytes
from account_policy import blocked_ips

SCHEMA = "noway-xray-backup-v1"
MAX_BYTES = 256 * 1024


def build(network: dict, rows: list[dict], domain: str) -> dict:
    transient = {"online_ips", "ip_blocked_until", "ip_monitoring_failed", "meter_unavailable"}
    rows = [{k: v for k, v in row.items() if k not in transient} for row in rows]
    return {"schema": SCHEMA, "created_at": datetime.now(timezone.utc).isoformat(),
            "domain": domain, "network": network, "accounts": rows,
            "scope": "Xray accounts, DNS and transport settings only; excludes SSH users/passwords, TLS keys, web login and Telegram token"}


def validate(data: dict, dns_validator) -> tuple[dict, list[dict]]:
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValidationError("Unsupported backup schema")
    if data.get("domain"):
        validate_domain(str(data["domain"]))
    config, rows = data.get("network"), data.get("accounts")
    if not isinstance(config, dict) or not isinstance(config.get("enabled"), bool):
        raise ValidationError("Backup network settings are invalid")
    if not isinstance(config.get("xhttp_enabled", False), bool):
        raise ValidationError("Backup XHTTP flag is invalid")
    if not isinstance(config.get("udp_enabled", True), bool):
        raise ValidationError("Backup UDP flag is invalid")
    if not isinstance(config.get("vless_non_tls_enabled", False), bool):
        raise ValidationError("Backup non-TLS flag is invalid")
    if config.get("vless_non_tls_enabled"):
        from reality_transport import vless_encryption
        vless_encryption.keys()  # Preserve local identity; never rotate on restore.
    network = {"enabled": config["enabled"], "vless_non_tls_enabled": config.get("vless_non_tls_enabled", False), "xhttp_enabled": config.get("xhttp_enabled", False), "udp_enabled": config.get("udp_enabled", True), "dns": dns_validator(config.get("dns", {}))}
    if not isinstance(config.get("reality_enabled", False), bool):
        raise ValidationError("Backup REALITY flag is invalid")
    if config.get("reality_enabled"):
        from reality_transport import keys, port
        keys()  # REALITY identity is local; never silently replace a server key.
        network.update(reality_enabled=True, reality_port=port(config.get("reality_port", 8443)))
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValidationError("A backup can contain at most 200 profiles")
    clean, names, identities, passwords, digests = [], set(), set(), set(), set()
    allowed = {"name", "uuid", "trojan_password", "protocols", "enabled", "expiry", "created_at", "subscription_hash", "subscription_issued_at", "quota_gb", "quota_unit", "max_ips", "used_bytes", "upload_bytes", "download_bytes", "trial", "expires_at", "blocked_ips"}
    for row in rows:
        if not isinstance(row, dict) or set(row) - allowed:
            raise ValidationError("Backup account has unsupported fields")
        name = validate_username(str(row.get("name", "")))
        if name != row.get("name") or name in names:
            raise ValidationError("Duplicate or noncanonical profile name in backup")
        try:
            identity = str(uuid.UUID(row["uuid"]))
            date.fromisoformat(row["expiry"])
            datetime.fromisoformat(row["created_at"])
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise ValidationError("Invalid UUID, expiry or creation date in backup") from exc
        password = validate_password(str(row.get("trojan_password", "")))
        protocols = row.get("protocols")
        if not isinstance(protocols, list) or not protocols or any(p not in ("vless", "vmess", "trojan") for p in protocols):
            raise ValidationError("Backup contains an unsupported protocol")
        if not isinstance(row.get("enabled"), bool) or identity in identities or password in passwords:
            raise ValidationError("Duplicate credentials or invalid enabled flag in backup")
        names.add(name); identities.add(identity); passwords.add(password)
        item = {"name": name, "uuid": identity, "trojan_password": password, "protocols": sorted(set(protocols)),
                "enabled": row["enabled"], "expiry": row["expiry"], "created_at": row["created_at"]}
        from common import validate_quota
        item["quota_gb"] = validate_quota(row.get("quota_gb", "Unlimited"))
        item["quota_unit"] = row.get("quota_unit", "GiB")
        if item["quota_unit"] not in {"GB", "GiB"}:
            raise ValidationError("Invalid quota unit")
        quota_bytes(item)
        item["max_ips"] = validate_max_ips(row.get("max_ips", 0))
        if "blocked_ips" in row:
            item["blocked_ips"] = blocked_ips(row)
        for field in ("used_bytes", "upload_bytes", "download_bytes"):
            value = row.get(field, 0)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 2 ** 63 - 1:
                raise ValidationError("Invalid traffic counter")
            item[field] = value
        if item["used_bytes"] != item["upload_bytes"] + item["download_bytes"]:
            raise ValidationError("Traffic counter totals do not agree")
        if "expires_at" in row:
            if not isinstance(row.get("trial", False), bool):
                raise ValidationError("Invalid trial flag")
            try:
                if datetime.fromisoformat(row["expires_at"]).tzinfo is None:
                    raise ValueError("Timezone required")
            except (ValueError, TypeError):
                raise ValidationError("Trial expiry must be a timezone-aware timestamp")
            item.update(expires_at=row["expires_at"], trial=bool(row.get("trial")))
        if row.get("subscription_hash"):
            digest = row["subscription_hash"]
            if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or digest in digests:
                raise ValidationError("Invalid subscription digest in backup")
            digests.add(digest)
            item["subscription_hash"] = digest
            issued = row.get("subscription_issued_at", "")
            try:
                datetime.fromisoformat(issued)
            except (ValueError, TypeError) as exc:
                raise ValidationError("Invalid subscription issue date") from exc
            item["subscription_issued_at"] = issued
        clean.append(item)
    return network, clean
