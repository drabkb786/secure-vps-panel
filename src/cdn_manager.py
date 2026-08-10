#!/usr/bin/env python3
"""CDN profile validation and connection-target selection."""

from __future__ import annotations

import copy
import secrets
from datetime import datetime, timezone
from typing import Any

from common import (
    ValidationError,
    validate_cdn_provider,
    validate_domain,
    validate_origin_secret,
)
from protocols import normalize_protocol_settings


def empty_cdn_config() -> dict[str, Any]:
    return {"active": "direct", "profiles": {}}


def configure_profile(
    existing: dict[str, Any] | None,
    *,
    provider: str,
    endpoint: str,
    origin: str,
    enabled: bool = True,
    origin_secret: str = "",
) -> dict[str, Any]:
    provider = validate_cdn_provider(provider)
    if provider == "direct":
        raise ValidationError(
            "Direct mode uses the panel domain and does not need a CDN profile"
        )
    endpoint = validate_domain(endpoint)
    origin = validate_domain(origin)
    if provider == "cloudfront":
        if endpoint == origin or not endpoint.endswith(".cloudfront.net"):
            raise ValidationError(
                "CloudFront endpoint must be the distribution hostname ending in .cloudfront.net"
            )
        origin_secret = validate_origin_secret(
            origin_secret or secrets.token_urlsafe(32)
        )
    else:
        if endpoint != origin:
            raise ValidationError(
                "Cloudflare endpoint must match the TLS origin hostname; use the panel domain as an orange-cloud DNS record"
            )
        origin_secret = ""

    result = (
        copy.deepcopy(existing) if isinstance(existing, dict) else empty_cdn_config()
    )
    profiles = result.get("profiles")
    if not isinstance(profiles, dict):
        profiles = {}
    profiles[provider] = {
        "provider": provider,
        "endpoint": endpoint,
        "origin": origin,
        "enabled": bool(enabled),
        "origin_secret": origin_secret,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    result["profiles"] = profiles
    if enabled:
        result["active"] = provider
    return result


def disable_profile(existing: dict[str, Any] | None, provider: str) -> dict[str, Any]:
    provider = validate_cdn_provider(provider)
    if provider == "direct":
        raise ValidationError("Direct mode is the fallback and cannot be removed")
    result = (
        copy.deepcopy(existing) if isinstance(existing, dict) else empty_cdn_config()
    )
    profiles = result.get("profiles", {})
    if provider in profiles and isinstance(profiles[provider], dict):
        profiles[provider]["enabled"] = False
        profiles[provider]["updated_at"] = datetime.now(timezone.utc).isoformat()
    if result.get("active") == provider:
        result["active"] = "direct"
    return result


def public_config(config: dict[str, Any] | None) -> dict[str, Any]:
    """Return CDN state without origin verification secrets."""
    result = copy.deepcopy(config) if isinstance(config, dict) else empty_cdn_config()
    for item in result.get("profiles", {}).values():
        if isinstance(item, dict):
            item.pop("origin_secret", None)
    return result


def target_for(
    *,
    domain: str,
    protocol: str,
    cdn_config: dict[str, Any] | None,
    provider: str = "direct",
    protocol_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    domain = validate_domain(domain)
    provider = validate_cdn_provider(provider)
    settings = normalize_protocol_settings(protocol_settings)
    if protocol not in settings:
        raise ValidationError(
            "Only vmess, vless and trojan have Xray connection profiles"
        )
    path = settings[protocol]["path"]

    if provider == "direct":
        return {
            "provider": "direct",
            "address": domain,
            "host": domain,
            "sni": domain,
            "port": 443,
            "path": path,
        }

    profiles = (cdn_config or {}).get("profiles", {})
    profile = profiles.get(provider) if isinstance(profiles, dict) else None
    if not isinstance(profile, dict) or not profile.get("enabled"):
        raise ValidationError(f"{provider} profile is not enabled")
    endpoint = validate_domain(str(profile.get("endpoint", "")))
    if provider == "cloudfront":
        path = "/cloudfront" + path
    return {
        "provider": provider,
        "address": endpoint,
        "host": endpoint,
        "sni": endpoint,
        "port": 443,
        "path": path,
    }
