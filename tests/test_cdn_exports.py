from __future__ import annotations

import base64
import json
import sys
from contextlib import nullcontext
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import paneld  # noqa: E402
from cdn_manager import configure_profile, public_config, target_for  # noqa: E402
from common import ValidationError  # noqa: E402
from exporter import client_json, export_bundle, share_link  # noqa: E402
from protocols import enable_protocols  # noqa: E402


def make_user() -> dict:
    return enable_protocols(
        {
            "username": "alice",
            "expiry": (date.today() + timedelta(days=30)).isoformat(),
            "quota_gb": None,
        },
        ["vless", "vmess", "trojan"],
    )


def cloudfront_config() -> dict:
    return configure_profile(
        {},
        provider="cloudfront",
        endpoint="d123example.cloudfront.net",
        origin="vpn.example.com",
        origin_secret="A" * 32,
    )


def test_cloudfront_route_and_secret_redaction() -> None:
    config = cloudfront_config()
    target = target_for(
        domain="vpn.example.com",
        protocol="vless",
        provider="cloudfront",
        cdn_config=config,
    )
    assert target == {
        "provider": "cloudfront",
        "address": "d123example.cloudfront.net",
        "host": "d123example.cloudfront.net",
        "sni": "d123example.cloudfront.net",
        "port": 443,
        "path": "/cloudfront/vless",
    }
    assert "origin_secret" not in public_config(config)["profiles"]["cloudfront"]


@pytest.mark.parametrize(
    "endpoint", ["vpn.example.com", "cdn.example.com", "cloudfront.net"]
)
def test_cloudfront_requires_distribution_hostname(endpoint: str) -> None:
    with pytest.raises(ValidationError, match="distribution hostname"):
        configure_profile(
            {},
            provider="cloudfront",
            endpoint=endpoint,
            origin="vpn.example.com",
            origin_secret="A" * 32,
        )


def test_cloudflare_requires_cert_matching_hostname() -> None:
    config = configure_profile(
        {},
        provider="cloudflare",
        endpoint="vpn.example.com",
        origin="vpn.example.com",
    )
    assert config["profiles"]["cloudflare"]["enabled"] is True
    with pytest.raises(ValidationError):
        configure_profile(
            {},
            provider="cloudflare",
            endpoint="cdn.example.com",
            origin="vpn.example.com",
        )


def test_panel_cdn_requires_installed_origin_domain_and_certificate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    domain_file = tmp_path / "domain.conf"
    domain_file.write_text("vpn.example.com\n", encoding="utf-8")
    live = tmp_path / "live"
    certificate = live / "vpn.example.com"
    certificate.mkdir(parents=True)
    (certificate / "fullchain.pem").write_text("test", encoding="utf-8")
    (certificate / "privkey.pem").write_text("test", encoding="utf-8")
    monkeypatch.setattr(paneld, "DOMAIN_FILE", domain_file)
    monkeypatch.setattr(paneld, "CDN_FILE", tmp_path / "cdn.json")
    monkeypatch.setattr(paneld, "LETSENCRYPT_LIVE", live)
    monkeypatch.setattr(paneld, "state_lock", nullcontext)
    monkeypatch.setattr(
        paneld, "install_nginx_config", lambda domain: domain == "vpn.example.com"
    )

    with pytest.raises(ValidationError, match="must match"):
        paneld.configure_cdn(
            {
                "provider": "cloudfront",
                "endpoint": "d123example.cloudfront.net",
                "origin": "other.example.com",
                "origin_secret": "A" * 32,
            }
        )
    result = paneld.configure_cdn(
        {
            "provider": "cloudfront",
            "endpoint": "d123example.cloudfront.net",
            "origin": "vpn.example.com",
            "origin_secret": "A" * 32,
        }
    )
    assert result["profile"]["origin"] == "vpn.example.com"


def test_domain_change_requires_cdn_disable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    domain_file = tmp_path / "domain.conf"
    domain_file.write_text("vpn.example.com\n", encoding="utf-8")
    cdn_file = tmp_path / "cdn.json"
    cdn_file.write_text(json.dumps(cloudfront_config()), encoding="utf-8")
    monkeypatch.setattr(paneld, "DOMAIN_FILE", domain_file)
    monkeypatch.setattr(paneld, "CDN_FILE", cdn_file)

    with pytest.raises(ValidationError, match="Disable active CDN"):
        paneld.set_domain({"domain": "new.example.com"})


def test_certificate_hostname_must_match_panel_domain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    domain_file = tmp_path / "domain.conf"
    domain_file.write_text("vpn.example.com\n", encoding="utf-8")
    monkeypatch.setattr(paneld, "DOMAIN_FILE", domain_file)

    with pytest.raises(ValidationError, match="must match"):
        paneld.issue_cert({"domain": "other.example.com"})


@pytest.mark.parametrize("protocol", ["vmess", "vless", "trojan"])
def test_current_xray_socks_client_shape(protocol: str) -> None:
    config = client_json(
        make_user(),
        protocol,
        domain="vpn.example.com",
        provider="direct",
        cdn_config={},
    )
    assert config["inbounds"][0]["protocol"] == "socks"
    assert config["inbounds"][0]["listen"] == "127.0.0.1"
    outbound = config["outbounds"][0]
    assert outbound["protocol"] == protocol
    if protocol in {"vmess", "vless"}:
        assert outbound["settings"]["vnext"][0]["address"] == "vpn.example.com"
        assert "servers" not in outbound["settings"]
    else:
        assert outbound["settings"]["servers"][0]["address"] == "vpn.example.com"
        assert "vnext" not in outbound["settings"]


def test_bundle_contains_open_profiles_and_authorized_payload() -> None:
    files = export_bundle(
        make_user(),
        "vless",
        domain="vpn.example.com",
        provider="cloudfront",
        cdn_config=cloudfront_config(),
    )
    assert sorted(Path(name).suffix for name in files).count(".json") == 3
    assert len(files) == 5
    payload = next(
        value for name, value in files.items() if name.endswith(".payload.txt")
    )
    assert "GET /cloudfront/vless HTTP/1.1[crlf]" in payload
    assert "A" * 32 not in "".join(files.values())


def test_vmess_link_decodes_to_v2_share_object() -> None:
    link = share_link(make_user(), "vmess", domain="vpn.example.com", cdn_config={})
    raw = link.removeprefix("vmess://")
    decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    data = json.loads(decoded)
    assert data["add"] == "vpn.example.com"
    assert data["net"] == "ws"
    assert data["tls"] == "tls"
