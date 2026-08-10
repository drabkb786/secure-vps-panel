from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cdn_manager import configure_profile  # noqa: E402
from dashboard_auth import (  # noqa: E402
    create_auth_config,
    csrf_token,
    issue_session,
    verify_csrf,
    verify_password,
    verify_session,
)
from nginx_config import render_nginx_config  # noqa: E402


def test_http_listener_does_not_expose_plaintext_xray_or_dashboard() -> None:
    text = render_nginx_config("vpn.example.com", tls=False, ipv6=False)
    assert "127.0.0.1:2082" in text
    assert "127.0.0.1:21001" not in text
    assert "127.0.0.1:21002" not in text
    assert "127.0.0.1:21003" not in text
    assert "/panel/" not in text


def test_tls_config_has_direct_and_secret_checked_cloudfront_routes() -> None:
    cdn = configure_profile(
        {},
        provider="cloudfront",
        endpoint="d123.cloudfront.net",
        origin="vpn.example.com",
        origin_secret="s" * 32,
    )
    text = render_nginx_config("vpn.example.com", tls=True, ipv6=True, cdn_config=cdn)
    assert "location = /vless" in text
    assert "location = /cloudfront/vless" in text
    assert 'if ($http_x_abdulbasit_origin_verify != "' + "s" * 32 + '")' in text
    assert "proxy_pass http://127.0.0.1:21002/vless;" in text
    assert "location ^~ /panel/" in text
    assert (
        text.count('if ($http_x_abdulbasit_origin_verify != "") { return 404; }') == 5
    )


def test_dashboard_password_session_and_csrf() -> None:
    config = create_auth_config("admin", "correct horse battery staple")
    assert verify_password(config, "admin", "correct horse battery staple")
    assert not verify_password(config, "admin", "wrong password")
    token = issue_session(config, now=1_000)
    assert verify_session(config, token, now=1_001)
    assert verify_session(config, token, now=1_000 + 28_801) is None
    csrf = csrf_token(config, token)
    assert verify_csrf(config, token, csrf)
    assert not verify_csrf(config, token, csrf + "x")
