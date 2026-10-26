from types import SimpleNamespace

import pytest

import paneld
from common import ValidationError


def test_domain_is_not_saved_when_nginx_rejects_config(tmp_path, monkeypatch):
    domain = tmp_path / "domain"
    domain.write_text("old.example.com\n")
    monkeypatch.setattr(paneld, "DOMAIN_FILE", domain)
    monkeypatch.setattr(paneld, "ACME_ROOT", tmp_path / "acme")
    monkeypatch.setattr(paneld, "domain_conflicts", lambda _: [])
    monkeypatch.setattr(paneld.xray_manager, "settings", lambda: {"enabled": False})
    def fail(_):
        raise RuntimeError("Nginx rejected config")
    monkeypatch.setattr(paneld, "install_nginx_config", fail)
    with pytest.raises(RuntimeError):
        paneld.set_domain({"domain": "new.example.com"})
    assert domain.read_text() == "old.example.com\n"


def test_nginx_routes_preserve_ssh_and_isolate_xray_tls(monkeypatch):
    monkeypatch.setattr(paneld, "ipv6_enabled", lambda: False)
    tls = paneld.nginx_text("vpn.example.com", True)
    assert "location /panel/" in tls and "127.0.0.1:9090" in tls
    assert "~*websocket 127.0.0.1:2082;" in tls
    assert tls.count("proxy_pass http://127.0.0.1:10001;") == 1
    assert "location = /vless { return 403; }" in tls
    assert "client_max_body_size 16k;" in tls
    assert "listen 443 ssl;" in tls
    plain = paneld.nginx_text("vpn.example.com", False)
    assert "listen 443" not in plain
    assert "proxy_pass http://127.0.0.1:10001" not in plain


def test_web_socket_peer_cannot_change_credentials_or_call_super_admin_commands(monkeypatch):
    monkeypatch.setattr(paneld.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1234))
    monkeypatch.setattr(paneld.web_auth, "revision", lambda: "current")
    with pytest.raises(ValidationError):
        paneld.authorize_command(1234, "configure_web", {})
    with pytest.raises(ValidationError):
        paneld.authorize_command(1234, "configure_bot", {"_web_revision": "current"})
    with pytest.raises(ValidationError):
        paneld.authorize_command(1234, "xray_create", {"_web_revision": "revoked"})
    params = {"_web_revision": "current", "name": "basit"}
    paneld.authorize_command(1234, "xray_create", params)
    assert params == {"name": "basit"}
