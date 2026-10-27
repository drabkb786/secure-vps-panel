from __future__ import annotations

import base64
import json
from datetime import date, timedelta
from urllib.parse import parse_qs, urlsplit, unquote

import pytest

import xray_manager as xray
from common import ValidationError, read_json


@pytest.fixture
def manager(tmp_path, monkeypatch):
    for attr, value in {"SETTINGS_FILE": tmp_path / "network.json", "ACCOUNTS_FILE": tmp_path / "accounts.json",
                        "CONFIG_DIR": tmp_path / "xray", "CONFIG_FILE": tmp_path / "xray/config.json",
                        "ENABLED_FILE": tmp_path / "xray/enabled", "DOMAIN_FILE": tmp_path / "domain",
                        "CERT_ROOT": tmp_path / "certs", "XRAY_BINARY": tmp_path / "core"}.items():
        monkeypatch.setattr(xray, attr, value)
    xray.DOMAIN_FILE.write_text("vpn.example.com")
    xray.XRAY_BINARY.touch()
    cert = xray.CERT_ROOT / "vpn.example.com"
    cert.mkdir(parents=True)
    for name in ("fullchain.pem", "privkey.pem"):
        (cert / name).touch()
    calls = []
    def run(args, **kwargs):
        calls.append(args)
    obj = xray.Manager(run, health_probe=lambda: True)
    obj.calls = calls
    return obj


def test_profiles_exports_and_authentication_material(manager):
    manager.configure({"enabled": True})
    manager.create({"name": "basit", "days": 30})
    config = read_json(xray.CONFIG_FILE)
    rows = xray.accounts()
    assert len(config["inbounds"]) == 3
    assert all(i["listen"] == "127.0.0.1" for i in config["inbounds"])
    assert len({i["port"] for i in config["inbounds"]}) == 3
    assert all(len(i["settings"]["clients"]) == 1 for i in config["inbounds"])
    assert "uuid" not in manager.status({})["accounts"][0]
    assert "trojan_password" not in json.dumps(manager.status({}))
    export = manager.export({"name": "basit"})
    assert set(export["links"]) == {"vless", "vmess", "trojan"}
    for protocol in xray.PROTOCOLS:
        profile = json.loads(export["files"][f"basit-{protocol}.json"])
        stream = profile["outbounds"][0]["streamSettings"]
        assert stream["security"] == "tls"
        assert stream["tlsSettings"] == {"allowInsecure": False, "serverName": "vpn.example.com"}
        assert stream["wsSettings"]["path"] == xray.PROTOCOLS[protocol][1]
    vmess = json.loads(base64.b64decode(export["links"]["vmess"].split("://")[1]))
    assert vmess["id"] == rows[0]["uuid"] and vmess["aid"] == "0"
    vless = urlsplit(export["links"]["vless"])
    assert vless.username == rows[0]["uuid"]
    assert parse_qs(vless.query)["path"] == ["/vless"]
    assert base64.b64decode(export["files"]["subscription.txt"]).decode() == export["files"]["links.txt"]
    assert xray.CONFIG_FILE.stat().st_mode & 0o777 == 0o640
    assert xray.ACCOUNTS_FILE.stat().st_mode & 0o777 == 0o600


def test_failed_restart_restores_accounts_config_and_enabled_state(manager):
    manager.configure({"enabled": True})
    old = {p: p.read_bytes() for p in (xray.CONFIG_FILE, xray.SETTINGS_FILE, xray.ACCOUNTS_FILE, xray.ENABLED_FILE)}
    def fail(args, **kwargs):
        if args[1] == "restart":
            raise RuntimeError("Simulated startup failure")
    manager.run = fail
    with pytest.raises(RuntimeError):
        manager.create({"name": "rollback_test", "days": 10})
    assert {p: p.read_bytes() for p in old} == old


def test_failed_candidate_never_replaces_working_files(manager):
    manager.configure({"enabled": True})
    before = xray.CONFIG_FILE.read_bytes()
    def fail(args, **kwargs):
        raise RuntimeError("Invalid config")
    manager.run = fail
    with pytest.raises(RuntimeError):
        manager.create({"name": "candidate", "days": 10})
    assert xray.CONFIG_FILE.read_bytes() == before
    assert xray.accounts() == []
    assert not list(xray.CONFIG_DIR.glob(".candidate-*"))


def test_expiry_sync_removes_access_and_renew_restores_it(manager):
    manager.configure({"enabled": True})
    manager.create({"name": "expire_me", "days": 1})
    rows = xray.accounts()
    rows[0]["expiry"] = date.today().isoformat()
    xray.atomic_write_json(xray.ACCOUNTS_FILE, rows)
    manager.sync({})
    assert all(not inbound["settings"]["clients"] for inbound in read_json(xray.CONFIG_FILE)["inbounds"])
    with pytest.raises(ValidationError):
        manager.export({"name": "expire_me"})
    manager.update({"name": "expire_me", "action": "renew", "days": 30})
    assert all(inbound["settings"]["clients"] for inbound in read_json(xray.CONFIG_FILE)["inbounds"])
    before = len([c for c in manager.calls if c[1] == "restart"])
    manager.sync({})
    assert len([c for c in manager.calls if c[1] == "restart"]) == before


def test_disabled_profiles_and_engine_stay_disabled_after_reboot(manager):
    manager.configure({"enabled": True})
    manager.create({"name": "testuser", "days": 5, "protocols": ["vless"]})
    manager.update({"name": "testuser", "action": "toggle", "enabled": False})
    assert all(not i["settings"]["clients"] for i in read_json(xray.CONFIG_FILE)["inbounds"])
    manager.configure({"enabled": False})
    assert not xray.ENABLED_FILE.exists()
    assert manager.calls[-1] == ["/bin/systemctl", "stop", "abdulbasit-xray"]


@pytest.mark.parametrize("params", [{"servers": []}, {"servers": ["http://example.com/dns-query"]}, {"servers": ["https://user:pass@example.com/dns-query"]}, {"servers": ["https://example.com:8443/dns-query"]}, {"servers": ["bad;reboot"]}, {"servers": ["1.1.1.1"], "query_strategy": "bad"}])
def test_reject_unsafe_dns(params):
    with pytest.raises(ValidationError):
        xray.validate_dns(params)


def test_dns_change_is_in_server_and_client_exports(manager):
    manager.configure({"enabled": True})
    manager.create({"name": "resolver", "days": 5})
    manager.set_dns({"servers": ["https://cloudflare-dns.com/dns-query", "2606:4700:4700::1111"], "query_strategy": "UseIP"})
    assert read_json(xray.CONFIG_FILE)["dns"]["queryStrategy"] == "UseIP"
    exported = json.loads(manager.export({"name": "resolver"})["files"]["resolver-vless.json"])
    assert exported["dns"] == read_json(xray.CONFIG_FILE)["dns"]


def test_enabling_requires_certificate_and_core(manager):
    xray.XRAY_BINARY.unlink()
    with pytest.raises(ValidationError, match="not installed"):
        manager.configure({"enabled": True})
    assert not xray.CONFIG_FILE.exists()


def test_reenable_restarts_stopped_service_even_with_unchanged_config(manager):
    manager.configure({"enabled": True})
    before = sum(c[1] == "restart" for c in manager.calls)
    manager.configure({"enabled": True})
    assert sum(c[1] == "restart" for c in manager.calls) == before + 1


def test_failed_listener_readiness_rolls_back_even_after_successful_systemctl(manager):
    manager.configure({"enabled": True})
    previous = {p: p.read_bytes() for p in (xray.CONFIG_FILE, xray.SETTINGS_FILE, xray.ACCOUNTS_FILE, xray.ENABLED_FILE)}
    def not_ready():
        raise RuntimeError("Xray did not become ready")
    manager.wait_running = not_ready
    with pytest.raises(RuntimeError, match="not become ready"):
        manager.create({"name": "not_ready", "days": 3})
    assert {p: p.read_bytes() for p in previous} == previous
    assert xray.ENABLED_FILE.stat().st_mode & 0o777 == 0o644


def test_creation_returns_direct_links_and_separate_txt_files(manager):
    manager.configure({"enabled": True})
    created = manager.create({"name": "direct", "days": 7, "protocols": ["vless", "trojan"]})
    exported = manager.export({"name": "direct"})
    assert created["links"] == exported["links"]
    assert set(exported["links"]) == {"vless", "trojan"}
    for p in exported["links"]:
        assert exported["files"][f"direct-{p}.txt"] == exported["links"][p] + "\n"
    manager.health_probe = lambda: False
    offline = manager.export({"name": "direct"})
    assert offline["links"] == created["links"]
    assert offline["readiness"]["core_ready"] is False
    assert offline["readiness"]["warnings"]
    assert offline["readiness"]["public_reachability"] == "not_checked"


def test_trojan_uri_percent_encoding_preserves_password():
    password = "test:@/?#%+&=value"
    link = xray.share_link("trojan", {"name": "encoding", "trojan_password": password}, "vpn.example.com")
    parsed = urlsplit(link)
    assert unquote(parsed.username) == password
    assert parsed.password is None and parsed.hostname == "vpn.example.com" and parsed.port == 443
    assert parse_qs(parsed.query)["path"] == ["/trojan"]


def test_invalid_share_link_protocol_and_domain_are_rejected():
    with pytest.raises(ValidationError):
        xray.share_link("other", {}, "vpn.example.com")
    with pytest.raises(ValidationError):
        xray.share_link("vless", {}, "example.com?injected=true")
