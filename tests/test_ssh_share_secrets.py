import base64
import json
import os
import subprocess

import pytest

import ssh_secrets as vault
import ssh_profiles
from common import ValidationError


@pytest.fixture
def secret(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "DIRECTORY", tmp_path / "vault")
    monkeypatch.setattr(vault, "SHADOW", tmp_path / "shadow")
    monkeypatch.setattr(vault, "OWNER", os.geteuid())
    password = "fixture@password:example"
    encoded = subprocess.run([vault.OPENSSL, "passwd", "-6", "-stdin"],
                             input=password + "\n", text=True, capture_output=True, check=True).stdout.strip()
    vault.SHADOW.write_text("basit:" + encoded + ":1:0:99999:7:::\n")
    account = {"username": "basit", "account_id": "account-a", "enabled": True,
               "expiry": "2099-01-01", "max_sessions": 2}
    return account, password


def test_authenticated_vault_roundtrip_is_private_and_bound_to_shadow(secret):
    account, password = secret
    assert vault.load(account) is None
    vault.save(account, password)
    assert vault.load(account) == password
    for path in vault.DIRECTORY.rglob("*"):
        assert not path.stat().st_mode & 0o077
        if path.is_file():
            assert password.encode() not in path.read_bytes()
    vault.SHADOW.write_text("basit:changed-system-password:1:0:99999:7:::\n")
    assert vault.load(account) is None


def test_wrong_password_and_foreign_account_cannot_register_or_inherit(secret):
    account, password = secret
    with pytest.raises(ValidationError, match="current password"):
        vault.save(account, "wrong-fixture")
    assert not vault.DIRECTORY.exists()
    vault.save(account, password)
    assert vault.load({**account, "account_id": "recreated-account"}) is None
    vault.forget(account)
    assert vault.load(account) is None


def test_tampered_ciphertext_is_rejected_and_missing_key_is_not_regenerated(secret):
    account, password = secret
    vault.save(account, password)
    path = vault.record_path(account)
    saved = json.loads(path.read_text())
    data = bytearray(base64.b64decode(saved["cms"])); data[-1] ^= 1
    saved["cms"] = base64.b64encode(data).decode()
    path.write_text(json.dumps(saved))
    with pytest.raises(ValidationError):
        vault.load(account)
    (vault.DIRECTORY / "keys/key.pem").unlink()
    with pytest.raises((ValidationError, FileNotFoundError)):
        vault.save(account, password)
    assert not (vault.DIRECTORY / "keys/key.pem").exists()


def test_world_readable_ciphertext_is_rejected(secret):
    account, password = secret
    vault.save(account, password)
    vault.record_path(account).chmod(0o644)
    with pytest.raises(ValidationError, match="permissions"):
        vault.load(account)


@pytest.mark.parametrize("route,endpoint,prefix", [
    ("direct", "vpn.example.com", ""),
    ("bunny", "cdn.example.com", "/bunny"),
    ("cloudfront", "d123456.cloudfront.net", "/cloudfront"),
])
def test_export_automatically_uses_saved_password_in_exact_two_share_values(secret, tmp_path, monkeypatch, route, endpoint, prefix):
    account, password = secret
    domain = tmp_path / "domain"; domain.write_text("vpn.example.com")
    monkeypatch.setattr(ssh_profiles, "DOMAIN_FILE", domain)
    monkeypatch.setattr(ssh_profiles.cdn_manager, "delivery", lambda *_: (endpoint, prefix))
    monkeypatch.setattr(ssh_profiles.slowdns, "settings", lambda: {"enabled": False})
    vault.save(account, password)
    result = ssh_profiles.export({"username": "basit", "route": route}, lambda _: account)
    port = 80 if route == "direct" else 443
    assert result["share"] == {"credentials": f"{endpoint}:{port}@basit:{password}",
                              "payload": f"GET {prefix}/cdn-cgi HTTP/1.1[crlf]Host: {endpoint}[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"}
    assert "password" not in account
    assert result["password_available"]
    if route != "direct":
        assert "binary WebSocket" in " ".join(result["share_warnings"])


def test_legacy_password_registration_is_verified_then_automatic(secret, tmp_path, monkeypatch):
    account, password = secret
    domain = tmp_path / "domain"; domain.write_text("vpn.example.com")
    monkeypatch.setattr(ssh_profiles, "DOMAIN_FILE", domain)
    monkeypatch.setattr(ssh_profiles.slowdns, "settings", lambda: {"enabled": False})
    before = ssh_profiles.export({"username": "basit"}, lambda _: account)
    assert not before["password_available"] and before["share"]["credentials"].endswith("@basit:")
    ssh_profiles.export({"username": "basit", "password": password, "remember_password": True}, lambda _: account)
    assert ssh_profiles.export({"username": "basit"}, lambda _: account)["share"]["credentials"].endswith(password)


def test_simple_export_does_not_construct_unrequested_bundles(secret, tmp_path, monkeypatch):
    account, password = secret
    domain = tmp_path / "domain"; domain.write_text("vpn.example.com")
    monkeypatch.setattr(ssh_profiles, "DOMAIN_FILE", domain)
    monkeypatch.setattr(ssh_profiles.slowdns, "settings", lambda: pytest.fail("Unrequested full bundle was built"))
    vault.save(account, password)
    result = ssh_profiles.export({"username": "basit", "simple": True}, lambda _: account)
    assert set(result) == {"name", "share", "password_available", "share_warnings"}
    assert set(result["share"]) == {"credentials", "payload"}
