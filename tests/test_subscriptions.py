import base64
import copy
import json
from datetime import date
from urllib.parse import urlsplit

import pytest

import xray_manager as xray
from common import ValidationError, read_json


def issue(manager):
    manager.configure({"enabled": True})
    manager.create({"name": "basit", "days": 30})
    result = manager.subscription_rotate({"name": "basit"})
    return result, result["url"].rsplit("/", 1)[1]


def test_subscription_token_is_one_time_displayed_hashed_and_rotatable(manager):
    result, token = issue(manager)
    assert len(token) == 43 and urlsplit(result["url"]).scheme == "https"
    assert token not in xray.ACCOUNTS_FILE.read_text()
    status = manager.status({})["accounts"][0]
    assert status["subscription_enabled"] and "subscription_hash" not in status
    original = manager.subscription_get({"token": token, "format": "plain"})["content"]
    new = manager.subscription_rotate({"name": "basit"})["url"].rsplit("/", 1)[1]
    with pytest.raises(ValidationError):
        manager.subscription_get({"token": token})
    assert manager.subscription_get({"token": new, "format": "plain"})["content"] == original
    manager.subscription_revoke({"name": "basit"})
    with pytest.raises(ValidationError):
        manager.subscription_get({"token": new})


@pytest.mark.parametrize("restriction", ["disabled_profile", "expired", "disabled_engine"])
def test_subscription_cannot_export_ineligible_accounts(manager, restriction):
    _, token = issue(manager)
    if restriction == "disabled_profile":
        manager.update({"name": "basit", "action": "toggle", "enabled": False})
    elif restriction == "expired":
        rows = xray.accounts(); rows[0]["expiry"] = date.today().isoformat(); xray.atomic_write_json(xray.ACCOUNTS_FILE, rows)
    else:
        manager.configure({"enabled": False})
    with pytest.raises(ValidationError):
        manager.subscription_get({"token": token})


def test_live_subscription_formats_reflect_current_account_without_reissuing_token(manager):
    _, token = issue(manager)
    plain = manager.subscription_get({"token": token, "format": "plain"})
    assert "vless://" in plain["content"] and "trojan://" in plain["content"]
    encoded = manager.subscription_get({"token": token})
    assert base64.b64decode(encoded["content"]).decode() == plain["content"]
    for format_name in ("clash", "singbox", "xray"):
        data = json.loads(manager.subscription_get({"token": token, "format": format_name})["content"])
        assert data
        assert '"insecure": true' not in json.dumps(data)
        assert '"skip-cert-verify": true' not in json.dumps(data)
    manager.update({"name": "basit", "action": "renew", "days": 1})
    assert manager.subscription_get({"token": token})["expiry"] != plain["expiry"]


def test_xhttp_opt_in_adds_correct_vless_variant_without_removing_existing_links(manager):
    _, token = issue(manager)
    previous = manager.export({"name": "basit"})["links"]
    manager.configure({"enabled": True, "xhttp_enabled": True})
    exported = manager.export({"name": "basit"})
    assert all(exported["links"][p] == link for p, link in previous.items())
    assert "type=xhttp" in exported["links"]["vless-xhttp"]
    cfg = json.loads(exported["files"]["basit-vless-xhttp.json"])
    assert cfg["outbounds"][0]["protocol"] == "vless"
    assert cfg["outbounds"][0]["streamSettings"]["network"] == "xhttp"
    assert "type=xhttp" in manager.subscription_get({"token": token, "format": "plain"})["content"]
    assert read_json(xray.CONFIG_FILE)["inbounds"][-1]["listen"] == "127.0.0.1"


def test_valid_backup_round_trip_preserves_credentials_and_saves_private_recovery_copy(manager):
    _, token = issue(manager)
    manager.configure({"enabled": True, "xhttp_enabled": True})
    backup = manager.backup_export({})["backup"]
    credential = xray.accounts()[0]["uuid"]
    manager.update({"name": "basit", "action": "delete"})
    result = manager.backup_restore({"backup": backup})
    assert result["restored"] == 1 and xray.accounts()[0]["uuid"] == credential
    assert manager.subscription_get({"token": token})["name"] == "basit"
    assert xray.DOMAIN_FILE.read_text() == "vpn.example.com"
    assert list(xray.BACKUP_DIR.glob("*.json"))[0].stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("defect", ["schema", "duplicate", "uuid", "protocol", "enabled", "path", "oversize"])
def test_invalid_backup_never_changes_working_files(manager, defect):
    issue(manager)
    backup = copy.deepcopy(manager.backup_export({})["backup"])
    if defect == "schema": backup["schema"] = "other"
    elif defect == "duplicate": backup["accounts"].append(copy.deepcopy(backup["accounts"][0]))
    elif defect == "uuid": backup["accounts"][0]["uuid"] = "bad"
    elif defect == "protocol": backup["accounts"][0]["protocols"] = ["unrecognized"]
    elif defect == "enabled": backup["network"]["enabled"] = "true"
    elif defect == "path": backup["accounts"][0]["name"] = "../../root"
    else: backup["extra"] = "A" * (257 * 1024)
    before = {p: p.read_bytes() for p in (xray.CONFIG_FILE, xray.SETTINGS_FILE, xray.ACCOUNTS_FILE)}
    with pytest.raises(ValidationError):
        manager.backup_restore({"backup": backup})
    assert {p: p.read_bytes() for p in before} == before
    assert not xray.BACKUP_DIR.exists()


def test_failed_restore_rolls_back_accounts_and_network(manager):
    issue(manager)
    backup = copy.deepcopy(manager.backup_export({})["backup"])
    backup["network"]["dns"]["servers"] = ["9.9.9.9"]
    before = {p: p.read_bytes() for p in (xray.CONFIG_FILE, xray.SETTINGS_FILE, xray.ACCOUNTS_FILE)}
    def fail(args, **kwargs):
        if args[1] == "restart": raise RuntimeError("simulated restart failure")
    manager.run = fail
    with pytest.raises(RuntimeError): manager.backup_restore({"backup": backup})
    assert {p: p.read_bytes() for p in before} == before


@pytest.mark.parametrize("store", ["accounts", "network"])
def test_corrupt_store_is_reported_instead_of_silently_treating_it_as_empty(manager, store):
    issue(manager)
    path = xray.ACCOUNTS_FILE if store == "accounts" else xray.SETTINGS_FILE
    path.write_text("{broken JSON")
    with pytest.raises(RuntimeError):
        manager.backup_export({})
    assert path.read_text() == "{broken JSON"


@pytest.mark.parametrize("store", ["accounts", "network"])
def test_restore_recovers_corrupt_metadata_and_keeps_raw_recovery_copy(manager, store):
    issue(manager)
    backup = manager.backup_export({})["backup"]
    path = xray.ACCOUNTS_FILE if store == "accounts" else xray.SETTINGS_FILE
    path.write_text("{broken JSON")
    result = manager.backup_restore({"backup": backup})
    assert result["restored"] == 1
    assert manager.status({})["accounts"][0]["name"] == "basit"
    recovery = read_json(next(xray.BACKUP_DIR.glob("*.json")))
    assert recovery["schema"] == "noway-xray-raw-recovery-v1"
    assert recovery["files"][path.name] == "{broken JSON"
