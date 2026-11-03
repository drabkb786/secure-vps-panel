"""Regression coverage for counter continuity, unit boundaries and actual IP sets."""
import copy
import json
import os
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import cdn_manager
import gateway_identity
import paneld
import session_enforcer
import ssh_identity
import traffic
import ws_proxy
import xray_manager as xray
from common import ValidationError, atomic_write_json, quota_bytes, validate_quota

EPOCH = "a" * 32


def account(name="basit", identity="a"):
    return {"name": name, "uuid": identity, "protocols": ["vless", "vmess", "trojan"],
            "upload_bytes": 0, "download_bytes": 0, "used_bytes": 0}


def stats(value, name="basit-vless", direction="uplink"):
    return {"stat": [{"name": f"user>>>{name}@noway.local>>>traffic>>>{direction}", "value": str(value)}]}


def save(rows, response, epoch=EPOCH):
    data = traffic.accumulate(rows, response, epoch)
    atomic_write_json(traffic.STATE_FILE, data)
    return data


def test_disappearing_counter_keeps_its_baseline(manager):
    rows = [account()]
    save(rows, stats(100)); save(rows, {})
    save(rows, stats(150))
    assert rows[0]["used_bytes"] == 150


def test_duplicate_counter_rejects_whole_sample_without_mutation(manager):
    rows = [account()]; save(rows, stats(100))
    before = copy.deepcopy(rows); checkpoint = traffic.STATE_FILE.read_bytes()
    response = stats(150); response["stat"] *= 2
    with pytest.raises(RuntimeError, match="Duplicate"):
        save(rows, response)
    assert rows == before and traffic.STATE_FILE.read_bytes() == checkpoint


@pytest.mark.parametrize("value", [True, -1, 1.5, "1.2", "nan", 2 ** 63, None])
def test_invalid_counter_is_never_rounded_or_committed(manager, value):
    rows = [account()]; response = stats(1); response["stat"][0]["value"] = value
    with pytest.raises(RuntimeError): save(rows, response)
    assert rows[0]["used_bytes"] == 0


def test_64_bit_counter_stays_exact_and_reset_keeps_baseline(manager):
    rows = [account()]; amount = 2 ** 53 + 123
    save(rows, stats(amount))
    assert rows[0]["used_bytes"] == amount
    traffic.reset_profile(rows[0]); save(rows, stats(amount + 7))
    assert rows[0]["used_bytes"] == 7


def test_reused_name_does_not_rebill_old_identity(manager):
    rows = [account()]; save(rows, stats(100))
    replacement = [account(identity="replacement")]
    save(replacement, stats(100)); save(replacement, stats(125))
    assert replacement[0]["used_bytes"] == 25


def test_core_epoch_fence_discards_racing_sample(manager, monkeypatch):
    manager.configure({"enabled": True}); manager.create({"name": "basit", "days": 3})
    epochs = iter([EPOCH, "b" * 32, "b" * 32, "b" * 32])
    answers = iter([stats(999), stats(12)])
    monkeypatch.setattr(manager, "epoch", lambda: next(epochs))
    monkeypatch.setattr(manager, "api", lambda *a: next(answers))
    assert manager.collect_usage()["available"]
    assert xray.accounts()[0]["used_bytes"] == 12


def test_unknown_epoch_retains_saved_usage(manager, monkeypatch):
    manager.configure({"enabled": True}); manager.create({"name": "basit", "days": 3})
    rows = xray.accounts(); save(rows, stats(71))
    monkeypatch.setattr(manager, "run", lambda *a, **kw: SimpleNamespace(stdout="unknown"))
    monkeypatch.setattr(manager, "api", lambda *a: pytest.fail("Unidentified epoch was sampled"))
    assert not manager.collect_usage()["available"]
    assert xray.accounts()[0]["used_bytes"] == 71


def test_ledger_hydrates_stale_account_cache_immediately(manager):
    manager.configure({"enabled": True}); manager.create({"name": "basit", "days": 3})
    rows = xray.accounts(); save(rows, stats(1234))
    assert xray.accounts(hydrate=False)[0]["used_bytes"] == 0
    assert manager.status({})["accounts"][0]["exact_bytes"]["used_bytes"] == "1234"


@pytest.mark.parametrize("quota", ["0.1001", "1.2345", "nan", "inf", True])
def test_quota_does_not_silently_round(quota):
    with pytest.raises(ValidationError): validate_quota(quota)


def test_gb_gib_boundary_and_legacy_capacity():
    row = {"quota_gb": .1, "quota_unit": "GB", "used_bytes": 99_999_999}
    assert quota_bytes(row) == 100_000_000 and not xray.quota_exhausted(row)
    row["used_bytes"] += 1
    assert xray.quota_exhausted(row)
    assert quota_bytes({"quota_gb": 1}) == 1_073_741_824
    assert quota_bytes({"quota_gb": 1, "quota_unit": "GB"}) == 1_000_000_000


def test_canonical_ip_union_across_protocols_does_not_truncate():
    row = account()
    response = {"users": [{"email": "basit-vless@noway.local", "ips": [{"ip": "::ffff:198.51.100.1"}]},
                           {"email": "basit-trojan@noway.local", "ips": [{"ip": "198.51.100.1"}, {"ip": "[2001:0db8::1]"}]}]}
    assert traffic.profile_ips([row], traffic.ip_rows(response))["basit"] == ["198.51.100.1", "2001:db8::1"]
    response["users"][0]["ips"] = [{"ip": f"2001:db8::{n:x}"} for n in range(1, 1200)]
    assert len(traffic.ip_rows(response)) > 1000


def test_xray_ip_violation_cooldown_and_monitor_failure(manager, monkeypatch):
    manager.configure({"enabled": True})
    manager.create({"name": "basit", "days": 3, "max_ips": 1})
    manager.create({"name": "other", "days": 3})
    ips = ["198.51.100.1", "198.51.100.2"]
    def api(command, *args):
        if command == "statsquery": return stats(200)
        return {"users": [{"email": "basit-vless@noway.local", "ips": [{"ip": ip} for ip in ips]}]}
    monkeypatch.setattr(manager, "api", api)
    manager.sync({})
    rows = xray.accounts(); assert not xray.active(rows[0]) and xray.active(rows[1])
    live = json.loads(xray.CONFIG_FILE.read_text())
    assert all(len(inbound["settings"]["clients"]) == 1 for inbound in live["inbounds"])
    rows[0]["ip_blocked_until"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    atomic_write_json(xray.ACCOUNTS_FILE, rows); ips.clear(); manager.sync({})
    assert xray.active(xray.accounts()[0])
    monkeypatch.setattr(manager, "api", lambda *a: (_ for _ in ()).throw(RuntimeError("down")))
    manager.sync({})
    rows = xray.accounts(); assert rows[0]["ip_monitoring_failed"] and not xray.active(rows[0])
    assert xray.active(rows[1])


def test_quota_monitor_failure_blocks_only_finite_accounts(manager, monkeypatch):
    manager.configure({"enabled": True})
    manager.create({"name": "basit", "days": 3, "quota_gb": 1})
    manager.create({"name": "other", "days": 3})
    manager.sync({})
    assert not xray.active(xray.accounts()[0]) and xray.active(xray.accounts()[1])


def test_corrupt_ledger_stops_unmetered_core_instead_of_resetting(manager):
    manager.configure({"enabled": True}); manager.create({"name": "basit", "days": 3})
    traffic.STATE_FILE.write_text('{"totals": []}')
    with pytest.raises(RuntimeError, match="stopped"):
        manager.sync({})
    assert manager.calls[-1] == ["/bin/systemctl", "stop", "abdulbasit-xray"]
    assert traffic.STATE_FILE.read_text() == '{"totals": []}'


def test_backup_preserves_units_and_ip_cap_without_runtime_cooldown(manager):
    manager.configure({"enabled": True}); manager.create({"name": "basit", "days": 3, "quota_gb": 1, "max_ips": 2})
    backup = manager.backup_export({})["backup"]
    manager.backup_restore({"backup": backup})
    row = xray.accounts()[0]
    assert row["max_ips"] == 2 and row["quota_unit"] == "GB" and quota_bytes(row) == 1_000_000_000


def test_finite_ssh_quota_is_rejected_before_side_effects(monkeypatch):
    monkeypatch.setattr(paneld, "run", lambda *a, **kw: pytest.fail("OS account mutated"))
    with pytest.raises(ValidationError, match="not supported"):
        paneld.create_user({"username": "basit", "password": "long-fixture-password", "days": 30, "max_sessions": 2, "quota_gb": 1})
    with pytest.raises(ValidationError, match="unavailable"):
        paneld.set_quota({"username": "basit", "quota_gb": 1})


def test_ssh_ip_cap_keeps_multiple_sessions_on_same_ip_and_rejects_unknown(tmp_path, monkeypatch):
    (tmp_path / "basit.json").write_text(json.dumps({"username": "basit", "expiry": "2099-01-01", "max_sessions": 20, "max_ips": 1}))
    (tmp_path / "bad.json").write_text("[]")
    monkeypatch.setattr(session_enforcer, "USERS_DIR", tmp_path)
    monkeypatch.setattr(session_enforcer, "dropbear_pids_by_uid", lambda: {1001: [10, 11, 12, 13]})
    monkeypatch.setattr(session_enforcer.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1001))
    monkeypatch.setattr(ssh_identity, "session_ips", lambda _: {10: "198.51.100.1", 11: "198.51.100.1", 12: "198.51.100.2", 13: None})
    killed = []; monkeypatch.setattr(session_enforcer, "terminate", lambda pids, uid: killed.extend(pids))
    session_enforcer.enforce_once()
    assert killed == [12, 13]


def test_gateway_ip_requires_private_marker_and_single_valid_ip():
    forged = {"x-forwarded-for": "198.51.100.1", "x-noway-gateway": "1"}
    assert ws_proxy.client_ip("127.0.0.1", forged) == "127.0.0.1"
    forged[gateway_identity.header_name().lower()] = "1"
    assert ws_proxy.client_ip("127.0.0.1", forged) == "198.51.100.1"
    forged["x-forwarded-for"] += ",203.0.113.1"
    assert ws_proxy.client_ip("127.0.0.1", forged) == "127.0.0.1"


def test_gateway_mapping_matches_live_kernel_socket_and_expires(monkeypatch):
    if not (ssh_identity.PROC / str(os.getpid()) / "fd").is_dir():
        pytest.skip("Runtime does not expose process descriptors; exercised by native Linux CI")
    monkeypatch.setattr(ssh_identity.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0)); listener.listen(1)
        monkeypatch.setattr(ssh_identity, "SSH_PORTS", {listener.getsockname()[1]})
        with socket.create_connection(listener.getsockname()) as client:
            try:
                os.readlink(ssh_identity.PROC / str(os.getpid()) / "fd" / str(client.fileno()))
            except FileNotFoundError:
                if os.getenv("GITHUB_ACTIONS"):
                    raise
                pytest.skip("Runtime hides current socket descriptors; native Linux CI is required")
            server, _ = listener.accept()
            with server:
                path = ssh_identity.register(client, "198.51.100.9", True)
                port = client.getsockname()[1]
                assert ssh_identity.gateway_ip(port, ssh_identity.tcp_sockets()) == "198.51.100.9"
                data = json.loads(path.read_text()); data["inode"] += 1; atomic_write_json(path, data)
                assert ssh_identity.gateway_ip(port, ssh_identity.tcp_sockets()) is None


def test_cloudfront_function_overwrites_spoofed_viewer_and_rejects_other_paths():
    function = cdn_manager.template()["Resources"]["RouteGuard"]["Properties"]["FunctionCode"]
    js = function + """
const event = {viewer:{ip:'2001:db8::3'}, request:{method:'GET', uri:'/cloudfront/vless', headers:{'x-noway-viewer-ip':{value:'spoof',multiValue:[{value:'spoof'}]}}}};
if (handler(event).headers['x-noway-viewer-ip'].value !== '2001:db8::3') process.exit(1);
if (handler(event).headers['x-noway-viewer-ip'].multiValue) process.exit(2);
event.request.uri='/panel/'; if(handler(event).statusCode !== 403) process.exit(3);
"""
    subprocess.run(["node", "-e", js], check=True, timeout=5)


def test_private_paths_are_absent_from_exports_and_redacted_config(manager):
    manager.configure({"enabled": True, "xhttp_enabled": True}); manager.create({"name": "basit", "days": 3})
    secret = gateway_identity.header_name().split("Gateway-")[1]
    assert secret in xray.CONFIG_FILE.read_text()
    assert secret not in json.dumps(manager.export({"name": "basit"}))
    assert secret not in json.dumps(paneld.OPS.config_view({}))
