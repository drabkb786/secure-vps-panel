"""Usage continuity, per-account IP isolation and server-side quota enforcement."""
import json
import os
import time
from pathlib import Path
from datetime import date, timedelta
from types import SimpleNamespace

import pytest
import account_policy
import paneld
import session_enforcer
import ssh_meter
import traffic
import xray_manager as xray
from common import atomic_write_json, ValidationError


@pytest.fixture
def ssh_account(tmp_path, monkeypatch):
    directory = tmp_path / "users"; directory.mkdir()
    monkeypatch.setattr(ssh_meter, "STATE_FILE", tmp_path / "ssh-usage.json")
    monkeypatch.setattr(paneld, "USERS_DIR", directory)
    monkeypatch.setattr(session_enforcer, "USERS_DIR", directory)
    row = {"username": "basit", "created_at": "2026-11-04T00:00:00Z", "expiry": (date.today() + timedelta(days=2)).isoformat(), "max_sessions": 5, "max_ips": 2, "enabled": True}
    atomic_write_json(directory / "basit.json", row)
    return row


def test_ssh_reconnect_restart_and_reset_keep_absolute_baselines(ssh_account):
    ledger = ssh_meter.Ledger()
    ledger.update("connection-a", ssh_account, "192.0.2.1", 100, 200)
    ledger.update("connection-a", ssh_account, "192.0.2.1", 100, 200)
    ledger.flush()
    restored = ssh_meter.Ledger()
    restored.update("connection-a", ssh_account, "192.0.2.1", 150, 300)
    restored.update("connection-b", ssh_account, "192.0.2.2", 20, 40)
    totals = restored.data["accounts"][account_policy.ssh_id(ssh_account)]
    assert (totals["upload_bytes"], totals["download_bytes"]) == (170, 340)
    assert totals["ips"]["192.0.2.1"]["download_bytes"] == 300
    restored.reset(ssh_account)
    restored.update("connection-a", ssh_account, "192.0.2.1", 160, 320)
    assert totals is not restored.data["accounts"][account_policy.ssh_id(ssh_account)]
    assert restored.data["accounts"][account_policy.ssh_id(ssh_account)]["upload_bytes"] == 10
    with pytest.raises(ValueError, match="decreased"):
        restored.update("connection-a", ssh_account, "192.0.2.1", 1, 1)


def test_download_snapshot_uses_one_direction_and_detects_usage_resets(ssh_account, monkeypatch):
    monkeypatch.setattr(ssh_meter, "available", lambda: True)
    monkeypatch.setattr(paneld, "list_sessions", lambda _: {"sessions": []})
    ledger = ssh_meter.Ledger()
    ledger.update("live", ssh_account, "192.0.2.1", 1000000000, 594000000)
    ledger.flush()
    before = paneld.download_snapshot({"kind": "ssh", "name": "basit"})
    ledger.update("live", ssh_account, "192.0.2.1", 1000000100, 594000000 + 157286400)
    ledger.flush()
    after = paneld.download_snapshot({"kind": "ssh", "name": "basit"})
    assert int(after["download_bytes"]) - int(before["download_bytes"]) == 157286400
    assert after["identity"] == before["identity"]
    ledger.reset(ssh_account)
    reset = paneld.download_snapshot({"kind": "ssh", "name": "basit"})
    assert reset["reset_at"] != before["reset_at"]
    assert reset["download_bytes"] == "0"


def test_download_snapshot_requires_complete_ssh_coverage(ssh_account, monkeypatch):
    monkeypatch.setattr(ssh_meter, "available", lambda: True)
    monkeypatch.setattr(paneld, "list_sessions", lambda _: {"sessions": [{"username": "basit", "pids": [123]}]})
    monkeypatch.setattr(ssh_meter, "coverage", lambda _: {})
    with pytest.raises(ValidationError, match="complete payload meter"):
        paneld.download_snapshot({"kind": "ssh", "name": "basit"})


def test_ssh_same_ip_multiple_connections_and_account_scoped_ban(ssh_account):
    ledger = ssh_meter.Ledger()
    ssh_account["max_ips"] = 1
    ledger.admit("a", ssh_account, "192.0.2.1")
    ledger.admit("b", ssh_account, "192.0.2.1")
    with pytest.raises(ValueError, match="IP limit"):
        ledger.admit("c", ssh_account, "192.0.2.2")
    account_policy.change_ip(ssh_account, "::ffff:192.0.2.1", True)
    with pytest.raises(ValueError, match="IP blocked"):
        ledger.admit("c", ssh_account, "192.0.2.1")
    other = {**ssh_account, "username": "other", "blocked_ips": []}
    ledger.admit("d", other, "192.0.2.1")
    assert ledger.active["d"]["ip"] == "192.0.2.1"


def test_ssh_enforcer_disconnects_only_account_blocked_ip(ssh_account, monkeypatch):
    ssh_account["blocked_ips"] = ["192.0.2.2"]
    atomic_write_json(paneld.user_file("basit"), ssh_account)
    monkeypatch.setattr(session_enforcer, "dropbear_pids_by_uid", lambda: {1001: [11, 12]})
    monkeypatch.setattr(session_enforcer.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1001))
    monkeypatch.setattr(session_enforcer.ssh_identity, "session_ips", lambda _: {11: "192.0.2.1", 12: "192.0.2.2"})
    calls = []
    monkeypatch.setattr(session_enforcer, "terminate", lambda pids, uid: calls.append((pids, uid)))
    session_enforcer.enforce_once()
    assert calls == [([12], 1001)]


def test_ssh_real_quota_rejects_missing_meter_and_disconnects_exhausted_account(ssh_account, monkeypatch):
    monkeypatch.setattr(ssh_meter, "available", lambda: False)
    with pytest.raises(ValidationError):
        paneld.set_quota({"username": "basit", "quota_gb": 1})
    assert "quota_gb" not in paneld.managed_user("basit")
    ssh_account.update(quota_gb=.1, quota_unit="GB", quota_enforced=True)
    atomic_write_json(paneld.user_file("basit"), ssh_account)
    monkeypatch.setattr(session_enforcer, "dropbear_pids_by_uid", lambda: {1001: [11]})
    monkeypatch.setattr(session_enforcer.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1001))
    calls = []
    monkeypatch.setattr(session_enforcer, "terminate", lambda pids, uid: calls.append(pids))
    session_enforcer.enforce_once()
    assert calls == [[11]]


def test_finite_ssh_quota_cannot_be_bypassed_through_an_unmetered_listener(ssh_account, monkeypatch):
    ssh_account.update(quota_gb=1, quota_unit="GB", quota_enforced=True, max_ips=0)
    atomic_write_json(paneld.user_file("basit"), ssh_account)
    monkeypatch.setattr(ssh_meter, "available", lambda: True)
    monkeypatch.setattr(session_enforcer, "dropbear_pids_by_uid", lambda: {1001: [22]})
    monkeypatch.setattr(session_enforcer.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1001))
    tick = [10.0]
    monkeypatch.setattr(session_enforcer.time, "monotonic", lambda: tick[0])
    session_enforcer._METER_WAIT.clear()
    calls = []
    monkeypatch.setattr(session_enforcer, "terminate", lambda pids, uid: calls.append(pids))
    session_enforcer.enforce_once()
    assert calls == []
    tick[0] = 18.0
    session_enforcer.enforce_once()
    assert calls == [[22]]


def test_meter_coverage_rejects_reused_pid_and_stale_reports(ssh_account):
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    try:
        ticks = Path('/proc', str(os.getpid()), 'stat').read_text().rsplit(')', 1)[1].split()[19]
    except OSError:
        pytest.skip('Host /proc does not expose the execution process namespace')
    token = f'{boot}:{os.getpid()}:{ticks}'
    data = {'sessions': {token: {'identity': 'account', 'reported_at': time.time()}}}
    assert ssh_meter.coverage(data) == {'account': {os.getpid()}}
    data['sessions'][token]['reported_at'] -= 30
    assert ssh_meter.coverage(data) == {}
    data['sessions'] = {token + '1': {'identity': 'account', 'reported_at': time.time()}}
    assert ssh_meter.coverage(data) == {}


def test_xray_ip_counters_are_not_double_counted_or_inherited(manager):
    manager.configure({"enabled": True}); manager.create({"name": "basit", "days": 3})
    row = xray.accounts()[0]
    email = f"{row['uuid']}-vless@noway.local"
    def response(value):
        return {"stat": [{"name": "user>>>noway-meter>>>version", "value": "1"},
            {"name": f"user>>>{email}>>>traffic>>>uplink", "value": str(value)},
            {"name": f"user>>>{email}>>>ip>>>::ffff:192.0.2.1>>>traffic>>>uplink", "value": str(value)}]}
    for value in (100, 100, 150):
        data = traffic.accumulate([row], response(value), "a" * 32)
        atomic_write_json(traffic.STATE_FILE, data)
    assert data["totals"][row["uuid"]]["upload_bytes"] == 150
    assert data["ip_totals"][row["uuid"]]["192.0.2.1"]["upload_bytes"] == 150
    assert data["ip_meter_available"]
    traffic.reset_profile(row)
    data = traffic.accumulate([row], response(160), "a" * 32)
    assert data["ip_totals"][row["uuid"]]["192.0.2.1"]["upload_bytes"] == 10


def test_xray_ban_is_canonical_and_account_scoped_with_rollback(manager):
    manager.configure({"enabled": True}); manager.create({"name": "first", "days": 3}); manager.create({"name": "other", "days": 3})
    manager.update({"name": "first", "action": "ip_policy", "ip": "::ffff:192.0.2.1", "blocked": True})
    config = json.loads(xray.CONFIG_FILE.read_text())
    first, other = xray.accounts()
    rule = config["routing"]["rules"][0]
    assert rule["source"] == ["192.0.2.1"]
    assert set(rule["user"]) == traffic.emails(first)
    assert not set(rule["user"]) & traffic.emails(other)
    original = xray.ACCOUNTS_FILE.read_bytes()
    def fail(*args, **kwargs):
        raise RuntimeError("candidate rejected")
    manager.run = fail
    with pytest.raises(RuntimeError):
        manager.update({"name": "other", "action": "ip_policy", "ip": "192.0.2.2", "blocked": True})
    assert xray.ACCOUNTS_FILE.read_bytes() == original


def test_ip_detail_pagination_keeps_blocked_offline_addresses(manager, monkeypatch):
    manager.configure({"enabled": True}); manager.create({"name": "first", "days": 3})
    manager.update({"name": "first", "action": "ip_policy", "ip": "2001:db8::1", "blocked": True})
    monkeypatch.setattr(paneld, "XRAY", manager)
    monkeypatch.setattr(manager, "online", lambda _: {"profiles": {"first": ["192.0.2.1"]}})
    result = paneld.account_connections({"kind": "xray", "name": "first", "limit": 1})
    assert result["connections"][0]["online"] and result["has_more"]
    result = paneld.account_connections({"kind": "xray", "name": "first", "offset": 1})
    assert result["connections"][0]["blocked"]
    with pytest.raises(ValidationError):
        paneld.account_connections({"kind": "xray", "name": "first", "offset": True})
