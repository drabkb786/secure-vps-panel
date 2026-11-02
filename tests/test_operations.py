import copy
import json
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

import pytest

import maintenance
import operations
import paneld
import slowdns
import traffic
import xray_manager as xray
from common import ValidationError, atomic_write_json


def create(manager, **extra):
    manager.configure({"enabled": True})
    manager.create({"name": "basit", "days": 30, **extra})


def fake_stats(monkeypatch, manager, values):
    monkeypatch.setattr(manager, "api", lambda *args: {"stat": [{"name": f"user>>>basit-vless@noway.local>>>traffic>>>{direction}", "value": str(value)} for direction, value in values.items()]})


def test_trial_is_exactly_twenty_four_hours_and_expiry_blocks_export(manager):
    before = datetime.now(timezone.utc)
    create(manager, trial=True, quota_gb=1)
    row = xray.accounts()[0]
    assert timedelta(hours=23, minutes=59) < datetime.fromisoformat(row["expires_at"]) - before < timedelta(hours=24, seconds=3)
    row["expires_at"] = (before - timedelta(seconds=1)).isoformat()
    atomic_write_json(xray.ACCOUNTS_FILE, [row])
    assert not xray.active(row)
    with pytest.raises(ValidationError): manager.export({"name": "basit"})


def test_sample_is_idempotent_persistent_and_preserves_totals_across_core_restart(manager, monkeypatch):
    create(manager)
    counts = {"uplink": 100, "downlink": 200}; fake_stats(monkeypatch, manager, counts)
    assert manager.collect_usage()["available"]
    assert xray.accounts()[0]["used_bytes"] == 300
    manager.collect_usage(); assert xray.accounts()[0]["used_bytes"] == 300
    counts["downlink"] = 250; manager.collect_usage()
    assert xray.accounts()[0]["used_bytes"] == 350
    traffic.new_epoch(); counts.update(uplink=10, downlink=20); manager.collect_usage()
    assert xray.accounts()[0]["used_bytes"] == 380


def test_authoritative_totals_repair_stale_metadata_without_double_count(manager, monkeypatch):
    create(manager); fake_stats(monkeypatch, manager, {"uplink": 100, "downlink": 200})
    before = xray.accounts(); manager.collect_usage()
    atomic_write_json(xray.ACCOUNTS_FILE, before)  # Simulate crash before metadata cache was updated.
    manager.collect_usage()
    assert xray.accounts()[0]["used_bytes"] == 300


def test_quota_reached_removes_credentials_from_live_config_and_blocks_export(manager, monkeypatch):
    create(manager, quota_gb=0.1)
    fake_stats(monkeypatch, manager, {"uplink": 0, "downlink": int(0.1 * 1024 ** 3) + 1})
    manager.sync({})
    assert all(not item["settings"]["clients"] for item in json.loads(xray.CONFIG_FILE.read_text())["inbounds"])
    assert manager.status({})["accounts"][0]["quota_exhausted"]
    with pytest.raises(ValidationError): manager.export({"name": "basit"})


def test_reset_usage_keeps_credentials_and_does_not_recharge_old_counters(manager, monkeypatch):
    create(manager); counts = {"uplink": 100, "downlink": 200}; fake_stats(monkeypatch, manager, counts)
    manager.collect_usage(); identity = xray.accounts()[0]["uuid"]
    manager.update({"name": "basit", "action": "reset_usage"})
    assert xray.accounts()[0]["used_bytes"] == 0 and xray.accounts()[0]["uuid"] == identity
    manager.collect_usage(); assert xray.accounts()[0]["used_bytes"] == 0
    counts["uplink"] = 125; manager.collect_usage(); assert xray.accounts()[0]["used_bytes"] == 25


def test_unavailable_stats_never_fabricates_or_resets_usage(manager):
    create(manager)
    rows = xray.accounts(); rows[0].update(used_bytes=456, upload_bytes=123, download_bytes=333); atomic_write_json(xray.ACCOUNTS_FILE, rows)
    assert manager.collect_usage()["available"] is False
    assert xray.accounts()[0]["used_bytes"] == 456
    with pytest.raises(ValidationError): manager.update({"name": "basit", "action": "reset_usage"})


def test_udp_policy_and_private_target_blocking_coexist():
    config = xray.server_config({"dns": xray.DEFAULT_DNS, "udp_enabled": False}, [])
    assert config["routing"]["rules"][0]["network"] == "udp"
    assert "169.254.0.0/16" in config["routing"]["rules"][1]["ip"]
    assert config["api"]["listen"] == "/run/abdulbasit-xray/stats.sock"
    assert config["api"]["services"] == ["StatsService"]


def test_gateway_peers_are_observations_not_fake_verified_accounts():
    rows = operations.parse_peers('ESTAB 0 0 192.0.2.10:443 198.51.100.10:55000\nESTAB 0 0 [::1]:443 [::1]:33200\nESTAB 0 0 192.0.2.10:22 198.51.100.10:55001')
    assert len(rows) == 1 and rows[0]["ip"] == "198.51.100.10" and not rows[0]["verified_account"]


def test_native_ip_schema_normalization():
    assert traffic.ip_rows({"users": [{"email": "basit-vless@noway.local", "ips": [{"ip": "198.51.100.42", "lastSeen": "123"}]}]})[0]["ip"] == "198.51.100.42"


def test_managed_logs_are_bounded_and_secrets_redacted():
    calls = []
    def run(args, **kw): calls.append(args); return SimpleNamespace(stdout='trojan://secret@vpn.example.com\n/panel/sub/' + 'A' * 43)
    manager = operations.Manager(run, None, None, None)
    text = manager.logs({})["text"]
    assert "secret" not in text and 'A' * 43 not in text
    assert "100" in calls[0]
    with pytest.raises(ValidationError): manager.logs({"service": "ssh;id"})
    with pytest.raises(ValidationError): manager.packet_test({"target": "127.0.0.1"})


def test_banner_control_codes_rejected_and_restart_failure_rolls_back(tmp_path, monkeypatch):
    path = tmp_path / "banner"; path.write_text("Previous\n"); monkeypatch.setattr(operations, "BANNER_FILE", path)
    def fail(*a, **kw): raise RuntimeError("restart failed")
    obj = operations.Manager(fail, None, None, None)
    with pytest.raises(ValidationError): obj.banner_set({"text": "\x1b[2J"})
    with pytest.raises(RuntimeError): obj.banner_set({"text": "New banner"})
    assert path.read_text() == "Previous\n"


def test_root_maintenance_cancellation_has_no_side_effects(monkeypatch):
    monkeypatch.setattr(maintenance.os, "geteuid", lambda: 0)
    monkeypatch.setattr(maintenance, "execute", lambda *a, **kw: pytest.fail("Cancelled action executed"))
    with pytest.raises(ValidationError): maintenance.run("uninstall", confirm=lambda _: "NO")
    monkeypatch.setattr(maintenance.os, "geteuid", lambda: 1000)
    with pytest.raises(ValidationError): maintenance.run("memory")


def test_web_never_exposes_root_maintenance(monkeypatch):
    import web_server
    assert "maintenance" not in web_server.COMMANDS and "slowdns_install" not in web_server.COMMANDS
    assert "backup_restore" not in web_server.COMMANDS


def test_valid_backup_also_recovers_corrupt_traffic_state(manager):
    create(manager)
    backup = manager.backup_export({})["backup"]
    traffic.STATE_FILE.write_text("{broken traffic")
    manager.backup_restore({"backup": backup})
    assert json.loads(traffic.STATE_FILE.read_text())["totals"]
    assert any(p.read_text() == "{broken traffic" for p in xray.BACKUP_DIR.glob("*.traffic.raw"))


def test_usage_reset_failure_restores_the_counter_checkpoint(manager, monkeypatch):
    create(manager, quota_gb=0.1)
    fake_stats(monkeypatch, manager, {"uplink": 0, "downlink": int(0.1 * 1024 ** 3) + 100})
    manager.sync({})
    original = manager.run
    def fail(args, **kw):
        if "restart" in args: raise RuntimeError("simulated restart failure")
        return original(args, **kw)
    monkeypatch.setattr(manager, "run", fail)
    with pytest.raises(RuntimeError): manager.update({"name": "basit", "action": "reset_usage"})
    assert xray.quota_exhausted(xray.accounts()[0])
    assert traffic.state()["totals"][xray.accounts()[0]["uuid"]]["download_bytes"] > 0
