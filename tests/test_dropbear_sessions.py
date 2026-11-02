from types import SimpleNamespace

import pytest

import dropbear_sessions as ds
import session_enforcer as enforcer


def auth(pid=201, stamp="11000000", **overrides):
    return {"_PID": str(pid), "_UID": "0", "_EXE": "/usr/sbin/dropbear",
            "_SYSTEMD_UNIT": "dropbear.service", "_BOOT_ID": "testboot",
            "__MONOTONIC_TIMESTAMP": stamp,
            "MESSAGE": "Password auth succeeded for 'basit' from 127.0.0.1:12345", **overrides}


def test_root_forwarding_session_attributed_from_final_auth_only():
    process = ds.Process(201, 200, 0, 1000, "/usr/sbin/dropbear")
    rows = [auth(), auth(pid=202, MESSAGE="Pubkey auth succeeded for 'basit' with ssh-ed25519 key SHA256:abc from [::1]:9999")]
    other = ds.Process(202, 200, 0, 1001, "/usr/sbin/dropbear")
    assert ds.attribute_auth(rows, {201: process, 202: other}, {1001: "basit"}, "testboot", 100) == {(201, 1000): 1001, (202, 1001): 1001}


@pytest.mark.parametrize("change", [
    {"_UID": "1001"}, {"_EXE": "/tmp/dropbear"}, {"_BOOT_ID": "oldboot"},
    {"_PID": "999", "SYSLOG_PID": "201"}, {"__MONOTONIC_TIMESTAMP": "9999999"},
    {"_SYSTEMD_UNIT": "unrelated.service"},
    {"MESSAGE": "Password auth succeeded for 'basit' from 127.0.0.1:1, extra auth required"},
    {"MESSAGE": "Password auth succeeded for 'root' from 127.0.0.1:1"},
])
def test_untrusted_partial_or_reused_pid_auth_is_not_attributed(change):
    process = ds.Process(201, 200, 0, 1000, "/usr/sbin/dropbear")
    assert ds.attribute_auth([auth(**change)], {201: process}, {1001: "basit"}, "testboot", 100) == {}


def test_snapshot_counts_root_and_uid_sessions_but_not_listener_or_standalone(tmp_path, monkeypatch):
    for pid in (200, 201, 202, 203, 204):
        (tmp_path / str(pid)).mkdir()
    boot = tmp_path / "sys/kernel/random/boot_id"
    boot.parent.mkdir(parents=True); boot.write_text("testboot")
    processes = {
        200: ds.Process(200, 1, 0, 900, "/usr/sbin/dropbear"),
        201: ds.Process(201, 200, 0, 1000, "/usr/sbin/dropbear"),
        202: ds.Process(202, 200, 1001, 999, "/usr/sbin/dropbear"),
        203: ds.Process(203, 200, 0, 1002, "/usr/sbin/dropbear"),
        204: ds.Process(204, 1, 1001, 1003, "/usr/sbin/dropbear"),
    }
    monkeypatch.setattr(ds, "PROC", tmp_path)
    monkeypatch.setattr(ds, "managed_uids", lambda _: {1001: "basit"})
    monkeypatch.setattr(ds, "process", processes.get)
    monkeypatch.setattr(ds, "journal_auth", lambda: [auth()])
    monkeypatch.setattr(ds.os, "sysconf", lambda _: 100)
    monkeypatch.setattr(ds, "_AUTH_CACHE", {})
    result = ds.snapshot(tmp_path)
    assert [p.pid for p in result["sessions"][1001]] == [202, 201]
    assert result["unattributed_root_processes"] == 1
    # Once authenticated, the in-memory match survives journal rotation.
    monkeypatch.setattr(ds, "journal_auth", lambda: [])
    assert [p.pid for p in ds.snapshot(tmp_path)["sessions"][1001]] == [202, 201]
    # Reused PID starts fresh and cannot inherit that cache entry.
    processes[201] = ds.Process(201, 200, 0, 2000, "/usr/sbin/dropbear")
    assert [p.pid for p in ds.snapshot(tmp_path)["sessions"][1001]] == [202]


def test_only_registered_tunnel_users_can_be_managed(tmp_path, monkeypatch):
    (tmp_path / "invalid.json").write_text("[]")
    for name in ("basit", "admin", "system", "mismatch"):
        (tmp_path / (name + ".json")).write_text('{"username":"' + ("basit" if name == "mismatch" else name) + '"}')
    monkeypatch.setattr(ds.pwd, "getpwnam", lambda name: SimpleNamespace(
        pw_uid=500 if name == "system" else 1001,
        pw_shell="/bin/bash" if name == "admin" else "/usr/local/lib/abdulbasit/tunnel-shell"))
    assert ds.managed_uids(tmp_path) == {1001: "basit"}


def test_termination_pins_identity_and_refuses_reused_pid(monkeypatch):
    old = ds.Process(201, 200, 0, 1000, "/usr/sbin/dropbear")
    monkeypatch.setattr(ds, "snapshot", lambda _: {"sessions": {1001: [old]}})
    monkeypatch.setattr(ds, "process", lambda _: ds.Process(201, 200, 0, 2000, old.executable))
    monkeypatch.setattr(ds.os, "pidfd_open", lambda _: 99)
    closed = []; sent = []
    monkeypatch.setattr(ds.os, "close", closed.append)
    monkeypatch.setattr(ds.signal, "pidfd_send_signal", lambda *args: sent.append(args))
    ds.terminate([201], 1001)
    assert closed == [99] and not sent


def test_termination_signals_only_pinned_authenticated_process(monkeypatch):
    item = ds.Process(201, 200, 0, 1000, "/usr/sbin/dropbear")
    monkeypatch.setattr(ds, "snapshot", lambda _: {"sessions": {1001: [item]}})
    monkeypatch.setattr(ds, "process", lambda _: item)
    monkeypatch.setattr(ds.os, "pidfd_open", lambda _: 99)
    monkeypatch.setattr(ds.time, "sleep", lambda _: None)
    closed = []; sent = []
    monkeypatch.setattr(ds.os, "close", closed.append)
    monkeypatch.setattr(ds.signal, "pidfd_send_signal", lambda *args: sent.append(args))
    ds.terminate([201, 999], 1001)
    assert sent == [(99, ds.signal.SIGTERM), (99, ds.signal.SIGKILL)]
    assert closed == [99]


def test_process_checks_executable_and_kernel_uid_start_time(tmp_path, monkeypatch):
    root = tmp_path / "201"; root.mkdir()
    executable = ds.Path("/usr/bin/true").resolve()
    (root / "exe").symlink_to(executable)
    fields = ["S", "200"] + ["0"] * 17 + ["12345"]
    (root / "stat").write_text("201 (dropbear fake name) " + " ".join(fields))
    (root / "status").write_text("Name:\tanything\nUid:\t0\t1001\t1001\t1001\n")
    monkeypatch.setattr(ds, "PROC", tmp_path)
    monkeypatch.setattr(ds, "EXECUTABLES", (executable,))
    assert ds.process(201) == ds.Process(201, 200, 1001, 12345, str(executable))
    monkeypatch.setattr(ds, "EXECUTABLES", (ds.Path("/usr/sbin/dropbear"),))
    assert ds.process(201) is None


def test_enforcer_keeps_oldest_connection_and_terminates_disabled(tmp_path, monkeypatch):
    path = tmp_path / "basit.json"
    path.write_text('{"username":"basit","expiry":"2099-01-01","max_sessions":1}')
    monkeypatch.setattr(enforcer, "USERS_DIR", tmp_path)
    monkeypatch.setattr(enforcer, "dropbear_pids_by_uid", lambda: {1001: [900, 500]})
    monkeypatch.setattr(enforcer.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1001))
    killed = []
    monkeypatch.setattr(enforcer, "terminate", lambda pids, uid: killed.append((pids, uid)))
    enforcer.enforce_once()
    assert killed == [([500], 1001)]
    path.write_text('{"username":"basit","expiry":"2099-01-01","enabled":false}')
    enforcer.enforce_once()
    assert killed[-1] == ([900, 500], 1001)
