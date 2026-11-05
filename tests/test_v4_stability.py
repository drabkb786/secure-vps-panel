import json
import socket
import subprocess
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import bunny_manager
import cdn_manager
import common
import openssh_sessions as sessions
import paneld
import reality_transport
import ssh_backend
import ssh_profiles
import xray_manager as xray
import xray_runtime
from test_slowdns import dns_manager


def test_short_password_is_scoped_to_managed_ssh():
    for password in ("bas", "basit", "baloch"):
        assert common.validate_ssh_password(password) == password
        with pytest.raises(common.ValidationError):
            common.validate_password(password)
    for password in ("ab", "abc\n", "ab\0c", "ab\rc", "abc\x1b"):
        with pytest.raises(common.ValidationError):
            common.validate_ssh_password(password)


def test_official_x25519_new_and_legacy_labels(tmp_path, monkeypatch):
    monkeypatch.setattr(reality_transport, "KEY_FILE", tmp_path / "reality.json")
    for public_label in ("Password (PublicKey)", "Password", "PublicKey", "Public key"):
        reality_transport.KEY_FILE.unlink(missing_ok=True)
        run = lambda *a, **kw: SimpleNamespace(stdout="PrivateKey: " + "A" * 43 + "\n" + public_label + ": " + "B" * 43 + "\nHash32: " + "C" * 43 + "\n")
        reality_transport.initialize(run, "/fixture/xray")
        assert reality_transport.keys()["public"] == "B" * 43
        assert reality_transport.KEY_FILE.stat().st_mode & 0o777 == 0o600


def test_openssh_ignores_admin_cgroup_and_reused_pid(tmp_path, monkeypatch):
    process = tmp_path / "201"; process.mkdir()
    executable = Path("/usr/bin/true").resolve()
    (process / "exe").symlink_to(executable)
    (process / "stat").write_text("201 (sshd: misleading title) " + " ".join(["S", "200"] + ["0"] * 17 + ["12345"]))
    (process / "status").write_text("Uid:\t1001\t1001\t1001\t1001\n")
    (process / "cgroup").write_text("0::/system.slice/unrelated.service\n")
    monkeypatch.setattr(sessions, "PROC", tmp_path)
    monkeypatch.setattr(sessions, "EXECUTABLES", (executable,))
    assert sessions.process(201) is None
    (process / "cgroup").write_text("0::/system.slice/abdulbasit-sshd.service\n")
    item = sessions.process(201)
    assert item.uid == 1001 and item.start_ticks == 12345
    monkeypatch.setattr(sessions, "snapshot", lambda _: {"sessions": {1001: [item]}})
    monkeypatch.setattr(sessions.os, "pidfd_open", lambda _: 99)
    monkeypatch.setattr(sessions, "process", lambda _: None)
    closed = []; sent = []
    monkeypatch.setattr(sessions.os, "close", closed.append)
    monkeypatch.setattr(sessions.signal, "pidfd_send_signal", lambda *a: sent.append(a))
    sessions.terminate([201], 1001)
    assert closed == [99] and not sent


def test_openssh_collapses_privsep_processes(tmp_path, monkeypatch):
    rows = {200: sessions.Process(200, 1, 0, 10, "sshd"),
            201: sessions.Process(201, 200, 0, 11, "sshd"),
            202: sessions.Process(202, 201, 1001, 12, "sshd"),
            203: sessions.Process(203, 202, 1001, 13, "sshd"),
            204: sessions.Process(204, 200, 110, 14, "sshd")}
    for pid in rows: (tmp_path / str(pid)).mkdir()
    monkeypatch.setattr(sessions, "PROC", tmp_path)
    monkeypatch.setattr(sessions, "process", rows.get)
    monkeypatch.setattr(sessions, "managed_uids", lambda _: {1001: "basit"})
    assert sessions.snapshot()["sessions"] == {1001: [rows[202]]}


def test_pam_session_scope_requires_trusted_managed_ancestor(tmp_path, monkeypatch):
    executable = Path("/usr/bin/true").resolve()
    monkeypatch.setattr(sessions, "PROC", tmp_path)
    monkeypatch.setattr(sessions, "EXECUTABLES", (executable,))
    for pid, parent, uid, group in ((200, 1, 0, "system.slice/abdulbasit-sshd.service"),
                                    (201, 200, 0, "user.slice/session-1.scope"),
                                    (202, 201, 1001, "user.slice/session-1.scope"),
                                    (300, 1, 0, "system.slice/ssh.service"),
                                    (301, 300, 1003, "user.slice/session-2.scope")):
        root = tmp_path / str(pid); root.mkdir()
        (root / "exe").symlink_to(executable)
        (root / "stat").write_text(f"{pid} (sshd) " + " ".join(["S", str(parent)] + ["0"] * 17 + [str(pid)]))
        (root / "status").write_text(f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        (root / "cgroup").write_text("0::/" + group + "\n")
    assert sessions.process(202).uid == 1001
    monkeypatch.setattr(sessions, "managed_uids", lambda _: {1001: "basit"})
    observed = sessions.snapshot()["sessions"]
    assert [p.pid for p in observed[1001]] == [202]
    assert 1003 not in observed, "An ordinary admin must never be attributed as a tunnel user"


def test_ssh_viewer_ip_uses_verified_listener_port_not_forwarded_destination(monkeypatch):
    import ssh_identity
    rows = {200: sessions.Process(200, 1, 0, 1, "sshd"), 201: sessions.Process(201, 200, 0, 2, "sshd"),
            202: sessions.Process(202, 201, 1001, 3, "sshd")}
    monkeypatch.setattr(sessions, "metadata", rows.get)
    monkeypatch.setattr(sessions, "process", rows.get)
    monkeypatch.setattr(ssh_identity, "socket_inodes", lambda pid: {99} if pid == 200 else {101, 102} if pid == 202 else set())
    monkeypatch.setattr(ssh_identity, "tcp_rows", lambda state: {99: ("0.0.0.0", 22022, "0.0.0.0", 0)})
    monkeypatch.setattr(ssh_identity, "tcp_sockets", lambda: {102: ("127.0.0.1", 41111, "127.0.0.1", 80),
                                                              101: ("192.0.2.5", 22022, "198.51.100.8", 51515)})
    assert ssh_identity.session_ips({1001: [202]}) == {202: "198.51.100.8"}


@pytest.mark.parametrize("command", ["packet_test", "slowdns_check", "diagnostics"])
def test_slow_observational_request_does_not_block_enforcement(monkeypatch, command):
    import threading
    entered, release = threading.Event(), threading.Event()
    def slow(_):
        entered.set(); release.wait(5)
        return {"done": True}
    monkeypatch.setattr(paneld, "HANDLERS", {command: slow, "xray_sync": lambda _: {"synced": True}})
    monkeypatch.setattr(paneld, "peer_uid", lambda _: 0)
    monkeypatch.setattr(paneld, "allowed_peer", lambda _: True)
    reader, reader_server = socket.socketpair(); writer, writer_server = socket.socketpair()
    threads = [threading.Thread(target=paneld.handle_connection, args=(peer,), daemon=True) for peer in (reader_server, writer_server)]
    try:
        threads[0].start(); reader.sendall((json.dumps({"command": command}) + "\n").encode())
        assert entered.wait(2)
        threads[1].start(); writer.sendall(b'{"command":"xray_sync"}\n'); writer.settimeout(2)
        assert json.loads(writer.recv(4096))["synced"] is True
    finally:
        release.set()
        for thread in threads:
            if thread.is_alive(): thread.join(3)
        reader.close(); writer.close()


def test_xray_live_addition_preserves_existing_core(manager):
    manager.configure({"enabled": True})
    calls = manager.calls
    original = manager.run
    def run(args, **kwargs):
        if "adu" in args:
            calls.append(args)
            data = json.loads(Path(args[-1]).read_text())
            number = sum(len(row["settings"]["clients"]) for row in data["inbounds"])
            return SimpleNamespace(stdout=f"Added {number} user(s) in total.\n")
        return original(args, **kwargs)
    manager.run = run
    calls.clear()
    manager.create({"name": "hotuser", "days": 10})
    assert any("adu" in call for call in calls)
    assert not any("restart" in call for call in calls)
    calls.clear()
    manager.update({"name": "hotuser", "action": "toggle", "enabled": False})
    assert any("restart" in call for call in calls), "Revocation must disconnect established sessions"


def test_xray_partial_api_success_reconciles_by_restart(manager):
    manager.configure({"enabled": True})
    original = manager.run
    def run(args, **kwargs):
        if "adu" in args:
            manager.calls.append(args)
            return SimpleNamespace(stdout="user failed\nAdded 1 user(s) in total.\n")
        return original(args, **kwargs)
    manager.run = run
    manager.calls.clear()
    manager.create({"name": "partial", "days": 10})
    assert any("restart" in call for call in manager.calls)


def test_runtime_delta_rejects_revocation_and_transport_changes():
    before = {"inbounds": [{"tag": "x", "settings": {"clients": [{"email": "a", "id": "one"}]}}]}
    assert xray_runtime.additions(before, {"inbounds": []}) is None
    after = json.loads(json.dumps(before)); after["inbounds"][0]["settings"]["clients"][0]["id"] = "two"
    assert xray_runtime.additions(before, after) is None


def test_bunny_secret_is_private_and_nginx_rolls_back(manager, tmp_path, monkeypatch):
    monkeypatch.setattr(bunny_manager, "CONFIG_FILE", tmp_path / "bunny.json")
    monkeypatch.setattr(bunny_manager, "DOMAIN_FILE", xray.DOMAIN_FILE)
    monkeypatch.setattr(cdn_manager, "CERT_ROOT", xray.CERT_ROOT)
    obj = bunny_manager.Manager(lambda _: None)
    obj.configure({"enabled": True, "endpoint": "cdn.example.com"})
    secret = bunny_manager.settings()["secret"]
    assert secret not in json.dumps(obj.status())
    assert secret in obj.setup()["files"]["bunny-setup.private.txt"]
    assert "%{User.IP}" in obj.setup()["files"]["bunny-setup.private.txt"]
    maps = bunny_manager.nginx_maps(bunny_manager.settings())
    assert "$http_x_noway_bunny_verify" in maps and "$http_x_noway_bunny_viewer_ip" in maps
    blocks = bunny_manager.nginx_locations(bunny_manager.settings(), True)
    assert "location ^~ /bunny/xhttp/" in blocks and "proxy_request_buffering off" in blocks
    assert "X-Noway-Bunny-Verify \"\"" in blocks
    previous = bunny_manager.CONFIG_FILE.read_bytes()
    obj.install_nginx = lambda _: (_ for _ in ()).throw(RuntimeError(secret))
    with pytest.raises(RuntimeError, match="rolled back") as error:
        obj.configure({"enabled": False})
    assert secret not in str(error.value) and bunny_manager.CONFIG_FILE.read_bytes() == previous


def test_ssh_export_uri_and_adapter_do_not_store_password(tmp_path, monkeypatch):
    domain = tmp_path / "domain"; domain.write_text("vpn.example.com")
    monkeypatch.setattr(ssh_profiles, "DOMAIN_FILE", domain)
    monkeypatch.setattr(ssh_profiles.slowdns, "settings", lambda: {"enabled": False})
    account = {"enabled": True, "expiry": (date.today() + timedelta(days=1)).isoformat(), "max_sessions": 2}
    data = ssh_profiles.export({"username": "basit", "password": "a@:"}, lambda _: account)
    assert data["links"]["ssh"] == "ssh://basit:a%40%3A@vpn.example.com:109"
    assert data["profile"]["requires_rfc6455"] is True
    assert "ssh-ws-client.py" in data["files"] and "ProxyCommand" in data["files"]["connect.txt"]
    assert "password" not in account
    clean = ssh_profiles.export({"username": "basit"}, lambda _: account)
    assert "password" not in clean["profile"]
    raw = json.loads(data["files"]["basit-raw-http.json"])
    raw_tls = json.loads(data["files"]["basit-raw-tls.json"])
    assert raw["port"] == 80 and raw["tls"] is False and raw["requires_rfc6455"] is False
    assert raw_tls["port"] == 443 and raw_tls["server_name"] == "vpn.example.com" and raw_tls["verify_certificate"] is True
    assert "Sec-WebSocket-Key" not in raw["payload"]
    assert "payload empty" in data["files"]["client-settings.txt"]
    assert "password" not in json.loads(clean["files"]["basit-raw-http.json"])
    assert "password" not in json.loads(clean["files"]["basit-raw-tls.json"])


def test_cdn_ssh_client_settings_do_not_offer_an_unframed_profile(tmp_path, monkeypatch):
    domain = tmp_path / "domain"; domain.write_text("vpn.example.com")
    monkeypatch.setattr(ssh_profiles, "DOMAIN_FILE", domain)
    monkeypatch.setattr(ssh_profiles.slowdns, "settings", lambda: {"enabled": False})
    monkeypatch.setattr(ssh_profiles.cdn_manager, "delivery", lambda *_: ("d123456.cloudfront.net", "/cloudfront"))
    account = {"enabled": True, "expiry": (date.today() + timedelta(days=1)).isoformat(), "max_sessions": 2}
    data = ssh_profiles.export({"username": "basit", "route": "cloudfront"}, lambda _: account)
    assert data["profile"]["path"] == "/cloudfront/cdn-cgi"
    assert not any("raw-http" in key or "raw-tls" in key for key in data["files"])
    assert "Requires RFC6455 binary" in data["files"]["client-settings.txt"]
    assert "SNI/Host: d123456.cloudfront.net" in data["files"]["client-settings.txt"]


def test_slowdns_queries_parent_referral(dns_manager, monkeypatch):
    import slowdns
    common.atomic_write_json(slowdns.SETTINGS_FILE, {"enabled": True, "zone": "tunnel.example.com", "ns_host": "ns1.example.com"})
    def run(args, **kwargs):
        if "@auth.example.com" in args:
            return SimpleNamespace(stdout="tunnel.example.com. 14400 IN NS ns1.example.com.\n")
        if "NS" in args:
            assert "tunnel.example.com" not in args, "Recursive child NS lookup is insufficient for DNSTT"
            return SimpleNamespace(stdout="auth.example.com.\n")
        return SimpleNamespace(stdout="203.0.113.5\n" if "A" in args else "")
    dns_manager.run = run
    result = dns_manager.check({})
    assert result["dns_ok"] and result["records"] == ["ns1.example.com"]
    assert result["authoritative_checks"][0]["ok"]
    for mtu in (511, 1401, "bad", 1232.5):
        with pytest.raises(common.ValidationError): slowdns.validate_mtu(mtu)
