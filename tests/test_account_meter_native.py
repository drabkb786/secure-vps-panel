"""Real byte-count acceptance. SSH provisioning is opt-in, disposable root only."""
import json
import os
import socket
import socketserver
import struct
import subprocess
import threading
import time
import uuid
from datetime import date, timedelta
from pathlib import Path

import pytest
import ssh_meter
import ssh_identity
import dropbear_sessions
import session_enforcer
import traffic
import xray_manager
from account_policy import ssh_id
from common import atomic_write_json
import test_xray_core as core_tools

METER_CORE = os.environ.get("XRAY_METER_TEST_BINARY", "")
METER_DROPBEAR = os.environ.get("METER_DROPBEAR_TEST_BINARY", "")


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except OSError:
            pass


def echo_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.mark.skipif(not METER_CORE, reason="XRAY_METER_TEST_BINARY is not set")
def test_real_xray_per_ip_bytes_and_account_scoped_block(tmp_path, monkeypatch):
    monkeypatch.setattr(core_tools, "CORE", METER_CORE)
    echo = echo_server()
    first, other = core_tools.record(), core_tools.record()
    first["blocked_ips"] = ["127.0.0.4"]
    config = xray_manager.server_config({"dns": xray_manager.DEFAULT_DNS}, [first, other])
    inbound = config["inbounds"][0]
    inbound.update(port=core_tools.free_port(), streamSettings={"network": "raw", "security": "none"})
    config["inbounds"] = [inbound]
    api = tmp_path / "meter.sock"; config["api"]["listen"] = str(api)
    config["routing"]["rules"] = config["routing"]["rules"][:1]
    config["outbounds"][0]["settings"]["finalRules"] = [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": str(echo.server_address[1])}]
    path = tmp_path / "core.json"; path.write_text(json.dumps(config))
    process, log = core_tools.start_core(path)
    def transfer(account, source, size):
        peer = socket.socket(); peer.settimeout(5); peer.bind((source, 0)); peer.connect(("127.0.0.1", inbound["port"]))
        payload = bytes([size % 251]) * size
        header = b"\x00" + uuid.UUID(account["uuid"]).bytes + b"\x00\x01" + struct.pack("!H", echo.server_address[1]) + b"\x01\x7f\x00\x00\x01"
        with peer:
            peer.sendall(header + payload)
            assert core_tools.read_exact(peer, 2) == b"\x00\x00"
            assert core_tools.read_exact(peer, len(payload)) == payload
    try:
        core_tools.wait_port(inbound["port"], process)
        transfer(first, "127.0.0.2", 65536)
        transfer(first, "127.0.0.3", 131072)
        with pytest.raises((AssertionError, OSError)):
            transfer(first, "127.0.0.4", 100)
        transfer(other, "127.0.0.4", 8192)  # Same address, another account is allowed.
        time.sleep(.1)
        response = subprocess.run([METER_CORE, "api", "statsquery", "--server=unix://" + str(api), "-pattern=user>>>"], capture_output=True, text=True, check=True, timeout=5)
        counters = {s["name"]: int(s.get("value", 0)) for s in json.loads(response.stdout)["stat"]}
        email = f"{first['uuid']}-vless@noway.local"
        for address, size in (("127.0.0.2", 65536), ("127.0.0.3", 131072)):
            for direction in ("uplink", "downlink"):
                assert counters[f"user>>>{email}>>>ip>>>{address}>>>traffic>>>{direction}"] == size
        assert counters["user>>>noway-meter>>>version"] == 1
    finally:
        process.terminate(); process.wait(timeout=5); log.close(); echo.shutdown(); echo.server_close()


@pytest.mark.skipif(not (METER_DROPBEAR and os.environ.get("NOWAY_METER_NATIVE") == "1"), reason="Opt-in disposable-root SSH acceptance is not enabled")
def test_real_dropbear_authenticated_payload_and_ip_policy(tmp_path, monkeypatch):
    assert os.geteuid() == 0
    # This test creates one disposable account and one temporary Unix listener;
    # it must never run against the owner's VPS or beside its live meter.
    if ssh_meter.SOCKET.exists():
        pytest.skip("An SSH meter socket already exists")
    import paramiko
    name = "nwmt_" + str(os.getpid())
    shell = Path("/usr/local/lib/abdulbasit/tunnel-shell")
    old_shell = shell.read_bytes() if shell.exists() else None
    old_shell_mode = shell.stat().st_mode & 0o777 if shell.exists() else None
    shells = Path("/etc/shells"); old_shells = shells.read_bytes()
    password = uuid.uuid4().hex
    directory = tmp_path / "users"; directory.mkdir()
    monkeypatch.setattr(ssh_meter, "USERS_DIR", directory)
    monkeypatch.setattr(ssh_meter, "STATE_FILE", tmp_path / "ssh-ledger.json")
    monkeypatch.setattr(dropbear_sessions, "EXECUTABLES", (Path(METER_DROPBEAR),))
    ssh_meter.SOCKET.parent.mkdir(mode=0o711, parents=True, exist_ok=True)
    echo = echo_server(); process = server = None
    created = False
    try:
        shell.parent.mkdir(parents=True, exist_ok=True); shell.write_text("#!/bin/sh\nexit 1\n"); shell.chmod(0o755)
        if str(shell) not in old_shells.decode().splitlines(): shells.write_bytes(old_shells + (str(shell) + "\n").encode())
        subprocess.run(["useradd", "--no-create-home", "--shell", str(shell), name], check=True, capture_output=True)
        created = True
        subprocess.run(["chpasswd"], input=name + ":" + password + "\n", text=True, check=True, capture_output=True)
        row = {"username": name, "created_at": "native-acceptance", "expiry": (date.today() + timedelta(days=1)).isoformat(), "max_ips": 2, "enabled": True}
        atomic_write_json(directory / (name + ".json"), row)
        port = core_tools.free_port(); monkeypatch.setattr(ssh_identity, "SSH_PORTS", {port})
        key = tmp_path / "hostkey"
        subprocess.run([os.environ["METER_DROPBEARKEY_TEST_BINARY"], "-t", "ed25519", "-f", str(key)], check=True, capture_output=True)
        server = ssh_meter.Server(str(ssh_meter.SOCKET)); ssh_meter.SOCKET.chmod(0o666)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        process = subprocess.Popen([METER_DROPBEAR, "-F", "-E", "-w", "-k", "-p", "0.0.0.0:" + str(port), "-P", str(tmp_path / "pid"), "-r", str(key)], stdout=subprocess.DEVNULL, stderr=(tmp_path / "dropbear.log").open("w"))
        core_tools.wait_port(port, process)
        address = socket.gethostbyname(socket.gethostname())
        if address.startswith("127."): pytest.skip("No non-loopback local IP for direct-source identity acceptance")
        def connect():
            peer = socket.create_connection((address, port), timeout=5)
            transport = paramiko.Transport(peer); transport.connect(username=name, password=password)
            return transport
        connection = connect()
        channel = connection.open_channel("direct-tcpip", echo.server_address, ("127.0.0.1", 12345), timeout=5)
        payload = b"native-meter" * 65536
        sender = threading.Thread(target=channel.sendall, args=(payload,)); sender.start()
        assert core_tools.read_exact(channel, len(payload)) == payload
        sender.join(5); assert not sender.is_alive()
        channel.close(); connection.close()
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            try:
                totals = ssh_meter.state()["accounts"][ssh_id(row)]
                if totals.get("download_bytes") == len(payload): break
            except KeyError:
                pass
            time.sleep(.1)
        assert (totals["upload_bytes"], totals["download_bytes"]) == (len(payload), len(payload))
        assert totals["ips"][address]["upload_bytes"] == len(payload)
        row["blocked_ips"] = [address]; atomic_write_json(directory / (name + ".json"), row)
        denied = None
        try:
            try:
                denied = connect()
                forwarded = denied.open_channel("direct-tcpip", echo.server_address, ("127.0.0.1", 1), timeout=3)
                forwarded.sendall(b"blocked")
                assert forwarded.recv(7) != b"blocked", "Blocked account IP forwarded application data"
            except (paramiko.SSHException, EOFError, OSError):
                pass
        finally:
            if denied:
                denied.close()
        row["blocked_ips"] = []
        atomic_write_json(directory / (name + ".json"), row)
        # Keep a real SSH connection open after crossing the smallest supported
        # quota, then exercise the production PID-safe enforcer and live reset.
        limited = connect()
        try:
            channel = limited.open_channel("direct-tcpip", echo.server_address, ("127.0.0.1", 12346), timeout=5)
            large = b"q" * (60 * 1024 * 1024)
            sender = threading.Thread(target=channel.sendall, args=(large,)); sender.start()
            remaining = len(large)
            while remaining:
                chunk = channel.recv(min(65536, remaining))
                assert chunk and chunk == b"q" * len(chunk)
                remaining -= len(chunk)
            sender.join(10); assert not sender.is_alive(); channel.close()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                totals = ssh_meter.state()["accounts"][ssh_id(row)]
                if totals.get("download_bytes") == len(payload) + len(large): break
                time.sleep(.1)
            assert totals["upload_bytes"] == totals["download_bytes"] == len(payload) + len(large)
            row.update(quota_gb=.1, quota_unit="GB", quota_enforced=True)
            atomic_write_json(directory / (name + ".json"), row)
            monkeypatch.setattr(session_enforcer, "USERS_DIR", directory)
            monkeypatch.setattr(ssh_meter, "available", lambda: True)  # Test binary is already verified by the live collector.
            session_enforcer.enforce_once()
            deadline = time.monotonic() + 4
            while limited.is_active() and time.monotonic() < deadline: time.sleep(.05)
            assert not limited.is_active(), "Exhausted real SSH session was not terminated"
        finally:
            limited.close()
        ssh_meter.reset(name)
        assert ssh_meter.state()["accounts"][ssh_id(row)]["upload_bytes"] == 0
        after_reset = connect()
        try:
            channel = after_reset.open_channel("direct-tcpip", echo.server_address, ("127.0.0.1", 12347), timeout=5)
            channel.sendall(b"renewed-allowance")
            assert core_tools.read_exact(channel, 17) == b"renewed-allowance"
            channel.close()
        finally:
            after_reset.close()
    finally:
        if process:
            process.terminate(); process.wait(timeout=5)
        if server:
            server.shutdown(); server.server_close(); ssh_meter.SOCKET.unlink(missing_ok=True)
        echo.shutdown(); echo.server_close()
        if created: subprocess.run(["userdel", name], capture_output=True, check=False)
        shells.write_bytes(old_shells)
        if old_shell is None: shell.unlink(missing_ok=True)
        else: shell.write_bytes(old_shell); shell.chmod(old_shell_mode)
