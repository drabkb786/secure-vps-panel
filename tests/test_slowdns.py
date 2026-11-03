import json
import os
import socket
import socketserver
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

import slowdns
from common import ValidationError


@pytest.fixture
def dns_manager(tmp_path, monkeypatch):
    for key, name in {"SETTINGS_FILE": "settings.json", "CONFIG_DIR": "runtime", "RUNTIME_FILE": "runtime/config.json", "PRIVATE_KEY": "runtime/server.key", "PUBLIC_KEY": "runtime/server.pub", "BINARY": "dnstt-server"}.items():
        monkeypatch.setattr(slowdns, key, tmp_path / name)
    return slowdns.Manager(lambda *args, **kw: SimpleNamespace(stdout=""))


def test_missing_core_and_occupied_port_leave_settings_unchanged(dns_manager):
    params = {"enabled": True, "zone": "tunnel.example.com", "ns_host": "ns1.example.com"}
    with pytest.raises(ValidationError, match="official dnstt"): dns_manager.configure(params)
    assert not slowdns.SETTINGS_FILE.exists()
    slowdns.BINARY.touch()
    dns_manager.run = lambda *args, **kw: SimpleNamespace(stdout='UNCONN 0 0 127.0.0.53:53 systemd-resolved')
    with pytest.raises(ValidationError, match="occupied"): dns_manager.configure(params)
    assert not slowdns.SETTINGS_FILE.exists()


def test_delegation_cycle_and_command_injection_are_rejected(dns_manager):
    with pytest.raises(ValidationError): dns_manager.configure({"enabled": True, "zone": "tunnel.example.com", "ns_host": "ns1.tunnel.example.com"})
    with pytest.raises(ValidationError): dns_manager.configure({"enabled": True, "zone": "example.com;id", "ns_host": "ns1.example.com"})


def test_failed_dns_restart_restores_previous_runtime_and_preserves_keys(dns_manager):
    slowdns.BINARY.touch(); slowdns.CONFIG_DIR.mkdir()
    slowdns.PRIVATE_KEY.write_text("private-key-fixture"); slowdns.PUBLIC_KEY.write_text("a" * 64)
    previous = {"enabled": False, "zone": "old.example.com", "ns_host": "ns1.example.com", "port": 53}
    slowdns.RUNTIME_FILE.write_text(json.dumps(previous))
    def run(args, **kw):
        if "restart" in args: raise RuntimeError("failed to start")
        return SimpleNamespace(stdout="")
    dns_manager.run = run
    with pytest.raises(RuntimeError): dns_manager.configure({"enabled": True, "zone": "new.example.com", "ns_host": "ns1.example.com"})
    assert json.loads(slowdns.RUNTIME_FILE.read_text()) == previous
    assert slowdns.PRIVATE_KEY.read_text() == "private-key-fixture"
    assert not slowdns.SETTINGS_FILE.exists()


@pytest.mark.parametrize("opens", [True, False])
def test_slow_listener_keeps_config_until_ready_or_timeout(dns_manager, monkeypatch, opens):
    slowdns.BINARY.touch(); slowdns.CONFIG_DIR.mkdir()
    slowdns.PRIVATE_KEY.write_text("private-key-fixture"); slowdns.PUBLIC_KEY.write_text("a" * 64)
    now, probes, calls = [0.0], [0], []
    monkeypatch.setattr(slowdns.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(slowdns.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay))
    def run(args, **kw):
        calls.append(args)
        if "-Hlunp" in args and slowdns.RUNTIME_FILE.exists():
            config = json.loads(slowdns.RUNTIME_FILE.read_text())
            assert config["enabled"] and config["zone"] == "tunnel.example.com"
            probes[0] += 1
            return SimpleNamespace(stdout="dnstt-server" if opens and probes[0] >= 3 else "")
        return SimpleNamespace(stdout="")
    dns_manager.run = run
    params = {"enabled": True, "zone": "tunnel.example.com", "ns_host": "ns1.example.com"}
    if opens:
        assert dns_manager.configure(params)["enabled"]
        assert probes[0] == 3 and now[0] > 0
        assert json.loads(slowdns.SETTINGS_FILE.read_text())["enabled"]
        assert any("enable" in call for call in calls)
    else:
        with pytest.raises(RuntimeError, match="within 10 seconds"):
            dns_manager.configure(params)
        assert now[0] >= 10 and probes[0] > 1
        assert not slowdns.RUNTIME_FILE.exists() and not slowdns.SETTINGS_FILE.exists()
        assert not any("enable" in call for call in calls)
        assert any("disable" in call for call in calls)
    assert slowdns.PRIVATE_KEY.read_text() == "private-key-fixture"


@pytest.mark.skipif(not os.environ.get("DNSTT_TEST_SERVER") or not os.environ.get("DNSTT_TEST_CLIENT"), reason="Supply official dnstt server/client binaries")
def test_real_official_dnstt_udp_tunnel_forwards_bidirectional_tcp(tmp_path):
    server, client = os.environ["DNSTT_TEST_SERVER"], os.environ["DNSTT_TEST_CLIENT"]
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            while data := self.request.recv(65536): self.request.sendall(data)
    echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    echo.daemon_threads = True
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    key, public = tmp_path / "server.key", tmp_path / "server.pub"
    subprocess.run([server, "-gen-key", "-privkey-file", str(key), "-pubkey-file", str(public)], check=True, capture_output=True, timeout=10)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0)); udp_port = sock.getsockname()[1]
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); local_port = sock.getsockname()[1]
    log = (tmp_path / "dnstt.log").open("w+")
    processes = []
    try:
        processes.append(subprocess.Popen([server, "-udp", f"127.0.0.1:{udp_port}", "-privkey-file", str(key), "tunnel.example.com", f"127.0.0.1:{echo.server_address[1]}"], stdout=log, stderr=log))
        processes.append(subprocess.Popen([client, "-udp", f"127.0.0.1:{udp_port}", "-pubkey-file", str(public), "tunnel.example.com", f"127.0.0.1:{local_port}"], stdout=log, stderr=log))
        for _ in range(120):
            try: connection = socket.create_connection(("127.0.0.1", local_port), timeout=0.1); break
            except OSError: time.sleep(0.025)
        else: raise AssertionError("dnstt client did not open")
        with connection:
            connection.settimeout(20)
            payload = b"NOWAY real DNS tunnel round trip\n" * 200
            connection.sendall(payload); answer = b""
            while len(answer) < len(payload):
                part = connection.recv(65536)
                if not part: break
                answer += part
            assert answer == payload
    finally:
        for process in reversed(processes): process.terminate(); process.wait(timeout=5)
        log.close(); echo.shutdown(); echo.server_close()
