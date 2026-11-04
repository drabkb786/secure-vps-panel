import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
import xray_manager as xray
import traffic
import gateway_identity
import ssh_identity
import ssh_backend
from reality_transport import vless_encryption
from types import SimpleNamespace


@pytest.fixture(autouse=True)
def private_gateway(tmp_path, monkeypatch):
    path = tmp_path / "gateway-header"
    path.write_text("X-Noway-Gateway-" + "a" * 64)
    monkeypatch.setattr(gateway_identity, "CONFIG_FILE", path)
    monkeypatch.setattr(ssh_identity, "PEER_DIR", tmp_path / "ws-peers")
    monkeypatch.setattr(ssh_backend, 'GATEWAY_FILE', tmp_path / 'gateway-backend')
    secret = tmp_path / 'haproxy-verify'; secret.write_text('c' * 64)
    monkeypatch.setattr(ssh_backend, 'HAPROXY_SECRET_FILE', secret)


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr(vless_encryption, 'KEY_FILE', tmp_path / 'vless-keys.json')
    monkeypatch.setattr(traffic, "STATE_FILE", tmp_path / "traffic.json")
    for attr, value in {"SETTINGS_FILE": tmp_path / "network.json", "BACKUP_DIR": tmp_path / "backups", "ACCOUNTS_FILE": tmp_path / "accounts.json",
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
        if args[-1] == 'vlessenc':
            return SimpleNamespace(stdout='"decryption": "mlkem768x25519plus.native.600s.' + 'a' * 43 + '"\n"encryption": "mlkem768x25519plus.native.0rtt.' + 'b' * 43 + '"\n')
        if "--property=InvocationID" in args:
            return SimpleNamespace(stdout="1" * 32)
    obj = xray.Manager(run, health_probe=lambda: True)
    obj.calls = calls
    return obj
