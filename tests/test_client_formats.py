import json
import os
from pathlib import Path
import subprocess

import pytest

from client_formats import clash_config, singbox_config
import xray_manager as xray


def test_client_exports_have_matching_credentials_tls_and_loopback_listener(manager):
    manager.configure({"enabled": True})
    manager.create({"name": "clients", "days": 7})
    row = xray.accounts()[0]
    box = singbox_config(row, "vpn.example.com")
    clash = clash_config(row, "vpn.example.com")
    assert box["inbounds"][0]["listen"] == "127.0.0.1" and clash["allow-lan"] is False
    assert len(box["outbounds"]) == 4 and len(clash["proxies"]) == 3
    for proxy in box["outbounds"][1:]:
        assert proxy["tls"] == {"enabled": True, "server_name": "vpn.example.com", "insecure": False, "alpn": ["http/1.1"]}
        assert proxy["transport"]["path"] == "/" + proxy["type"]
        assert proxy.get("uuid", row["uuid"]) == row["uuid"]
    for proxy in clash["proxies"]:
        assert proxy["skip-cert-verify"] is False and proxy["network"] == "ws"
        if proxy["type"] == "trojan": assert proxy["password"] == row["trojan_password"]


@pytest.mark.parametrize("kind,environment", [("singbox", "SINGBOX_TEST_BINARY"), ("clash", "MIHOMO_TEST_BINARY")])
def test_export_accepted_by_native_client_binary(manager, tmp_path, kind, environment):
    binary = os.environ.get(environment)
    if not binary: pytest.skip(f"{environment} is not set")
    manager.configure({"enabled": True}); manager.create({"name": "native", "days": 7})
    row = xray.accounts()[0]
    config = (singbox_config if kind == "singbox" else clash_config)(row, "vpn.example.com")
    path = tmp_path / ("client.json" if kind == "singbox" else "client.yaml")
    path.write_text(json.dumps(config))
    command = [binary, "check", "-c", str(path)] if kind == "singbox" else [binary, "-t", "-f", str(path), "-d", str(tmp_path)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
