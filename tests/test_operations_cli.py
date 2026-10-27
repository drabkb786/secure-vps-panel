import json
from types import SimpleNamespace

import pytest

import panelctl
import paneld
import session_enforcer
from common import ValidationError


@pytest.mark.parametrize("arguments,command,expected", [
    (["xray-trial", "basit", "--quota", "2"], "xray_create", {"name": "basit", "days": 1, "trial": True, "quota_gb": "2"}),
    (["xray-lock", "basit"], "xray_update", {"name": "basit", "action": "toggle", "enabled": False}),
    (["xray-reset-usage", "basit"], "xray_update", {"name": "basit", "action": "reset_usage"}),
    (["lock-user", "basit"], "set_user_lock", {"username": "basit", "enabled": False}),
    (["doctor", "--repair"], "doctor", {"repair": True}),
    (["slowdns-enable", "--zone", "tunnel.example.com", "--ns-host", "ns1.example.com"], "slowdns_configure", {"enabled": True, "zone": "tunnel.example.com", "ns_host": "ns1.example.com", "port": 53}),
])
def test_new_cli_controls_dispatch_exact_validated_parameters(monkeypatch, arguments, command, expected):
    calls = []
    monkeypatch.setattr("sys.argv", ["panelctl", *arguments])
    monkeypatch.setattr(panelctl, "request", lambda command_name, **params: calls.append((command_name, params)) or {"done": True})
    assert panelctl.main() == 0
    assert calls == [(command, expected)]


def test_ssh_lock_expires_only_managed_user_and_terminates_verified_sessions(tmp_path, monkeypatch):
    row = {"username": "basit", "expiry": "2099-01-01", "enabled": True}
    path = tmp_path / "basit.json"
    monkeypatch.setattr(paneld, "managed_user", lambda _: dict(row))
    monkeypatch.setattr(paneld, "user_file", lambda _: path)
    monkeypatch.setattr(paneld, "binary", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr(paneld.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=12345))
    monkeypatch.setattr(paneld, "session_processes", lambda: {"basit": [54321]})
    calls = []; killed = []
    monkeypatch.setattr(paneld, "run", lambda args, **kw: calls.append(args))
    monkeypatch.setattr(session_enforcer, "terminate", lambda pids, uid: killed.append((pids, uid)))
    paneld.set_user_lock({"username": "basit", "enabled": False})
    assert calls == [["/usr/sbin/usermod", "--lock", "--expiredate", "1970-01-02", "basit"]]
    assert json.loads(path.read_text())["enabled"] is False
    assert killed == [([54321], 12345)]


def test_ssh_unlock_refuses_expired_user_without_calling_os(monkeypatch):
    monkeypatch.setattr(paneld, "managed_user", lambda _: {"expiry": "2000-01-01"})
    monkeypatch.setattr(paneld, "run", lambda *a, **kw: pytest.fail("Expired account unlocked"))
    with pytest.raises(ValidationError): paneld.set_user_lock({"username": "basit", "enabled": True})


def test_new_browser_commands_still_require_current_admin_revision(monkeypatch):
    monkeypatch.setattr(paneld.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1234))
    monkeypatch.setattr(paneld.web_auth, "revision", lambda: "current")
    for name in ("banner_set", "doctor", "slowdns_configure", "traffic_sample", "set_user_lock"):
        with pytest.raises(ValidationError): paneld.authorize_command(1234, name, {})
        paneld.authorize_command(1234, name, {"_web_revision": "current"})
