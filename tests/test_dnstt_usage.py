from __future__ import annotations

import json
import sys
from contextlib import nullcontext
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import paneld  # noqa: E402
import usage_collector  # noqa: E402
from common import ValidationError  # noqa: E402
from dnstt_config import (  # noqa: E402
    build_config,
    client_profile,
    conflicting_udp53_lines,
    dns_records,
    host_port,
)
from protocols import enable_protocols, protocol_email  # noqa: E402


def dnstt_config() -> dict:
    return build_config(
        zone="t.example.com",
        nameserver="tns.example.com",
        listen_ip="203.0.113.10",
        public_key="a" * 64,
        private_key_file="/etc/abdulbasit/dnstt/server.key",
    )


def test_dnstt_dns_records_and_client_profile() -> None:
    config = dnstt_config()
    assert dns_records(config) == [
        {"type": "A", "name": "tns.example.com", "value": "203.0.113.10"},
        {"type": "NS", "name": "t.example.com", "value": "tns.example.com"},
    ]
    client = client_profile(config, "alice")
    assert client["ssh"] == {"host": "127.0.0.1", "port": 7000, "username": "alice"}
    assert "dnstt-client -udp tns.example.com:53" in client["client_examples"]["udp"]


def test_dnstt_rejects_nameserver_inside_tunnel_zone() -> None:
    with pytest.raises(ValidationError):
        build_config(
            zone="t.example.com",
            nameserver="ns.t.example.com",
            listen_ip="203.0.113.10",
            public_key="a" * 64,
            private_key_file="/tmp/key",
        )


def test_ipv6_host_port_is_bracketed() -> None:
    assert host_port("2001:db8::10", 53) == "[2001:db8::10]:53"
    assert host_port("127.0.0.1", 109) == "127.0.0.1:109"


def test_udp53_conflict_check_allows_local_resolver_on_another_ip() -> None:
    output = "UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((systemd-resolve))"
    assert conflicting_udp53_lines(output, "203.0.113.10") == []
    wildcard = "UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:((named))"
    assert conflicting_udp53_lines(wildcard, "203.0.113.10") == [wildcard]


def test_udp53_conflict_ignores_current_dnstt_listener() -> None:
    output = "UNCONN 0 0 203.0.113.10:53 0.0.0.0:* users:((dnstt-server,pid=10,fd=3))"
    assert conflicting_udp53_lines(output, "203.0.113.10") == []


def test_stats_parser_aggregates_protocol_counters() -> None:
    text = """
stat: < name: "user>>>alice@users.abdulbasit.invalid>>>traffic>>>uplink" value: 120 >
stat: < name: "user>>>alice@users.abdulbasit.invalid>>>traffic>>>downlink" value: 380 >
"""
    assert usage_collector.parse_stats(text) == {"alice@users.abdulbasit.invalid": 500}


def test_stats_parser_accepts_current_xray_json_output() -> None:
    text = json.dumps(
        {
            "stat": [
                {
                    "name": "user>>>alice@users.abdulbasit.invalid>>>traffic>>>uplink",
                    "value": 120,
                },
                {
                    "name": "user>>>alice@users.abdulbasit.invalid>>>traffic>>>downlink",
                    "value": 380,
                },
                {"name": "inbound>>>vless-in>>>traffic>>>uplink", "value": 999},
            ]
        }
    )
    assert usage_collector.parse_stats(text) == {"alice@users.abdulbasit.invalid": 500}


def test_stats_query_uses_real_filter_and_reset_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        usage_collector.shutil, "which", lambda _name: "/usr/local/bin/xray"
    )

    def fake_run(args, **_kwargs):
        commands.append(args)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "stat": [
                        {
                            "name": "user>>>alice@users.abdulbasit.invalid>>>traffic>>>uplink",
                            "value": 42,
                        }
                    ]
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(usage_collector.subprocess, "run", fake_run)
    assert usage_collector.query_stats() == {
        "alice@users.abdulbasit.invalid": 42
    }
    assert commands == [
        [
            "/usr/local/bin/xray",
            "api",
            "statsquery",
            "--server=127.0.0.1:21085",
            "-pattern",
            "user>>>",
            "-reset",
        ]
    ]


def test_usage_enforces_quota_and_requests_xray_sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    users_dir = tmp_path / "users"
    users_dir.mkdir()
    user = enable_protocols(
        {
            "username": "alice",
            "expiry": (date.today() + timedelta(days=30)).isoformat(),
            "quota_gb": 0.1,
            "usage_bytes": 99_999_900,
        },
        ["vless"],
    )
    (users_dir / "alice.json").write_text(json.dumps(user), encoding="utf-8")
    deployed: list[bool] = []
    monkeypatch.setattr(usage_collector, "USERS_DIR", users_dir)
    monkeypatch.setattr(usage_collector, "XRAY_SYNC_PENDING_FILE", tmp_path / "pending")
    monkeypatch.setattr(usage_collector, "state_lock", nullcontext)
    monkeypatch.setattr(usage_collector, "deploy_config", lambda: deployed.append(True))
    changed, access_changed = usage_collector.apply_usage(
        {protocol_email("alice"): 100}
    )
    stored = json.loads((users_dir / "alice.json").read_text(encoding="utf-8"))
    assert (changed, access_changed) == (1, True)
    assert stored["usage_bytes"] == 100_000_000
    assert stored["access_blocked_reason"] == "quota"
    assert deployed == [True]


def test_usage_transaction_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    users_dir = tmp_path / "users"
    users_dir.mkdir()
    user = enable_protocols(
        {
            "username": "alice",
            "expiry": (date.today() + timedelta(days=30)).isoformat(),
            "quota_gb": None,
            "usage_bytes": 10,
        },
        ["vless"],
    )
    (users_dir / "alice.json").write_text(json.dumps(user), encoding="utf-8")
    monkeypatch.setattr(usage_collector, "USERS_DIR", users_dir)
    monkeypatch.setattr(
        usage_collector, "XRAY_SYNC_PENDING_FILE", tmp_path / "sync.pending"
    )
    monkeypatch.setattr(usage_collector, "state_lock", nullcontext)
    totals = {protocol_email("alice"): 500}
    assert usage_collector.apply_usage(totals, transaction_id="a" * 32) == (1, False)
    assert usage_collector.apply_usage(totals, transaction_id="a" * 32) == (0, False)
    stored = json.loads((users_dir / "alice.json").read_text(encoding="utf-8"))
    assert stored["usage_bytes"] == 510


def test_usage_pending_journal_replays_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    users_dir = tmp_path / "users"
    users_dir.mkdir()
    user = enable_protocols(
        {
            "username": "alice",
            "expiry": (date.today() + timedelta(days=30)).isoformat(),
            "quota_gb": None,
            "usage_bytes": 0,
        },
        ["vless"],
    )
    (users_dir / "alice.json").write_text(json.dumps(user), encoding="utf-8")
    journal = tmp_path / "usage.pending.json"
    journal.write_text(
        json.dumps(
            {
                "id": "b" * 32,
                "totals": {protocol_email("alice"): 700},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(usage_collector, "USERS_DIR", users_dir)
    monkeypatch.setattr(
        usage_collector, "XRAY_SYNC_PENDING_FILE", tmp_path / "sync.pending"
    )
    monkeypatch.setattr(usage_collector, "XRAY_USAGE_PENDING_FILE", journal)
    monkeypatch.setattr(usage_collector, "state_lock", nullcontext)
    monkeypatch.setattr(usage_collector, "query_stats", lambda: {})
    result = usage_collector.collect_once()
    assert result["journal_replayed"] is True
    assert not journal.exists()
    stored = json.loads((users_dir / "alice.json").read_text(encoding="utf-8"))
    assert stored["usage_bytes"] == 700


def test_manual_usage_reset_discards_that_users_pending_counter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    users_dir = tmp_path / "users"
    users_dir.mkdir()
    user = enable_protocols(
        {
            "username": "alice",
            "expiry": (date.today() + timedelta(days=30)).isoformat(),
            "quota_gb": None,
            "usage_bytes": 900,
        },
        ["vless"],
    )
    (users_dir / "alice.json").write_text(json.dumps(user), encoding="utf-8")
    journal = tmp_path / "usage.pending.json"
    journal.write_text(
        json.dumps(
            {
                "id": "c" * 32,
                "totals": {
                    protocol_email("alice"): 100,
                    protocol_email("bob"): 200,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(paneld, "USERS_DIR", users_dir)
    monkeypatch.setattr(paneld, "XRAY_USAGE_PENDING_FILE", journal)
    monkeypatch.setattr(paneld, "state_lock", nullcontext)
    monkeypatch.setattr(paneld, "deploy_config", lambda *_args, **_kwargs: {})
    paneld.reset_usage({"username": "alice"})
    stored = json.loads((users_dir / "alice.json").read_text(encoding="utf-8"))
    pending = json.loads(journal.read_text(encoding="utf-8"))
    assert stored["usage_bytes"] == 0
    assert protocol_email("alice") not in pending["totals"]
    assert pending["totals"][protocol_email("bob")] == 200


def test_renew_does_not_unlock_a_disabled_ssh_protocol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    users_dir = tmp_path / "users"
    users_dir.mkdir()
    user = enable_protocols(
        {
            "username": "alice",
            "expiry": (date.today() - timedelta(days=1)).isoformat(),
            "quota_gb": None,
            "usage_bytes": 0,
        },
        ["ssh"],
    )
    user["protocols"]["ssh"]["enabled"] = False
    (users_dir / "alice.json").write_text(json.dumps(user), encoding="utf-8")
    commands: list[list[str]] = []
    monkeypatch.setattr(paneld, "USERS_DIR", users_dir)
    monkeypatch.setattr(paneld, "state_lock", nullcontext)
    monkeypatch.setattr(paneld, "binary", lambda name: name)
    monkeypatch.setattr(
        paneld,
        "run",
        lambda args, **_kwargs: (
            commands.append(args) or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    paneld.renew_user({"username": "alice", "days": 30})
    assert any(command[0] == "usermod" for command in commands)
    assert not any(command[0] == "passwd" for command in commands)


def test_dnstt_key_rotation_rolls_back_on_restart_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dnstt_dir = tmp_path / "dnstt"
    dnstt_dir.mkdir()
    private_key = dnstt_dir / "server.key"
    public_key = dnstt_dir / "server.pub"
    private_key.write_text("1" * 64 + "\n", encoding="ascii")
    public_key.write_text("a" * 64 + "\n", encoding="ascii")
    config_file = tmp_path / "dnstt.json"
    original_config = '{"enabled": true, "public_key": "' + "a" * 64 + '"}\n'
    config_file.write_text(original_config, encoding="utf-8")

    def fake_run(args, **_kwargs):
        if "-gen-key" in args:
            Path(args[args.index("-privkey-file") + 1]).write_text(
                "2" * 64 + "\n", encoding="ascii"
            )
            Path(args[args.index("-pubkey-file") + 1]).write_text(
                "b" * 64 + "\n", encoding="ascii"
            )
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[-2:] == ["restart", "abdulbasit-dnstt"]:
            raise RuntimeError("simulated restart failure")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(paneld, "DNSTT_DIR", dnstt_dir)
    monkeypatch.setattr(paneld, "DNSTT_FILE", config_file)
    monkeypatch.setattr(paneld, "binary", lambda name: name)
    monkeypatch.setattr(paneld, "run", fake_run)
    monkeypatch.setattr(
        paneld.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    with pytest.raises(RuntimeError, match="simulated restart failure"):
        paneld.configure_dnstt(
            {
                "zone": "t.example.com",
                "nameserver": "tns.example.com",
                "listen_ip": "203.0.113.10",
                "target_port": 109,
                "rotate_keys": True,
            }
        )
    assert private_key.read_text(encoding="ascii") == "1" * 64 + "\n"
    assert public_key.read_text(encoding="ascii") == "a" * 64 + "\n"
    assert config_file.read_text(encoding="utf-8") == original_config
