from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from protocols import (  # noqa: E402
    XRAY_INBOUNDS,
    enable_protocols,
    quota_exceeded,
    render_xray_config,
    rotate_protocol,
)


def make_user() -> dict:
    return enable_protocols(
        {
            "username": "alice",
            "expiry": (date.today() + timedelta(days=30)).isoformat(),
            "quota_gb": 2,
            "usage_bytes": 0,
        },
        ["ssh", "vmess", "vless", "trojan"],
    )


def test_xray_v26_server_config_is_loopback_only() -> None:
    config = render_xray_config([make_user()])
    assert config["api"]["listen"] == "127.0.0.1:21085"
    assert config["stats"] == {}
    assert [item["protocol"] for item in config["inbounds"]] == [
        "vmess",
        "vless",
        "trojan",
    ]
    for inbound in config["inbounds"]:
        assert inbound["listen"] == "127.0.0.1"
        assert inbound["port"] == XRAY_INBOUNDS[inbound["protocol"]]["port"]
        assert len(inbound["settings"]["clients"]) == 1
        assert "users" not in inbound["settings"]


def test_expired_and_over_quota_users_are_removed() -> None:
    expired = make_user()
    expired["expiry"] = (date.today() - timedelta(days=1)).isoformat()
    limited = make_user()
    limited["username"] = "bob"
    limited["usage_bytes"] = 2_000_000_000
    assert quota_exceeded(limited)
    config = render_xray_config([expired, limited])
    assert all(not inbound["settings"]["clients"] for inbound in config["inbounds"])


def test_credentials_are_unique_and_rotate() -> None:
    user = make_user()
    assert user["protocols"]["vmess"]["id"] != user["protocols"]["vless"]["id"]
    old = user["protocols"]["trojan"]["password"]
    rotated = rotate_protocol(user, "trojan")
    assert rotated["protocols"]["trojan"]["password"] != old
    assert user["protocols"]["trojan"]["password"] == old
