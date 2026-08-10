from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from paneld import command_allowed, parameters_allowed  # noqa: E402


def test_root_can_use_every_registered_command() -> None:
    assert command_allowed("root", "configure_bot")
    assert command_allowed("root", "configure_dashboard")


def test_dashboard_cannot_manage_bot_admins_or_services() -> None:
    assert command_allowed("dashboard", "create_user")
    assert command_allowed("dashboard", "configure_cdn")
    assert not command_allowed("dashboard", "configure_bot")
    assert not command_allowed("dashboard", "add_admin")
    assert not command_allowed("dashboard", "restart_service")


def test_bot_cannot_change_cdn_secret_or_dnstt_server() -> None:
    assert command_allowed("bot", "generate_exports")
    assert command_allowed("bot", "get_export")
    assert not command_allowed("bot", "configure_cdn")
    assert not command_allowed("bot", "configure_dnstt")
    assert not command_allowed("bot", "configure_dashboard")


def test_bot_restart_and_certificate_parameters_are_restricted() -> None:
    assert parameters_allowed("bot", "restart_service", {"service": "nginx"})
    assert not parameters_allowed("bot", "restart_service", {"service": "dropbear"})
    assert parameters_allowed("bot", "issue_cert", {})
    assert not parameters_allowed("bot", "issue_cert", {"domain": "other.example.com"})
