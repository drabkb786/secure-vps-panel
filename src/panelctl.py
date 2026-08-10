#!/usr/bin/env python3
"""Root/admin CLI for the Abdul Basit panel daemon."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from typing import Any

from common import DEFAULT_SUPER_ADMIN_ID
from panel_client import request


def print_json(data: dict[str, Any]) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="abdulbasit-panelctl")
    sub = p.add_subparsers(dest="action", required=True)

    create = sub.add_parser("create-user")
    create.add_argument("username")
    create.add_argument("--days", type=int, required=True)
    create.add_argument("--sessions", type=int, required=True)
    create.add_argument("--quota", default="Unlimited")
    create.add_argument(
        "--protocols", default="ssh", help="Comma-separated: ssh,vmess,vless,trojan"
    )

    delete = sub.add_parser("delete-user")
    delete.add_argument("username")

    renew = sub.add_parser("renew-user")
    renew.add_argument("username")
    renew.add_argument("--days", type=int, required=True)

    sessions = sub.add_parser("set-sessions")
    sessions.add_argument("username")
    sessions.add_argument("--sessions", type=int, required=True)

    quota = sub.add_parser("set-quota")
    quota.add_argument("username")
    quota.add_argument("--quota", required=True)

    enable_protocol = sub.add_parser("enable-protocol")
    enable_protocol.add_argument("username")
    enable_protocol.add_argument("protocols", help="Comma-separated protocols")

    disable_protocol = sub.add_parser("disable-protocol")
    disable_protocol.add_argument("username")
    disable_protocol.add_argument("protocol")

    rotate_protocol = sub.add_parser("rotate-protocol")
    rotate_protocol.add_argument("username")
    rotate_protocol.add_argument("protocol")

    reset_usage = sub.add_parser("reset-usage")
    reset_usage.add_argument("username")

    sub.add_parser("list-users")
    sub.add_parser("list-sessions")
    sub.add_parser("status")

    domain = sub.add_parser("set-domain")
    domain.add_argument("domain")

    cert = sub.add_parser("issue-cert")
    cert.add_argument("--domain", default="")

    cdn = sub.add_parser("configure-cdn")
    cdn.add_argument("provider", choices=["cloudfront", "cloudflare"])
    cdn.add_argument("--endpoint", required=True)
    cdn.add_argument("--origin", default="")
    cdn.add_argument("--secret", default="")

    remove_cdn = sub.add_parser("remove-cdn")
    remove_cdn.add_argument("provider", choices=["cloudfront", "cloudflare"])
    sub.add_parser("list-cdn")

    exports = sub.add_parser("generate-exports")
    exports.add_argument("username")
    exports.add_argument("protocol", choices=["vmess", "vless", "trojan"])
    exports.add_argument(
        "--provider", default="direct", choices=["direct", "cloudflare", "cloudfront"]
    )

    list_exports = sub.add_parser("list-exports")
    list_exports.add_argument("username")

    get_export = sub.add_parser("get-export")
    get_export.add_argument("username")
    get_export.add_argument("filename")

    delete_export = sub.add_parser("delete-export")
    delete_export.add_argument("username")
    delete_export.add_argument("filename")

    dnstt = sub.add_parser("configure-dnstt")
    dnstt.add_argument("--zone", required=True)
    dnstt.add_argument("--nameserver", required=True)
    dnstt.add_argument("--listen-ip", required=True)
    dnstt.add_argument("--target-port", type=int, default=109)
    dnstt.add_argument("--rotate-keys", action="store_true")
    sub.add_parser("list-dnstt")
    sub.add_parser("disable-dnstt")
    dnstt_export = sub.add_parser("export-dnstt")
    dnstt_export.add_argument("username")

    restart = sub.add_parser("restart")
    restart.add_argument("service")

    sub.add_parser("configure-bot")
    sub.add_parser("configure-dashboard")

    add_admin = sub.add_parser("add-admin")
    add_admin.add_argument("telegram_id")

    remove_admin = sub.add_parser("remove-admin")
    remove_admin.add_argument("telegram_id")

    sub.add_parser("list-admins")
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.action == "create-user":
            password = getpass.getpass("Password (minimum 12 characters): ")
            confirmation = getpass.getpass("Confirm password: ")
            if password != confirmation:
                raise RuntimeError("Passwords do not match")
            result = request(
                "create_user",
                username=args.username,
                password=password,
                days=args.days,
                max_sessions=args.sessions,
                quota_gb=args.quota,
                protocols=args.protocols,
            )
        elif args.action == "delete-user":
            result = request("delete_user", username=args.username)
        elif args.action == "renew-user":
            result = request("renew_user", username=args.username, days=args.days)
        elif args.action == "set-sessions":
            result = request(
                "set_sessions", username=args.username, max_sessions=args.sessions
            )
        elif args.action == "set-quota":
            result = request("set_quota", username=args.username, quota_gb=args.quota)
        elif args.action == "enable-protocol":
            result = request(
                "enable_protocol", username=args.username, protocols=args.protocols
            )
        elif args.action == "disable-protocol":
            result = request(
                "disable_protocol", username=args.username, protocol=args.protocol
            )
        elif args.action == "rotate-protocol":
            result = request(
                "rotate_protocol", username=args.username, protocol=args.protocol
            )
        elif args.action == "reset-usage":
            result = request("reset_usage", username=args.username)
        elif args.action == "list-users":
            result = request("list_users")
        elif args.action == "list-sessions":
            result = request("list_sessions")
        elif args.action == "status":
            result = request("service_status")
        elif args.action == "set-domain":
            result = request("set_domain", domain=args.domain)
        elif args.action == "issue-cert":
            result = request("issue_cert", domain=args.domain)
        elif args.action == "configure-cdn":
            result = request(
                "configure_cdn",
                provider=args.provider,
                endpoint=args.endpoint,
                origin=args.origin,
                origin_secret=args.secret,
            )
        elif args.action == "remove-cdn":
            result = request("remove_cdn", provider=args.provider)
        elif args.action == "list-cdn":
            result = request("list_cdn")
        elif args.action == "generate-exports":
            result = request(
                "generate_exports",
                username=args.username,
                protocol=args.protocol,
                provider=args.provider,
            )
        elif args.action == "list-exports":
            result = request("list_exports", username=args.username)
        elif args.action == "get-export":
            result = request(
                "get_export", username=args.username, filename=args.filename
            )
        elif args.action == "delete-export":
            result = request(
                "delete_export", username=args.username, filename=args.filename
            )
        elif args.action == "configure-dnstt":
            result = request(
                "configure_dnstt",
                zone=args.zone,
                nameserver=args.nameserver,
                listen_ip=args.listen_ip,
                target_port=args.target_port,
                rotate_keys=args.rotate_keys,
            )
        elif args.action == "list-dnstt":
            result = request("list_dnstt")
        elif args.action == "disable-dnstt":
            result = request("disable_dnstt")
        elif args.action == "export-dnstt":
            result = request("export_dnstt", username=args.username)
        elif args.action == "restart":
            result = request("restart_service", service=args.service)
        elif args.action == "configure-bot":
            token = getpass.getpass("Telegram bot token (input hidden): ")
            super_admin = (
                input(
                    f"Super Admin numeric Telegram ID [{DEFAULT_SUPER_ADMIN_ID}]: "
                ).strip()
                or DEFAULT_SUPER_ADMIN_ID
            )
            result = request("configure_bot", token=token, super_admin=super_admin)
        elif args.action == "configure-dashboard":
            username = input("Dashboard admin username [admin]: ").strip() or "admin"
            password = getpass.getpass("Dashboard password (minimum 12 characters): ")
            confirmation = getpass.getpass("Confirm dashboard password: ")
            if password != confirmation:
                raise RuntimeError("Passwords do not match")
            result = request(
                "configure_dashboard", username=username, password=password
            )
        elif args.action == "add-admin":
            result = request("add_admin", admin_id=args.telegram_id)
        elif args.action == "remove-admin":
            result = request("remove_admin", admin_id=args.telegram_id)
        elif args.action == "list-admins":
            result = request("list_admins")
        else:
            raise RuntimeError("Unknown action")
        print_json(result)
        return 0
    except (RuntimeError, KeyboardInterrupt) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
