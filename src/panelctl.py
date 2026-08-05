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

    sub.add_parser("list-users")
    sub.add_parser("list-sessions")
    sub.add_parser("status")

    domain = sub.add_parser("set-domain")
    domain.add_argument("domain")

    cert = sub.add_parser("issue-cert")
    cert.add_argument("--domain", default="")

    restart = sub.add_parser("restart")
    restart.add_argument("service")

    sub.add_parser("configure-bot")

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
            result = request("create_user", username=args.username, password=password, days=args.days, max_sessions=args.sessions, quota_gb=args.quota)
        elif args.action == "delete-user":
            result = request("delete_user", username=args.username)
        elif args.action == "renew-user":
            result = request("renew_user", username=args.username, days=args.days)
        elif args.action == "set-sessions":
            result = request("set_sessions", username=args.username, max_sessions=args.sessions)
        elif args.action == "set-quota":
            result = request("set_quota", username=args.username, quota_gb=args.quota)
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
        elif args.action == "restart":
            result = request("restart_service", service=args.service)
        elif args.action == "configure-bot":
            token = getpass.getpass("Telegram bot token (input hidden): ")
            super_admin = input(f"Super Admin numeric Telegram ID [{DEFAULT_SUPER_ADMIN_ID}]: ").strip() or DEFAULT_SUPER_ADMIN_ID
            result = request("configure_bot", token=token, super_admin=super_admin)
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
