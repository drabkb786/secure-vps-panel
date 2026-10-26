#!/usr/bin/env python3
"""Root/admin CLI for the Abdul Basit panel daemon."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
import os
import zipfile
from pathlib import Path
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
    sub.add_parser("configure-web", help="Create/reset browser login; run as root")
    sub.add_parser("diagnostics")
    lookup = sub.add_parser("dns-lookup")
    lookup.add_argument("--domain", default="")
    dns = sub.add_parser("dns-set")
    dns.add_argument("--server", action="append", required=True)
    dns.add_argument("--strategy", choices=["UseIP", "UseIPv4", "UseIPv6"], default="UseIPv4")
    for action in ("xray-status", "xray-enable", "xray-disable", "xray-sync"):
        sub.add_parser(action)
    profile = sub.add_parser("xray-create")
    profile.add_argument("name")
    profile.add_argument("--days", type=int, default=30)
    profile.add_argument("--protocol", action="append", choices=["vless", "vmess", "trojan"])
    renew_profile = sub.add_parser("xray-renew")
    renew_profile.add_argument("name")
    renew_profile.add_argument("--days", type=int, required=True)
    delete_profile = sub.add_parser("xray-delete")
    delete_profile.add_argument("name")
    export = sub.add_parser("xray-export")
    export.add_argument("name")
    export.add_argument("--zip", type=Path, help="Save a private ZIP with all client profiles")
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
        elif args.action == "configure-web":
            if os.geteuid() != 0:
                raise RuntimeError("Run configure-web as root")
            username = input("Web admin username [noway]: ").strip() or "noway"
            password = getpass.getpass("Web admin password (minimum 12 characters): ")
            if password != getpass.getpass("Confirm web password: "):
                raise RuntimeError("Passwords do not match")
            result = request("configure_web", username=username, password=password)
        elif args.action == "diagnostics":
            result = request("diagnostics")
        elif args.action == "dns-lookup":
            result = request("dns_lookup", domain=args.domain)
        elif args.action == "dns-set":
            result = request("dns_set", servers=args.server, query_strategy=args.strategy)
        elif args.action in {"xray-status", "xray-sync"}:
            result = request(args.action.replace("-", "_"))
        elif args.action in {"xray-enable", "xray-disable"}:
            result = request("xray_configure", enabled=args.action == "xray-enable")
        elif args.action == "xray-create":
            params = {"name": args.name, "days": args.days}
            if args.protocol:
                params["protocols"] = args.protocol
            result = request("xray_create", **params)
        elif args.action == "xray-renew":
            result = request("xray_update", name=args.name, action="renew", days=args.days)
        elif args.action == "xray-delete":
            result = request("xray_update", name=args.name, action="delete")
        elif args.action == "xray-export":
            result = request("xray_export", name=args.name)
            if args.zip:
                # Exclusive creation avoids clobbering an existing file or following a symlink.
                fd = os.open(args.zip, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as handle, zipfile.ZipFile(handle, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name, content in result["files"].items():
                        archive.writestr(name, content)
                result = {"saved": str(args.zip)}
        else:
            raise RuntimeError("Unknown action")
        print_json(result)
        return 0
    except (RuntimeError, OSError, KeyboardInterrupt) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
