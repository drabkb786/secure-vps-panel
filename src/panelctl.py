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
    create.add_argument("--ips", type=int, default=0, help="Unique source IP cap; 0 = unlimited")

    delete = sub.add_parser("delete-user")
    delete.add_argument("username")

    renew = sub.add_parser("renew-user")
    renew.add_argument("username")
    renew.add_argument("--days", type=int, required=True)

    sessions = sub.add_parser("set-sessions")
    sessions.add_argument("username")
    sessions.add_argument("--sessions", type=int, required=True)
    sessions.add_argument("--ips", type=int, default=None, help="Unique source IP cap; 0 = unlimited")

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
    for action in ("xray-status", "xray-disable", "xray-sync"):
        sub.add_parser(action)
    enable = sub.add_parser("xray-enable")
    enable.add_argument("--xhttp", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable the additional VLESS XHTTP TLS endpoint")
    enable.add_argument("--non-tls", action=argparse.BooleanOptionalAction, default=None, help="Also expose direct VLESS WS + VLESS Encryption on port 80; requires a compatible Xray client, TLS stays enabled")
    profile = sub.add_parser("xray-create")
    profile.add_argument("name")
    profile.add_argument("--days", type=int, default=30)
    profile.add_argument("--quota", default="Unlimited")
    profile.add_argument("--ips", type=int, default=0)
    profile.add_argument("--protocol", action="append", choices=["vless", "vmess", "trojan"])
    renew_profile = sub.add_parser("xray-renew")
    renew_profile.add_argument("name")
    renew_profile.add_argument("--days", type=int, required=True)
    delete_profile = sub.add_parser("xray-delete")
    delete_profile.add_argument("name")
    export = sub.add_parser("xray-export")
    export.add_argument("name")
    format_group = export.add_mutually_exclusive_group()
    format_group.add_argument("--zip", type=Path, help="Save a private ZIP with all client profiles")
    format_group.add_argument("--links", action="store_true", help="Print only the import links, one per line")
    link = sub.add_parser("xray-link", help="Print one direct import URI without JSON wrapping")
    link.add_argument("name")
    link.add_argument("--protocol", choices=["vless", "vmess", "trojan", "vless-xhttp", "vless-reality", "vless-non-tls"], default="vless")
    for action in ("subscription-rotate", "subscription-revoke"):
        command = sub.add_parser(action)
        command.add_argument("name")
    backup = sub.add_parser("backup")
    backup.add_argument("--output", type=Path, required=True)
    restore = sub.add_parser("restore")
    restore.add_argument("path", type=Path)
    restore.add_argument("--yes", action="store_true", help="Confirm replacement of Xray profiles/settings")
    trial = sub.add_parser("xray-trial")
    trial.add_argument("name")
    trial.add_argument("--quota", default="1")
    for action in ("xray-lock", "xray-unlock", "xray-reset-usage", "lock-user", "unlock-user"):
        sub.add_parser(action).add_argument("name")
    quota_profile = sub.add_parser("xray-quota")
    quota_profile.add_argument("name"); quota_profile.add_argument("--quota", required=True)
    quota_profile.add_argument("--unit", choices=["GB", "GiB"], default=None)
    limits = sub.add_parser("xray-limits", help="Set byte quota and unique IP cap together")
    limits.add_argument("name"); limits.add_argument("--quota", required=True)
    limits.add_argument("--unit", choices=["GB", "GiB"], required=True)
    limits.add_argument("--ips", type=int, required=True)
    for action in ("traffic", "connections", "doctor", "restart-managed", "config-view", "memory-report", "banner", "slowdns-status", "slowdns-check", "slowdns-disable", "slowdns-install"):
        command = sub.add_parser(action)
        if action == "doctor": command.add_argument("--repair", action="store_true")
    packet = sub.add_parser("packet-test"); packet.add_argument("--target", choices=["1.1.1.1", "8.8.8.8"], default="1.1.1.1")
    logs = sub.add_parser("logs"); logs.add_argument("--service", default="abdulbasit-xray"); logs.add_argument("--level", choices=["error", "all"], default="error")
    banner = sub.add_parser("set-banner"); banner.add_argument("path", type=Path)
    slow = sub.add_parser("slowdns-enable"); slow.add_argument("--zone", required=True); slow.add_argument("--ns-host", required=True); slow.add_argument("--port", type=int, default=53); slow.add_argument("--mtu", type=int, default=1232)
    slow.add_argument("--mode", choices=["ssh", "xray", "both"], default=None)
    slow.add_argument("--xray-zone", default=None)
    udp = sub.add_parser("xray-udp"); udp.add_argument("mode", choices=["on", "off"])
    maintenance = sub.add_parser("maintenance"); maintenance.add_argument("operation", choices=["memory", "clean-logs", "reinstall", "uninstall"]); maintenance.add_argument("--source", type=Path); maintenance.add_argument("--reclaim", action="store_true")
    for action in ("cloudfront-status", "cloudfront-check", "cloudfront-disable"):
        sub.add_parser(action)
    cf = sub.add_parser("cloudfront-enable", help="Prepare TLS origin or attach a CloudFront distribution")
    cf.add_argument("--endpoint", default=None)
    cf.add_argument("--price-class", choices=["PriceClass_All", "PriceClass_200", "PriceClass_100"], default=None)
    setup = sub.add_parser("cloudfront-setup", help="Save private CloudFormation setup ZIP; AWS charges apply")
    setup.add_argument("--output", type=Path, required=True)
    for command in (export, link):
        command.add_argument("--route", choices=["direct", "cloudfront", "bunny", "dns"], default="direct")
    ssh = sub.add_parser("ssh-export")
    ssh.add_argument("username")
    ssh.add_argument("--route", choices=["direct", "bunny", "cloudfront"], default="direct")
    ssh.add_argument("--with-password", action="store_true", help="Prompt for password; include only in this export")
    ssh.add_argument("--save-password", action="store_true", help="Verify/save an existing SSH password once for future automatic sharing")
    ssh.add_argument("--zip", type=Path)
    for action in ("bunny-status", "bunny-check", "bunny-disable"):
        sub.add_parser(action)
    sub.add_parser("bunny-enable").add_argument("--endpoint", required=True)
    sub.add_parser("bunny-setup").add_argument("--output", type=Path, required=True)
    reality = sub.add_parser("reality-enable")
    reality.add_argument("--port", type=int, default=8443)
    sub.add_parser("reality-disable")
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.action in {"reality-enable", "reality-disable"}:
            result = request("xray_configure", enabled=True, reality_enabled=args.action == "reality-enable", **({"reality_port": args.port} if args.action == "reality-enable" else {}))
        elif args.action == "ssh-export":
            params = {"username": args.username, "route": args.route, "simple": not bool(args.zip)}
            if args.with_password or args.save_password:
                params["password"] = getpass.getpass("Current SSH password (verify and save): " if args.save_password else "Current SSH password (export only): ")
            if args.save_password:
                params["remember_password"] = True
            result = request("ssh_export", **params)
            if args.zip:
                fd = os.open(args.zip, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream, zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name, content in result["files"].items(): archive.writestr(name, content)
                result = {"saved": str(args.zip), "private": True}
            else:
                if not result["password_available"]:
                    raise RuntimeError("Current password is not saved; use ssh-export USER --save-password once")
                result = result["share"]
        elif args.action in {"cloudfront-status", "cloudfront-check", "bunny-status", "bunny-check"}:
            result = request(args.action.replace("-", "_"))
        elif args.action in {"cloudfront-enable", "cloudfront-disable", "bunny-enable", "bunny-disable"}:
            provider = args.action.split("-")[0]
            params = {"enabled": args.action.endswith("-enable")}
            for key in ("endpoint", "price_class"):
                if getattr(args, key, None) is not None: params[key] = getattr(args, key)
            result = request(provider + "_configure", **params)
        elif args.action in {"cloudfront-setup", "bunny-setup"}:
            data = request(args.action.replace("-", "_"))
            # Exclusive creation prevents overwriting a file or following a symlink.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream, zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, content in data["files"].items(): archive.writestr(name, content)
            result = {"saved": str(args.output), "notice": "Private origin secret included; keep this ZIP out of git and public sharing"}
        elif args.action == "maintenance":
            import maintenance
            result = maintenance.run(args.operation, source=args.source, reclaim=args.reclaim, confirm=input)
        elif args.action == "slowdns-install":
            if os.geteuid() != 0: raise RuntimeError("Core installation requires the root terminal")
            import subprocess
            process = subprocess.run(["/bin/bash", str(Path(__file__).parent / "install-dnstt.sh")], check=False, timeout=900)
            if process.returncode: raise RuntimeError("Official core installation failed; review the installer output")
            result = {"installed": True}
        elif args.action == "xray-limits":
            result = request("xray_update", name=args.name, action="limits", quota_gb=args.quota, quota_unit=args.unit, max_ips=args.ips)
        elif args.action in {"xray-lock", "xray-unlock", "xray-reset-usage", "xray-quota"}:
            action = "reset_usage" if args.action == "xray-reset-usage" else "quota" if args.action == "xray-quota" else "toggle"
            params = {"name": args.name, "action": action}
            if action == "toggle": params["enabled"] = args.action == "xray-unlock"
            if action == "quota": params["quota_gb"] = args.quota
            if action == "quota" and args.unit: params["quota_unit"] = args.unit
            result = request("xray_update", **params)
        elif args.action == "xray-trial":
            result = request("xray_create", name=args.name, days=1, trial=True, quota_gb=args.quota)
        elif args.action in {"lock-user", "unlock-user"}:
            result = request("set_user_lock", username=args.name, enabled=args.action == "unlock-user")
        elif args.action in {"traffic", "connections", "restart-managed", "config-view", "memory-report", "banner", "slowdns-status", "slowdns-check"}:
            mapping = {"traffic": "traffic_sample", "connections": "live_connections", "restart-managed": "restart_managed", "config-view": "config_view", "memory-report": "memory_report", "banner": "banner_get"}
            result = request(mapping.get(args.action, args.action.replace("-", "_")))
        elif args.action == "doctor": result = request("doctor", repair=args.repair)
        elif args.action == "packet-test": result = request("packet_test", target=args.target)
        elif args.action == "logs": result = request("live_logs", service=args.service, level=args.level)
        elif args.action == "set-banner": result = request("banner_set", text=args.path.read_text())
        elif args.action in {"slowdns-enable", "slowdns-disable"}:
            params = {"enabled": args.action == "slowdns-enable"}
            if params["enabled"]:
                params.update(zone=args.zone, ns_host=args.ns_host, port=args.port, mtu=args.mtu)
                if args.mode is not None:
                    params["mode"] = args.mode
                if args.xray_zone is not None:
                    params["xray_zone"] = args.xray_zone
            result = request("slowdns_configure", **params)
        elif args.action == "xray-udp":
            result = request("xray_configure", enabled=True, udp_enabled=args.mode == "on")
        elif args.action == "create-user":
            password = getpass.getpass("Password (minimum 3 characters): ")
            confirmation = getpass.getpass("Confirm password: ")
            if password != confirmation:
                raise RuntimeError("Passwords do not match")
            result = request("create_user", username=args.username, password=password, days=args.days, max_sessions=args.sessions, quota_gb=args.quota, max_ips=args.ips)
        elif args.action == "delete-user":
            result = request("delete_user", username=args.username)
        elif args.action == "renew-user":
            result = request("renew_user", username=args.username, days=args.days)
        elif args.action == "set-sessions":
            result = request("set_sessions", username=args.username, max_sessions=args.sessions, **({"max_ips": args.ips} if args.ips is not None else {}))
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
            params = {"enabled": args.action == "xray-enable"}
            if args.action == "xray-enable" and args.xhttp is not None:
                params["xhttp_enabled"] = args.xhttp
            if args.action == "xray-enable" and args.non_tls is not None:
                params["vless_non_tls_enabled"] = args.non_tls
            result = request("xray_configure", **params)
        elif args.action in {"subscription-rotate", "subscription-revoke"}:
            result = request(args.action.replace("-", "_"), name=args.name)
        elif args.action == "backup":
            data = request("backup_export")["backup"]
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump(data, handle, indent=2); handle.write("\n")
            result = {"saved": str(args.output), "scope": data.get("scope")}
        elif args.action == "restore":
            if os.geteuid() != 0:
                raise RuntimeError("Restore requires the root CLI")
            if not args.path.is_file() or args.path.stat().st_size > 256 * 1024:
                raise RuntimeError("Choose a regular backup JSON file, at most 256 KiB")
            data = json.loads(args.path.read_text())
            if not args.yes and input("Replace current Xray profiles/settings? Type RESTORE: ").strip() != "RESTORE":
                raise RuntimeError("Restore cancelled")
            result = request("backup_restore", backup=data)
        elif args.action == "xray-create":
            params = {"name": args.name, "days": args.days, "quota_gb": args.quota, "max_ips": args.ips}
            if args.protocol:
                params["protocols"] = args.protocol
            result = request("xray_create", **params)
        elif args.action == "xray-renew":
            result = request("xray_update", name=args.name, action="renew", days=args.days)
        elif args.action == "xray-delete":
            result = request("xray_update", name=args.name, action="delete")
        elif args.action in {"xray-export", "xray-link"}:
            result = request("xray_export", name=args.name, route=args.route)
            for warning in result.get("readiness", {}).get("warnings", []):
                print(f"WARNING: {warning}", file=sys.stderr)
            if args.action == "xray-link":
                link = result["links"].get(args.protocol)
                if not link:
                    raise RuntimeError(f"{args.protocol.upper()} is not enabled for this account")
                print(link)
                return 0
            if args.links:
                print("\n".join(result["links"].values()))
                return 0
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
    except (RuntimeError, OSError, ValueError, KeyboardInterrupt) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
