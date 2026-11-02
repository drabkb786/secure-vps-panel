"""Bounded server operations; destructive installation work stays in the root CLI."""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
from datetime import datetime, timezone
from pathlib import Path

from common import BASE_DIR, DOMAIN_FILE, ValidationError, atomic_write, read_text

BANNER_FILE = BASE_DIR / "ssh-banner.txt"
UNITS = ("nginx", "dropbear", "abdulbasit-ws", "abdulbasit-session-enforcer", "abdulbasit-xray", "abdulbasit-dnstt")
LOG_UNITS = (*UNITS, "abdulbasit-paneld", "abdulbasit-web", "abdulbasit-bot")


def redact(text):
    text = re.sub(r"(?:vless|vmess|trojan)://\S+", "[private import link]", text)
    text = re.sub(r"/panel/sub/[A-Za-z0-9_-]+", "/panel/sub/[redacted]", text)
    return re.sub(r"\b[0-9]{6,12}:[A-Za-z0-9_-]{30,80}\b", "[bot token]", text)


def endpoint(value):
    host, port = value.rsplit(":", 1)
    return str(ipaddress.ip_address(host.strip("[]"))), int(port)


def parse_peers(text):
    peers = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "ESTAB":
            continue
        try:
            local, port = endpoint(parts[3]); remote, _ = endpoint(parts[4])
        except (ValueError, IndexError):
            continue
        if port not in (80, 443, 109, 447) or ipaddress.ip_address(remote).is_loopback:
            continue
        peers.append({"ip": remote, "port": port, "transport": "SSH" if port in (109, 447) else "TLS gateway" if port == 443 else "HTTP gateway",
                      "verified_account": False})
    # A gateway connection alone does not prove profile authentication.
    return peers[:1000]


class Manager:
    def __init__(self, run, xray, services, regenerate_nginx):
        self.run, self.xray, self.services, self.regenerate_nginx = run, xray, services, regenerate_nginx

    def logs(self, params):
        service = params.get("service", "abdulbasit-xray")
        if service not in LOG_UNITS:
            raise ValidationError("Choose a managed service")
        level = params.get("level", "error")
        if level not in ("error", "all"):
            raise ValidationError("Choose error or all logs")
        args = [shutil.which("journalctl") or "/bin/journalctl", "--no-pager", "--output=short-iso", "-n", "100", "-u", service]
        if level == "error": args += ["--priority=err"]
        result = self.run(args, timeout=8)
        return {"service": service, "text": redact(result.stdout[-24000:]), "captured_at": datetime.now(timezone.utc).isoformat()}

    def connections(self, _):
        peers = parse_peers(self.run([shutil.which("ss") or "/usr/bin/ss", "-Htn"], timeout=5).stdout)
        online = self.xray.online({})
        return {"gateway_peers": peers, "unique_gateway_ips": len({x["ip"] for x in peers}), "xray": online,
                "note": "Gateway peers are observed TCP connections, not verified accounts. Xray addresses are authenticated recent activity reported by the core."}

    def packet_test(self, params):
        target = params.get("target", "1.1.1.1")
        if target not in ("1.1.1.1", "8.8.8.8"):
            raise ValidationError("Choose 1.1.1.1 or 8.8.8.8")
        ping = shutil.which("ping")
        if not ping:
            raise ValidationError("Install iputils-ping first")
        try:
            output = self.run([ping, "-n", "-c", "15", "-i", "1", "-W", "1", "-w", "16", target], timeout=19).stdout
            ok = True
        except RuntimeError as exc:
            output, ok = str(exc), False
        return {"ok": ok, "target": target, "text": output[-6000:], "note": "15 ICMP probes; this is packet loss/latency, not a bandwidth speed test. Some networks block ICMP."}

    def banner_get(self, _):
        return {"text": read_text(BANNER_FILE), "scope": "Managed Dropbear login banner; normal OpenSSH is unchanged"}

    def banner_set(self, params):
        text = params.get("text")
        if not isinstance(text, str) or len(text) > 2000 or any(ord(c) < 32 and c not in "\n\t" for c in text):
            raise ValidationError("Use up to 2000 plain-text characters, without terminal control codes")
        before = read_text(BANNER_FILE)
        atomic_write(BANNER_FILE, text + "\n", 0o644)
        try:
            self.run(["/bin/systemctl", "restart", "dropbear"], timeout=30)
        except Exception:
            atomic_write(BANNER_FILE, before + "\n", 0o644)
            raise
        return self.banner_get({})

    def config_view(self, _):
        from xray_manager import settings, server_config, accounts
        config = server_config(settings(), accounts())
        for inbound in config["inbounds"]:
            for client in inbound.get("settings", {}).get("clients", []):
                for key in ("id", "password"):
                    if key in client: client[key] = "[redacted]"
        return {"domain": read_text(DOMAIN_FILE), "network": settings(), "xray_server": config,
                "note": "Credential fields are redacted. Use private exports for actual client files."}

    def restart_all(self, params):
        from xray_manager import settings
        import slowdns
        self.run([shutil.which("nginx") or "/usr/sbin/nginx", "-t"], timeout=10)
        self.xray.collect_usage()
        units = [x for x in UNITS if x != "abdulbasit-xray" or settings()["enabled"]]
        if not slowdns.settings().get("enabled"): units.remove("abdulbasit-dnstt")
        statuses = self.services({})["services"]
        actions = []
        for unit in units:
            if params.get("failed_only") and statuses.get(unit) == "active": continue
            try:
                if unit == "abdulbasit-xray": self.xray.configure({"enabled": True})
                else: self.run(["/bin/systemctl", "restart", unit], timeout=30)
                actions.append({"service": unit, "ok": True})
            except RuntimeError as exc:
                actions.append({"service": unit, "ok": False, "detail": str(exc)})
        return {"actions": actions, "note": "Managed gateway services only. The command daemon, web worker and normal OpenSSH are kept available."}

    def doctor(self, params):
        import diagnostics
        if params.get("repair") is not True:
            return diagnostics.report({})
        before = diagnostics.report({})
        actions = self.restart_all({"failed_only": True})
        return {"before": before, **actions, "after": diagnostics.report({}),
                "note": "Repairs restart failed managed services after a successful Nginx config check. DNS provider records, certificates and firewall rules are never invented or silently changed."}

    def memory(self, _):
        values = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1); values[key] = int(value.strip().split()[0]) * 1024
        return {"total": values.get("MemTotal"), "available": values.get("MemAvailable"),
                "cached": values.get("Cached"), "note": "Linux reclaims file cache automatically. Clearing caches is a root-terminal maintenance action, not a speed boost."}
