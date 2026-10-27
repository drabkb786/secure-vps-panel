"""Managed Xray WS/TLS profiles, transactional config changes and client exports.

Nginx terminates TLS; all three Xray inbounds are loopback-only. Existing
independent xray.service installations/configs are never overwritten.
"""
from __future__ import annotations

import base64
import grp
import ipaddress
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

from common import (BASE_DIR, DOMAIN_FILE, ValidationError, atomic_write,
                    atomic_write_json, calculate_expiry, read_json, read_text,
                    validate_days, validate_domain, validate_username)

SETTINGS_FILE = BASE_DIR / "network.json"
ACCOUNTS_FILE = BASE_DIR / "xray_accounts.json"
CONFIG_DIR = Path("/etc/abdulbasit-xray")
CONFIG_FILE = CONFIG_DIR / "config.json"
ENABLED_FILE = CONFIG_DIR / "enabled"
CERT_ROOT = Path("/etc/letsencrypt/live")
XRAY_BINARY = Path("/usr/local/lib/abdulbasit/xray")
PROTOCOLS = {"vless": (10001, "/vless"), "vmess": (10002, "/vmess"), "trojan": (10003, "/trojan")}
DEFAULT_DNS = {"servers": ["1.1.1.1", "8.8.8.8"], "query_strategy": "UseIPv4"}
MAX_ACCOUNTS = 200


def settings() -> dict:
    return {"enabled": False, "dns": dict(DEFAULT_DNS), **read_json(SETTINGS_FILE, {})}


def accounts() -> list[dict]:
    data = read_json(ACCOUNTS_FILE, [])
    if not isinstance(data, list):
        raise RuntimeError("Xray account store is invalid; restore its backup")
    return data


def active(account: dict, today: date | None = None) -> bool:
    try:
        return account.get("enabled", True) is True and date.fromisoformat(account["expiry"]) > (today or date.today())
    except (KeyError, ValueError, TypeError):
        return False


def public_account(account: dict) -> dict:
    return {k: v for k, v in account.items() if k not in {"uuid", "trojan_password"}} | {"active": active(account)}


def validate_dns(params: dict) -> dict:
    servers = params.get("servers")
    if not isinstance(servers, list) or not 1 <= len(servers) <= 4:
        raise ValidationError("Supply 1-4 DNS server IPs or HTTPS DoH URLs")
    clean = []
    for value in servers:
        if not isinstance(value, str) or len(value) > 256:
            raise ValidationError("Invalid DNS server")
        value = value.strip()
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            try:
                u = urlsplit(value)
            except ValueError as exc:
                raise ValidationError("Invalid DNS server URL") from exc
            try:
                valid_port = u.port in (None, 443)
            except ValueError:
                valid_port = False
            if u.scheme != "https" or not u.hostname or u.username or u.password or u.fragment or u.query or not valid_port:
                raise ValidationError("DNS supports IP addresses or HTTPS DoH on port 443")
            try:
                ipaddress.ip_address(u.hostname)
            except ValueError:
                validate_domain(u.hostname)
            if not u.path.startswith("/") or any(ch.isspace() or ord(ch) < 32 for ch in value):
                raise ValidationError("DoH URL must include a path, such as /dns-query")
        if value not in clean:
            clean.append(value)
    strategy = params.get("query_strategy", "UseIPv4")
    if strategy not in {"UseIP", "UseIPv4", "UseIPv6"}:
        raise ValidationError("DNS strategy must be UseIP, UseIPv4 or UseIPv6")
    return {"servers": clean, "query_strategy": strategy}


def server_config(config: dict, rows: list[dict]) -> dict:
    dns = validate_dns(config["dns"])
    inbounds = []
    for protocol, (port, path) in PROTOCOLS.items():
        clients = []
        for row in rows:
            if not active(row) or protocol not in row["protocols"]:
                continue
            client = {"email": f"{row['name']}-{protocol}@noway.local", "level": 0}
            if protocol == "trojan":
                client["password"] = row["trojan_password"]
            else:
                client["id"] = row["uuid"]
            clients.append(client)
        # 'clients' is supported by older releases and retained as an alias in current Xray.
        inbound_settings = {"clients": clients}
        if protocol == "vless":
            inbound_settings["decryption"] = "none"
        inbounds.append({
            "tag": f"noway-{protocol}", "listen": "127.0.0.1", "port": port,
            "protocol": protocol, "settings": inbound_settings,
            "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": path}},
        })
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": dns["servers"], "queryStrategy": dns["query_strategy"]},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {"domainStrategy": dns["query_strategy"]}}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        # Block private/link-local targets, including metadata services, after DNS resolution.
        "routing": {"domainStrategy": "IPOnDemand", "rules": [{
            "type": "field", "ip": ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"], "outboundTag": "block",
        }]},
    }


def client_config(protocol: str, row: dict, domain: str, dns: dict) -> dict:
    _, path = PROTOCOLS[protocol]
    credential = {"password": row["trojan_password"]} if protocol == "trojan" else {"id": row["uuid"], "encryption": "none"} if protocol == "vless" else {"id": row["uuid"], "security": "auto", "alterId": 0}
    proxy_settings = {"servers": [{"address": domain, "port": 443, **credential}]} if protocol == "trojan" else {"vnext": [{"address": domain, "port": 443, "users": [credential]}]}
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": dns["servers"], "queryStrategy": dns["query_strategy"]},
        "inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{
            "tag": "proxy", "protocol": protocol, "settings": proxy_settings,
            "streamSettings": {
                "network": "ws", "security": "tls",
                "tlsSettings": {"serverName": domain, "allowInsecure": False},
                "wsSettings": {"path": path, "host": domain},
            },
        }],
    }


def share_link(protocol: str, row: dict, domain: str) -> str:
    if protocol not in PROTOCOLS:
        raise ValidationError("Choose vless, vmess or trojan")
    domain = validate_domain(domain)
    _, path = PROTOCOLS[protocol]
    label = f"NOWAY-{row['name']}-{protocol.upper()}"
    if protocol == "vmess":
        data = {"v": "2", "ps": label, "add": domain, "port": "443", "id": row["uuid"], "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": domain, "path": path, "tls": "tls", "sni": domain}
        return "vmess://" + base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()
    credential = row["trojan_password"] if protocol == "trojan" else row["uuid"]
    query = {"security": "tls", "type": "ws", "host": domain, "sni": domain, "path": path}
    if protocol == "vless":
        query["encryption"] = "none"
    return f"{protocol}://{quote(credential, safe='')}@{domain}:443?{urlencode(query)}#{quote(label)}"


class Manager:
    def __init__(self, run, *, health_probe=None):
        self.run = run
        self.health_probe = health_probe or self.runtime_ready

    def runtime_ready(self) -> bool:
        """A successful Type=simple start alone does not establish listener readiness."""
        try:
            self.run(["/bin/systemctl", "is-active", "--quiet", "abdulbasit-xray"], timeout=3)
            for port, _ in PROTOCOLS.values():
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    pass
            return True
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            return False

    def wait_running(self) -> None:
        deadline = time.monotonic() + 8
        while True:
            if self.health_probe():
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("Xray did not become ready; previous config restored. Check journalctl -u abdulbasit-xray for port conflicts or startup errors")
            time.sleep(0.2)

    def ready(self) -> str:
        domain = validate_domain(read_text(DOMAIN_FILE))
        if not all((CERT_ROOT / domain / name).is_file() for name in ("fullchain.pem", "privkey.pem")):
            raise ValidationError("Set the domain and issue its TLS certificate before enabling Xray")
        if not XRAY_BINARY.is_file():
            raise ValidationError("Xray core is not installed; run install.sh --with-xray")
        return domain

    def apply(self, config: dict, rows: list[dict], *, force_restart: bool = False) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o750)
        os.chmod(CONFIG_DIR, 0o750)
        try:
            gid = grp.getgrnam("abdulbasit-xray").gr_gid
            os.chown(CONFIG_DIR, 0, gid)
        except KeyError:
            gid = None
        text = json.dumps(server_config(config, rows), indent=2) + "\n"
        if config["enabled"]:
            self.ready()
            # Verify a candidate without touching the working config first.
            fd, candidate = tempfile.mkstemp(prefix=".candidate-", suffix=".json", dir=CONFIG_DIR)
            try:
                with os.fdopen(fd, "w") as handle:
                    handle.write(text)
                self.run([str(XRAY_BINARY), "run", "-test", "-config", candidate], timeout=30)
            finally:
                Path(candidate).unlink(missing_ok=True)
        old = {p: p.read_text() if p.exists() else None for p in (CONFIG_FILE, SETTINGS_FILE, ACCOUNTS_FILE, ENABLED_FILE)}
        changed = force_restart or text != old[CONFIG_FILE] or config["enabled"] != settings()["enabled"]
        try:
            atomic_write_json(SETTINGS_FILE, config)
            atomic_write_json(ACCOUNTS_FILE, rows)
            atomic_write(CONFIG_FILE, text, 0o640)
            if gid is not None:
                os.chown(CONFIG_FILE, 0, gid)
            if config["enabled"]:
                atomic_write(ENABLED_FILE, "enabled\n", 0o644)
            else:
                ENABLED_FILE.unlink(missing_ok=True)
            if changed:
                self.run(["/bin/systemctl", "restart" if config["enabled"] else "stop", "abdulbasit-xray"], timeout=30)
                if config["enabled"]:
                    self.wait_running()
        except Exception:
            for path, content in old.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, content, 0o640 if path == CONFIG_FILE else 0o644 if path == ENABLED_FILE else 0o600)
                    if path == CONFIG_FILE and gid is not None:
                        os.chown(path, 0, gid)
            if old[CONFIG_FILE] is not None:
                try:
                    self.run(["/bin/systemctl", "restart" if settings()["enabled"] else "stop", "abdulbasit-xray"], timeout=30)
                except RuntimeError:
                    pass
            else:
                try:
                    self.run(["/bin/systemctl", "stop", "abdulbasit-xray"], timeout=30)
                except RuntimeError:
                    pass
            raise

    def status(self, _: dict) -> dict:
        cfg = settings()
        return {"network": cfg, "xray_installed": XRAY_BINARY.is_file(), "accounts": [public_account(x) for x in accounts()],
                "endpoints": [{"protocol": p, "port": 443, "path": v[1], "transport": "ws+tls"} for p, v in PROTOCOLS.items()]}

    def configure(self, params: dict) -> dict:
        enabled = params.get("enabled")
        if not isinstance(enabled, bool):
            raise ValidationError("enabled must be a boolean")
        cfg = settings()
        cfg["enabled"] = enabled
        # Explicit enable/disable must act even when the saved settings are unchanged.
        self.apply(cfg, accounts(), force_restart=True)
        return self.status({})

    def set_dns(self, params: dict) -> dict:
        cfg = settings()
        cfg["dns"] = validate_dns(params)
        if cfg["enabled"]:
            self.apply(cfg, accounts())
        else:
            atomic_write_json(SETTINGS_FILE, cfg)
        return {"dns": cfg["dns"], "scope": "Xray server and exported client profiles"}

    def create(self, params: dict) -> dict:
        domain = self.ready()
        if not settings()["enabled"]:
            raise ValidationError("Enable Xray first")
        rows = accounts()
        name = validate_username(str(params.get("name", "")))
        protocols = params.get("protocols", list(PROTOCOLS))
        if not isinstance(protocols, list) or not protocols or any(not isinstance(x, str) or x not in PROTOCOLS for x in protocols):
            raise ValidationError("Select vless, vmess and/or trojan")
        if any(x["name"] == name for x in rows):
            raise ValidationError("Xray account name already exists")
        if len(rows) >= MAX_ACCOUNTS:
            raise ValidationError(f"Maximum {MAX_ACCOUNTS} accounts; remove unused accounts first")
        row = {"name": name, "protocols": sorted(set(protocols)), "uuid": str(uuid.uuid4()),
               "trojan_password": secrets.token_urlsafe(32), "enabled": True,
               "expiry": calculate_expiry(validate_days(params.get("days"))),
               "created_at": datetime.now(timezone.utc).isoformat()}
        self.apply(settings(), rows + [row])
        return {"account": public_account(row), "links": {p: share_link(p, row, domain) for p in row["protocols"]}}

    def update(self, params: dict) -> dict:
        name = validate_username(str(params.get("name", "")))
        rows = accounts()
        row = next((x for x in rows if x["name"] == name), None)
        if row is None:
            raise ValidationError("Xray account does not exist")
        action = params.get("action")
        if action == "delete":
            rows.remove(row)
        elif action == "renew":
            row["expiry"] = calculate_expiry(validate_days(params.get("days")), row["expiry"])
        elif action == "toggle" and isinstance(params.get("enabled"), bool):
            row["enabled"] = params["enabled"]
        else:
            raise ValidationError("Choose delete, renew or toggle with enabled")
        self.apply(settings(), rows)
        return {"name": name, "action": action}

    def export(self, params: dict) -> dict:
        domain = self.ready()
        cfg = settings()
        if not cfg["enabled"]:
            raise ValidationError("Xray is disabled")
        name = validate_username(str(params.get("name", "")))
        row = next((x for x in accounts() if x["name"] == name), None)
        if row is None or not active(row):
            raise ValidationError("Account is missing, disabled or expired")
        links = {p: share_link(p, row, domain) for p in row["protocols"]}
        text = "\n".join(links.values()) + "\n"
        files = {f"{name}-{p}.json": json.dumps(client_config(p, row, domain, cfg["dns"]), indent=2) + "\n" for p in row["protocols"]}
        files.update({f"{name}-{p}.txt": link + "\n" for p, link in links.items()})
        files.update({"links.txt": text, "subscription.txt": base64.b64encode(text.encode()).decode() + "\n"})
        running = self.health_probe()
        warnings = [] if running else ["The link is configured, but Xray is not currently ready. Enable/restart Xray and run diagnostics before connecting."]
        return {"name": name, "links": links, "files": files,
                "readiness": {"core_ready": running, "public_reachability": "not_checked", "warnings": warnings}}

    def sync(self, _: dict) -> dict:
        cfg = settings()
        if cfg["enabled"]:
            self.apply(cfg, accounts())
        return {"synced": True}
