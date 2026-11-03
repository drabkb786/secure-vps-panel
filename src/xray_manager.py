"""Managed Xray WS/TLS profiles, transactional config changes and client exports.

Nginx terminates TLS; all three Xray inbounds are loopback-only. Existing
independent xray.service installations/configs are never overwritten.
"""
from __future__ import annotations

import base64
import grp
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
import uuid
from datetime import date, datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

from client_formats import clash_config, singbox_config
import cdn_manager
import profile_backup
import traffic
import gateway_identity

from common import (BASE_DIR, DOMAIN_FILE, ValidationError, atomic_write,
                    atomic_write_json, calculate_expiry, read_json, read_text,
                    validate_days, validate_domain, validate_username, validate_quota,
                    validate_max_ips, quota_bytes)

SETTINGS_FILE = BASE_DIR / "network.json"
ACCOUNTS_FILE = BASE_DIR / "xray_accounts.json"
CONFIG_DIR = Path("/etc/abdulbasit-xray")
CONFIG_FILE = CONFIG_DIR / "config.json"
ENABLED_FILE = CONFIG_DIR / "enabled"
CERT_ROOT = Path("/etc/letsencrypt/live")
XRAY_BINARY = Path("/usr/local/lib/abdulbasit/xray")
BACKUP_DIR = BASE_DIR / "backups"
XHTTP_PORT, XHTTP_PATH = 10004, "/xhttp/"
PROTOCOLS = {"vless": (10001, "/vless"), "vmess": (10002, "/vmess"), "trojan": (10003, "/trojan")}
DEFAULT_DNS = {"servers": ["1.1.1.1", "8.8.8.8"], "query_strategy": "UseIPv4"}
MAX_ACCOUNTS = 200


def settings() -> dict:
    data = read_json(SETTINGS_FILE, None) if SETTINGS_FILE.exists() else {}
    if not isinstance(data, dict):
        raise RuntimeError("Network settings are unreadable or invalid; restore a known-good backup")
    return {"enabled": False, "xhttp_enabled": False, "udp_enabled": True, "dns": dict(DEFAULT_DNS), **data}


def accounts(*, hydrate=True) -> list[dict]:
    data = read_json(ACCOUNTS_FILE, None) if ACCOUNTS_FILE.exists() else []
    if not isinstance(data, list):
        raise RuntimeError("Xray account store is invalid; restore its backup")
    return traffic.hydrate(data) if hydrate else data


def active(account: dict, today: date | None = None) -> bool:
    try:
        eligible = account.get("enabled", True) is True and not quota_exhausted(account) and not account.get("meter_unavailable") and not account.get("ip_monitoring_failed")
        if account.get("ip_blocked_until"):
            eligible = eligible and datetime.fromisoformat(account["ip_blocked_until"]) <= datetime.now(timezone.utc)
        if account.get("expires_at"):
            return eligible and datetime.fromisoformat(account["expires_at"]) > datetime.now(timezone.utc)
        return eligible and date.fromisoformat(account["expiry"]) > (today or date.today())
    except (KeyError, ValueError, TypeError):
        return False


def quota_exhausted(account: dict) -> bool:
    limit = quota_bytes(account)
    return limit is not None and int(account.get("used_bytes", 0)) >= limit


def public_account(account: dict) -> dict:
    fields = {"name", "protocols", "enabled", "expiry", "created_at", "expires_at", "trial", "quota_gb", "used_bytes", "upload_bytes", "download_bytes", "max_ips", "online_ips", "ip_blocked_until", "ip_monitoring_failed", "meter_unavailable"}
    return {k: v for k, v in account.items() if k in fields} | {
        "active": active(account), "quota_exhausted": quota_exhausted(account), "subscription_enabled": bool(account.get("subscription_hash")),
        "quota_unit": account.get("quota_unit", "GiB"), "quota_bytes": quota_bytes(account),
        "exact_bytes": {k: str(account.get(k, 0)) for k in ("used_bytes", "upload_bytes", "download_bytes")}}


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
            client = {"email": f"{row['uuid']}-{protocol}@noway.local", "level": 0}
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
            "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": gateway_identity.backend_path(protocol)},
                               "sockopt": {"trustedXForwardedFor": [gateway_identity.header_name()]}},
        })
    if config.get("xhttp_enabled"):
        clients = [{"id": row["uuid"], "email": f"{row['uuid']}-xhttp@noway.local"} for row in rows if active(row) and "vless" in row["protocols"]]
        inbounds.append({"tag": "noway-xhttp", "listen": "127.0.0.1", "port": XHTTP_PORT,
                         "protocol": "vless", "settings": {"clients": clients, "decryption": "none"},
                         "streamSettings": {"network": "xhttp", "security": "none", "xhttpSettings": {"path": gateway_identity.backend_path("xhttp"), "mode": "auto"},
                                            "sockopt": {"trustedXForwardedFor": [gateway_identity.header_name()]}}})
    return {
        "log": {"loglevel": "warning"},
        "api": {"tag": "noway-stats", "listen": str(traffic.API_SOCKET), "services": ["StatsService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True, "statsUserOnline": True}}},
        "dns": {"servers": dns["servers"], "queryStrategy": dns["query_strategy"]},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {"domainStrategy": dns["query_strategy"]}}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        # Block private/link-local targets, including metadata services, after DNS resolution.
        "routing": {"domainStrategy": "IPOnDemand", "rules": ([] if config.get("udp_enabled", True) else [{"type": "field", "network": "udp", "outboundTag": "block"}]) + [{
            "type": "field", "ip": ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"], "outboundTag": "block",
        }]},
    }


def client_config(protocol: str, row: dict, domain: str, dns: dict, prefix: str = "") -> dict:
    xhttp = protocol == "vless-xhttp"
    protocol = "vless" if xhttp else protocol
    _, path = PROTOCOLS[protocol]
    path = prefix + path
    credential = {"password": row["trojan_password"]} if protocol == "trojan" else {"id": row["uuid"], "encryption": "none"} if protocol == "vless" else {"id": row["uuid"], "security": "auto", "alterId": 0}
    proxy_settings = {"servers": [{"address": domain, "port": 443, **credential}]} if protocol == "trojan" else {"vnext": [{"address": domain, "port": 443, "users": [credential]}]}
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": dns["servers"], "queryStrategy": dns["query_strategy"]},
        "inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{
            "tag": "proxy", "protocol": protocol, "settings": proxy_settings,
            "streamSettings": {
                "network": "xhttp" if xhttp else "ws", "security": "tls",
                "tlsSettings": {"serverName": domain, "allowInsecure": False, "alpn": ["h2"] if xhttp else ["http/1.1"]},
                **({"xhttpSettings": {"path": XHTTP_PATH, "host": domain, "mode": "packet-up"}} if xhttp else {"wsSettings": {"path": path, "host": domain, **({"heartbeatPeriod": 25} if prefix else {})}}),
            },
        }],
    }


def share_link(protocol: str, row: dict, domain: str, prefix: str = "") -> str:
    xhttp = protocol == "vless-xhttp"
    if protocol not in PROTOCOLS and not xhttp:
        raise ValidationError("Choose vless, vmess or trojan")
    domain = validate_domain(domain)
    label = f"NOWAY-{row['name']}-{protocol.upper()}"
    protocol = "vless" if xhttp else protocol
    _, path = PROTOCOLS[protocol]
    path = prefix + path
    if protocol == "vmess":
        data = {"v": "2", "ps": label, "add": domain, "port": "443", "id": row["uuid"], "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": domain, "path": path, "tls": "tls", "sni": domain, "alpn": "http/1.1"}
        return "vmess://" + base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()
    credential = row["trojan_password"] if protocol == "trojan" else row["uuid"]
    query = {"security": "tls", "type": "ws", "host": domain, "sni": domain, "path": path, "alpn": "http/1.1"}
    if xhttp:
        query.update({"type": "xhttp", "path": XHTTP_PATH, "mode": "packet-up", "alpn": "h2"})
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
            ports = [p for p, _ in PROTOCOLS.values()] + ([XHTTP_PORT] if settings().get("xhttp_enabled") else [])
            for port in ports:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    pass
            with socket.socket(socket.AF_UNIX) as stats_socket:
                stats_socket.settimeout(0.3); stats_socket.connect(str(traffic.API_SOCKET))
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

    def api(self, command, *args):
        result = self.run([str(XRAY_BINARY), "api", command, "--server=" + traffic.API_ADDRESS, "-t=2", *args], timeout=4)
        return json.loads(result.stdout)

    def collect_usage(self, _=None):
        if not settings()["enabled"]:
            return {"available": False, "reason": "Xray is disabled"}
        try:
            for attempt in range(2):
                epoch = self.epoch()
                response = self.api("statsquery", "-pattern=user>>>")
                if epoch == self.epoch():
                    break
            else:
                raise RuntimeError("Core restarted during statistics sampling")
            rows = accounts(); data = traffic.accumulate(rows, response, epoch)
        except (RuntimeError, OSError, AttributeError, ValueError, TypeError, subprocess.TimeoutExpired):
            return {"available": False, "reason": "Statistics unavailable or inconsistent; saved totals retained", "sample_interval_seconds": traffic.SAMPLE_SECONDS}
        # One authoritative atomic counter file prevents duplicate counting if a
        # crash happens between persisting totals and refreshing account metadata.
        atomic_write_json(traffic.STATE_FILE, data)
        atomic_write_json(ACCOUNTS_FILE, rows)
        return {"available": True, "sampled_at": data["sampled_at"], "accounts": [public_account(x) for x in rows],
                "sample_interval_seconds": traffic.SAMPLE_SECONDS, "counter_discontinuities": data.get("counter_discontinuities", 0),
                "note": "Integer Xray payload bytes. Target sampling interval: 5 seconds plus query/restart time. Polling can overshoot quotas; uncheckpointed bytes can be lost on a core crash. GB = 1,000,000,000 bytes; GiB = 1,073,741,824 bytes."}

    def epoch(self):
        epoch = self.run(["/bin/systemctl", "show", "abdulbasit-xray", "--property=InvocationID", "--value"], timeout=3).stdout.strip()
        if not re.fullmatch(r"[a-fA-F0-9]{32}", epoch) or int(epoch, 16) == 0:
            raise RuntimeError("Xray instance ID is unavailable")
        return epoch

    def online(self, _):
        try:
            epoch = self.epoch()
            connections = traffic.ip_rows(self.api("statsonlineiplist", "-all"))
            if epoch != self.epoch():
                raise RuntimeError("Core restarted during IP sampling")
            rows = accounts()
            names = {email: row["name"] for row in rows for email in traffic.emails(row)}
            for item in connections:
                item["name"] = names.get(item["email"], "unmanaged")
            return {"available": True, "connections": connections,
                    "profiles": traffic.profile_ips(rows, connections),
                    "note": "Unique source IPs of active authenticated streams, combined across protocols. NAT/shared Wi-Fi counts as one IP; this is not a device count."}
        except (RuntimeError, OSError, AttributeError, ValueError, subprocess.TimeoutExpired):
            return {"available": False, "connections": [], "note": "Xray online API unavailable"}

    def apply(self, config: dict, rows: list[dict], *, force_restart: bool = False) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o750)
        os.chmod(CONFIG_DIR, 0o750)
        try:
            gid = grp.getgrnam("abdulbasit-xray").gr_gid
            os.chown(CONFIG_DIR, 0, gid)
        except KeyError:
            gid = None
        text = json.dumps(server_config(config, rows), indent=2) + "\n"
        old = {p: p.read_text() if p.exists() else None for p in (CONFIG_FILE, SETTINGS_FILE, ACCOUNTS_FILE, ENABLED_FILE)}
        changed = force_restart or text != old[CONFIG_FILE] or config["enabled"] != settings()["enabled"]
        if not changed:
            atomic_write_json(SETTINGS_FILE, config)
            atomic_write_json(ACCOUNTS_FILE, rows)
            return
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
                traffic.new_epoch()
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
                    self.run(["/bin/systemctl", "restart" if old[ENABLED_FILE] is not None else "stop", "abdulbasit-xray"], timeout=30)
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
        endpoints = [{"protocol": p, "port": 443, "path": v[1], "transport": "ws+tls"} for p, v in PROTOCOLS.items()]
        if cfg.get("xhttp_enabled"):
            endpoints.append({"protocol": "vless-xhttp", "port": 443, "path": XHTTP_PATH, "transport": "xhttp+tls"})
        return {"network": cfg, "xray_installed": XRAY_BINARY.is_file(), "accounts": [public_account(x) for x in accounts()],
                "endpoints": endpoints}

    def configure(self, params: dict) -> dict:
        enabled = params.get("enabled")
        if not isinstance(enabled, bool):
            raise ValidationError("enabled must be a boolean")
        self.collect_usage()
        cfg = settings()
        cfg["enabled"] = enabled
        if "xhttp_enabled" in params:
            if not isinstance(params["xhttp_enabled"], bool):
                raise ValidationError("xhttp_enabled must be a boolean")
            cfg["xhttp_enabled"] = params["xhttp_enabled"]
        if "udp_enabled" in params:
            if not isinstance(params["udp_enabled"], bool):
                raise ValidationError("udp_enabled must be a boolean")
            cfg["udp_enabled"] = params["udp_enabled"]
        # Explicit enable/disable must act even when the saved settings are unchanged.
        self.apply(cfg, accounts(), force_restart=True)
        return self.status({})

    def set_dns(self, params: dict) -> dict:
        self.collect_usage()
        cfg = settings()
        cfg["dns"] = validate_dns(params)
        if cfg["enabled"]:
            self.apply(cfg, accounts())
        else:
            atomic_write_json(SETTINGS_FILE, cfg)
        return {"dns": cfg["dns"], "scope": "Xray server and exported client profiles"}

    def create(self, params: dict) -> dict:
        if "trial" in params and not isinstance(params["trial"], bool):
            raise ValidationError("trial must be a boolean")
        domain = self.ready()
        if not settings()["enabled"]:
            raise ValidationError("Enable Xray first")
        self.collect_usage()
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
               "created_at": datetime.now(timezone.utc).isoformat(), "quota_gb": validate_quota(params.get("quota_gb", "Unlimited")),
               "quota_unit": "GB", "max_ips": validate_max_ips(params.get("max_ips", 0)),
               "used_bytes": 0, "upload_bytes": 0, "download_bytes": 0}
        if params.get("trial") is True:
            row.update(trial=True, expires_at=(datetime.now(timezone.utc) + timedelta(hours=24)).isoformat())
        self.apply(settings(), rows + [row])
        return {"account": public_account(row), "links": self.profile_links(row, domain, settings())}

    @staticmethod
    def profile_links(row: dict, domain: str, config: dict, prefix: str = "") -> dict:
        variants = list(row["protocols"])
        if not prefix and config.get("xhttp_enabled") and "vless" in variants:
            variants.append("vless-xhttp")
        return {p: share_link(p, row, domain, prefix) for p in variants}

    def update(self, params: dict) -> dict:
        self.collect_usage()
        old_traffic = None
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
            row.pop("expires_at", None); row.pop("trial", None)
        elif action == "toggle" and isinstance(params.get("enabled"), bool):
            row["enabled"] = params["enabled"]
        elif action in {"quota", "limits"}:
            row["quota_gb"] = validate_quota(params.get("quota_gb", "Unlimited"))
            row["quota_unit"] = params.get("quota_unit", row.get("quota_unit", "GiB"))
            quota_bytes(row)
            if action == "limits":
                row["max_ips"] = validate_max_ips(params.get("max_ips", 0))
                if not row["max_ips"]:
                    row.pop("ip_blocked_until", None); row.pop("ip_monitoring_failed", None)
            if row["quota_gb"] is None:
                row.pop("meter_unavailable", None)
        elif action == "reset_usage":
            if self.collect_usage().get("available") is not True:
                raise ValidationError("Start Xray statistics before resetting usage so the baseline can be preserved")
            row.update(used_bytes=0, upload_bytes=0, download_bytes=0)
            old_traffic = traffic.STATE_FILE.read_text() if traffic.STATE_FILE.exists() else None
            traffic.reset_profile(row)
        else:
            raise ValidationError("Choose delete, renew, toggle, quota, limits or reset_usage")
        try:
            self.apply(settings(), rows)
        except Exception:
            if action == "reset_usage":
                if old_traffic is None: traffic.STATE_FILE.unlink(missing_ok=True)
                else: atomic_write(traffic.STATE_FILE, old_traffic)
            raise
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
        route = params.get("route", "direct")
        domain, prefix = cdn_manager.delivery(route, domain)
        links = self.profile_links(row, domain, cfg, prefix)
        text = "\n".join(links.values()) + "\n"
        files = {f"{name}-{p}.json": json.dumps(client_config(p, row, domain, cfg["dns"], prefix), indent=2) + "\n" for p in links}
        files[f"{name}-singbox.json"] = json.dumps(singbox_config(row, domain, prefix), indent=2) + "\n"
        files[f"{name}-clash.yaml"] = json.dumps(clash_config(row, domain, prefix), indent=2) + "\n"
        files.update({f"{name}-{p}.txt": link + "\n" for p, link in links.items()})
        files.update({"links.txt": text, "subscription.txt": base64.b64encode(text.encode()).decode() + "\n"})
        running = self.health_probe()
        warnings = [] if running else ["The link is configured, but Xray is not currently ready. Enable/restart Xray and run diagnostics before connecting."]
        if prefix:
            warnings.append("CloudFront delivery: run endpoint checks and a real client transfer; AWS deployment and speed are not verified by this export.")
        return {"name": name, "route": route, "links": links, "files": files,
                "readiness": {"core_ready": running, "public_reachability": "not_checked", "warnings": warnings}}

    def subscription_rotate(self, params: dict) -> dict:
        name = validate_username(str(params.get("name", "")))
        domain = self.ready()
        rows = accounts()
        row = next((x for x in rows if x["name"] == name), None)
        if row is None or not active(row):
            raise ValidationError("Profile is missing, disabled or expired")
        token = secrets.token_urlsafe(32)
        row["subscription_hash"] = hashlib.sha256(token.encode()).hexdigest()
        row["subscription_issued_at"] = datetime.now(timezone.utc).isoformat()
        atomic_write_json(ACCOUNTS_FILE, rows)
        url = f"https://{domain}/panel/sub/{token}"
        return {"name": name, "url": url, "cloudfront_url": url + "?route=cloudfront", "formats": {p: url + "?format=" + p for p in ("base64", "plain", "xray", "clash", "singbox")},
                "notice": "This URL is shown once. Rotation revokes the old URL; previously downloaded proxy credentials are unchanged."}

    def subscription_revoke(self, params: dict) -> dict:
        name = validate_username(str(params.get("name", "")))
        rows = accounts()
        row = next((x for x in rows if x["name"] == name), None)
        if row is None:
            raise ValidationError("Profile does not exist")
        row.pop("subscription_hash", None); row.pop("subscription_issued_at", None)
        atomic_write_json(ACCOUNTS_FILE, rows)
        return {"name": name, "revoked": True}

    def subscription_get(self, params: dict) -> dict:
        token = params.get("token", "")
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise ValidationError("Subscription unavailable")
        digest = hashlib.sha256(token.encode()).hexdigest()
        row = next((x for x in accounts() if hmac.compare_digest(x.get("subscription_hash", ""), digest)), None)
        cfg = settings()
        if row is None or not active(row) or not cfg["enabled"]:
            raise ValidationError("Subscription unavailable")
        domain = validate_domain(read_text(DOMAIN_FILE))
        format_name = params.get("format", "base64")
        route = params.get("route", "direct")
        domain, prefix = cdn_manager.delivery(route, domain)
        links = self.profile_links(row, domain, cfg, prefix)
        plain = "\n".join(links.values()) + "\n"
        if format_name in ("plain", "base64"):
            content = plain if format_name == "plain" else base64.b64encode(plain.encode()).decode() + "\n"
            mime = "text/plain; charset=utf-8"
        elif format_name == "xray":
            content = json.dumps([client_config(p, row, domain, cfg["dns"], prefix) for p in links], indent=2)
            mime = "application/json"
        elif format_name in ("clash", "singbox"):
            content = json.dumps((clash_config if format_name == "clash" else singbox_config)(row, domain, prefix), indent=2)
            mime = "text/yaml; charset=utf-8" if format_name == "clash" else "application/json"
        else:
            raise ValidationError("Unsupported subscription format")
        return {"content": content, "content_type": mime, "name": row["name"], "expiry": row["expiry"],
                "expires_at": row.get("expires_at"), "traffic": {"upload": row.get("upload_bytes", 0), "download": row.get("download_bytes", 0),
                    "total": quota_bytes(row) or 0}}

    def backup_export(self, _: dict) -> dict:
        return {"backup": profile_backup.build(settings(), accounts(), read_text(DOMAIN_FILE))}

    def backup_restore(self, params: dict) -> dict:
        data = params.get("backup")
        if len(json.dumps(data).encode()) > profile_backup.MAX_BYTES:
            raise ValidationError("Backup exceeds 256 KiB")
        network, rows = profile_backup.validate(data, validate_dns)
        try:
            self.collect_usage()
        except RuntimeError:
            pass  # Valid-backup recovery must also work with corrupt metadata.
        path = BACKUP_DIR / f"xray-before-restore-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}.json"
        try:
            recovery = self.backup_export({})["backup"]
        except RuntimeError:
            # Corrupt metadata must not prevent recovery. This forensic snapshot
            # is intentionally a different schema and cannot be imported as a backup.
            recovery = {"schema": "noway-xray-raw-recovery-v1", "files": {
                p.name: p.read_text() if p.exists() else None
                for p in (SETTINGS_FILE, ACCOUNTS_FILE, CONFIG_FILE, ENABLED_FILE)}}
        atomic_write_json(path, recovery)
        previous_traffic = traffic.STATE_FILE.read_text() if traffic.STATE_FILE.exists() else None
        if previous_traffic is not None:
            atomic_write(path.with_suffix(".traffic.raw"), previous_traffic)
        atomic_write_json(traffic.STATE_FILE, {"totals": {x["uuid"]: {k: int(x.get(k, 0)) for k in ("upload_bytes", "download_bytes")} for x in rows}, "counters": {}})
        try:
            self.apply(network, rows, force_restart=True)
        except Exception:
            if previous_traffic is None: traffic.STATE_FILE.unlink(missing_ok=True)
            else: atomic_write(traffic.STATE_FILE, previous_traffic)
            raise
        return {"restored": len(rows), "rollback_backup": str(path), "domain": read_text(DOMAIN_FILE),
                "notice": "Restored Xray profiles/settings only. Current domain, SSH accounts, certificates, web login and bot token were preserved."}

    def sync(self, _: dict) -> dict:
        cfg = settings()
        if cfg["enabled"]:
            sample = self.collect_usage()
            online = self.online({})
            try:
                rows = accounts()
            except RuntimeError:
                self.run(["/bin/systemctl", "stop", "abdulbasit-xray"], timeout=30)
                raise RuntimeError("Accounting state is corrupt; managed Xray stopped. Restore a valid backup before resuming access.")
            now = datetime.now(timezone.utc)
            for row in rows:
                row["meter_unavailable"] = quota_bytes(row) is not None and not sample["available"]
                limit = validate_max_ips(row.get("max_ips", 0))
                row["ip_monitoring_failed"] = bool(limit and not online["available"])
                if online["available"]:
                    row["online_ips"] = online["profiles"].get(row["name"], [])
                    if limit and len(row["online_ips"]) > limit:
                        row["ip_blocked_until"] = (now + timedelta(seconds=30)).isoformat()
                    elif row.get("ip_blocked_until") and datetime.fromisoformat(row["ip_blocked_until"]) <= now:
                        row.pop("ip_blocked_until", None)
                else:
                    row.pop("online_ips", None)
            self.apply(cfg, rows)
        return {"synced": True}
