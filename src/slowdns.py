"""Official DNSTT transports to managed SSH and private VLESS, with a shared UDP ingress."""
from __future__ import annotations

import grp
import ipaddress
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

from common import BASE_DIR, ValidationError, atomic_write_json, read_json, read_text, validate_domain

SETTINGS_FILE = BASE_DIR / "slowdns.json"
CONFIG_DIR = Path("/etc/abdulbasit-dnstt")
RUNTIME_FILE = CONFIG_DIR / "config.json"
PRIVATE_KEY = CONFIG_DIR / "server.key"
PUBLIC_KEY = CONFIG_DIR / "server.pub"
BINARY = Path("/usr/local/lib/abdulbasit/dnstt-server")


def settings():
    data = read_json(SETTINGS_FILE, None) if SETTINGS_FILE.exists() else {}
    if not isinstance(data, dict): raise RuntimeError("SlowDNS settings are invalid")
    return {"enabled": False, "zone": "", "ns_host": "", "port": 53, "mtu": 1232, "mode": "ssh", "xray_zone": "", **data}


def validate_mtu(value):
    try:
        mtu = int(str(value))
    except (ValueError, TypeError):
        raise ValidationError("DNSTT MTU must be a whole number")
    if not 512 <= mtu <= 1400:
        raise ValidationError("DNSTT MTU must be 512-1400; start with 1232")
    return mtu


def protect(path, mode=0o640):
    os.chmod(path, mode)
    try: os.chown(path, 0, grp.getgrnam("abdulbasit-dnstt").gr_gid)
    except KeyError: pass


class Manager:
    def __init__(self, run): self.run = run

    def owns_listener(self, output):
        if not output.strip():
            return False
        pid = self.run(["/bin/systemctl", "show", "abdulbasit-dnstt", "--property=MainPID", "--value"], timeout=5).stdout.strip()
        return pid.isdecimal() and int(pid) > 0 and bool(re.search(r"pid=" + re.escape(pid) + r"[,)]", output))

    def status(self, _):
        config = settings(); public = read_text(PUBLIC_KEY)
        key = public if re.fullmatch(r"[a-fA-F0-9]{64}", public) else ""
        tunnels = {}
        for kind in (("ssh", "xray") if config["mode"] == "both" else (config["mode"],)):
            zone = config["xray_zone"] if kind == "xray" and config["mode"] == "both" else config["zone"]
            local = 7000 if kind == "ssh" else 7001
            tunnels[kind] = {"zone": zone, "public_key": key, "local_port": local,
                "upstream": "127.0.0.1:109" if kind == "ssh" else "127.0.0.1:10006",
                "udp_command": f"dnstt-client -udp YOUR_DNS_RESOLVER:53 -pubkey {key} {zone} 127.0.0.1:{local}",
                "doh_command": f"dnstt-client -doh https://dns.google/dns-query -pubkey {key} {zone} 127.0.0.1:{local}",
                "dot_command": f"dnstt-client -dot dns.google:853 -pubkey {key} {zone} 127.0.0.1:{local}"}
        return {**config, "installed": BINARY.is_file(), "public_key": key, "tunnels": tunnels,
                "upstream": tunnels.get("ssh", tunnels.get("xray", {})).get("upstream"),
                "note": "SSH and VLESS use their managed account credentials. Both mode needs two distinct delegated zones on the same public UDP port. DNS tunnels cannot identify the client's public IP."}

    def configure(self, params):
        enabled = params.get("enabled")
        if not isinstance(enabled, bool): raise ValidationError("enabled must be a boolean")
        old = settings()
        if not enabled:
            self.run(["/bin/systemctl", "disable", "--now", "abdulbasit-dnstt"], timeout=15)
            atomic_write_json(SETTINGS_FILE, {**old, "enabled": False})
            if RUNTIME_FILE.exists():
                atomic_write_json(RUNTIME_FILE, {**old, "enabled": False}); protect(RUNTIME_FILE)
            return self.status({})
        zone = validate_domain(str(params.get("zone", old["zone"])))
        mode = params.get("mode", old["mode"])
        if mode not in {"ssh", "xray", "both"}:
            raise ValidationError("Choose ssh, xray or both DNS tunnel modes")
        xray_zone = str(params.get("xray_zone", old["xray_zone"]))
        if mode == "both":
            xray_zone = validate_domain(xray_zone)
            if zone == xray_zone or zone.endswith("." + xray_zone) or xray_zone.endswith("." + zone):
                raise ValidationError("SSH and Xray tunnel zones must be distinct and must not contain one another")
        mtu = validate_mtu(params.get("mtu", old["mtu"]))
        ns_host = validate_domain(str(params.get("ns_host", old["ns_host"])))
        if any(ns_host == z or ns_host.endswith("." + z) for z in ([zone, xray_zone] if mode == "both" else [zone])):
            raise ValidationError("Nameserver host must be outside the delegated tunnel zone")
        try: port = int(params.get("port", old["port"]))
        except (ValueError, TypeError): raise ValidationError("Invalid UDP port")
        if port not in range(1, 65536) or port in (80, 443, 109, 447, 2082, 9090, 10006, 53530, 53531):
            raise ValidationError("Choose a free UDP port, normally 53")
        if not BINARY.is_file():
            raise ValidationError("Install the official dnstt core first: bash scripts/install-dnstt.sh")
        for node in (CONFIG_DIR, PRIVATE_KEY, PUBLIC_KEY, RUNTIME_FILE):
            if node.is_symlink(): raise ValidationError("Symlinked SlowDNS configuration paths are not allowed")
        output = self.run([shutil.which("ss") or "/usr/bin/ss", "-Hlunp", f"sport = :{port}"], timeout=5).stdout
        if output.strip() and not self.owns_listener(output):
            raise ValidationError("UDP port is occupied. Keep the existing DNS resolver and choose another port or address arrangement.")
        CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o750); protect(CONFIG_DIR, 0o750)
        if not PRIVATE_KEY.exists():
            self.run([str(BINARY), "-gen-key", "-privkey-file", str(PRIVATE_KEY), "-pubkey-file", str(PUBLIC_KEY)], timeout=10)
        if not re.fullmatch(r"[a-fA-F0-9]{64}", read_text(PUBLIC_KEY)):
            raise RuntimeError("dnstt public key is missing or invalid")
        protect(PRIVATE_KEY); protect(PUBLIC_KEY, 0o644)
        config = {"enabled": True, "zone": zone, "ns_host": ns_host, "port": port, "mtu": mtu, "mode": mode, "xray_zone": xray_zone}
        previous_runtime = read_json(RUNTIME_FILE, None)
        atomic_write_json(RUNTIME_FILE, config); protect(RUNTIME_FILE)
        try:
            self.run(["/bin/systemctl", "restart", "abdulbasit-dnstt"], timeout=20)
            # Type=simple becomes active before Python reads config and execs
            # dnstt. Keep that config intact until the listener is ready.
            deadline = time.monotonic() + 10
            while True:
                self.run(["/bin/systemctl", "is-active", "--quiet", "abdulbasit-dnstt"], timeout=5)
                listener = self.run([shutil.which("ss") or "/usr/bin/ss", "-Hlunp", f"sport = :{port}"], timeout=5).stdout
                if self.owns_listener(listener): break
                if time.monotonic() >= deadline:
                    raise RuntimeError("dnstt did not open its UDP listener within 10 seconds; inspect journalctl -u abdulbasit-dnstt")
                time.sleep(0.1)
            self.run(["/bin/systemctl", "enable", "abdulbasit-dnstt"], timeout=10)
            atomic_write_json(SETTINGS_FILE, config)
        except Exception:
            if previous_runtime is None: RUNTIME_FILE.unlink(missing_ok=True)
            else: atomic_write_json(RUNTIME_FILE, previous_runtime); protect(RUNTIME_FILE)
            try: self.run(["/bin/systemctl", "restart", "abdulbasit-dnstt"] if old["enabled"] else ["/bin/systemctl", "disable", "--now", "abdulbasit-dnstt"], timeout=15)
            except RuntimeError: pass
            raise
        return self.status({})

    def check(self, _):
        data = self.status({})
        checks = {kind: self.check_zone({**data, "zone": tunnel["zone"]}) for kind, tunnel in data["tunnels"].items()}
        if "xray" in checks:
            checks["xray"].pop("ssh_command", None)
            checks["xray"]["client_command"] = data["tunnels"]["xray"]["udp_command"]
        primary = checks.get("ssh", checks.get("xray", {}))
        return {**primary, **data, "dns_ok": bool(checks) and all(row["dns_ok"] for row in checks.values()), "delegations": checks}

    def check_zone(self, data):
        if not data["zone"]: return {**data, "dns_ok": False, "records": [], "hint": "Configure the tunnel zone and nameserver hostname first"}
        dig = shutil.which("dig") or "/usr/bin/dig"
        # DNSTT is not a general-purpose authoritative DNS server. Query the
        # parent authorities directly, where the delegation referral lives.
        authorities = []
        labels = data["zone"].split(".")
        for i in range(1, len(labels)):
            parent = ".".join(labels[i:])
            output = self.run([dig, "+time=2", "+tries=1", "+short", "NS", parent], timeout=6).stdout
            authorities = [validate_domain(x.rstrip(".")) for x in output.splitlines() if x.strip()][:8]
            if authorities:
                break
        records, checks = [], []
        for ns in authorities:
            try:
                output = self.run([dig, "@" + ns, data["zone"], "NS", "+norecurse", "+time=2", "+tries=1", "+noall", "+answer", "+authority"], timeout=6).stdout
                found = []
                for line in output.splitlines():
                    fields = line.split()
                    if len(fields) >= 5 and fields[0].rstrip(".").lower() == data["zone"] and fields[3] == "NS":
                        found.append(fields[4].rstrip(".").lower())
                records.extend(found)
                checks.append({"nameserver": ns, "ok": data["ns_host"] in found, "records": found})
            except (RuntimeError, OSError):
                checks.append({"nameserver": ns, "ok": False, "records": []})
        addresses = []
        for family in ("A", "AAAA"):
            output = self.run([dig, "+time=2", "+tries=1", "+short", family, data["ns_host"]], timeout=6).stdout
            for line in output.splitlines():
                try:
                    addresses.append(str(ipaddress.ip_address(line)))
                except ValueError:
                    continue
        delegated = bool(checks) and all(x["ok"] for x in checks)
        return {**data, "records": sorted(set(records)), "authoritative_checks": checks,
                "nameserver_addresses": addresses, "dns_ok": delegated and bool(addresses),
                "client_command": f"dnstt-client -udp YOUR_DNS_RESOLVER:53 -pubkey {data['public_key']} {data['zone']} 127.0.0.1:7000",
                "ssh_command": "ssh -p 7000 YOUR_MANAGED_SSH_USER@127.0.0.1",
                "hint": ("Parent NS delegation and nameserver address found. Compare its IP with this VPS and test a real client externally; UDP reachability is not proven." if delegated and addresses else
                         f"Set {data['ns_host']} A/AAAA to this VPS and delegate {data['zone']} with an NS record. Parent authorities must agree.")}



def serve():
    config = read_json(RUNTIME_FILE, {})
    zone = validate_domain(str(config.get("zone", "")))
    if config.get("enabled") is not True: raise RuntimeError("SlowDNS is disabled")
    port = int(config["port"])
    if not 1 <= port <= 65535: raise RuntimeError("Invalid listener port")
    mode = config.get("mode", "ssh")
    if mode == "both":
        import dns_router
        validate_domain(config["xray_zone"])
        dns_router.serve(BINARY, PRIVATE_KEY, config)
        return
    if mode not in {"ssh", "xray"}:
        raise RuntimeError("Invalid DNS tunnel mode")
    upstream = "127.0.0.1:109" if mode == "ssh" else "127.0.0.1:10006"
    os.execv(str(BINARY), [str(BINARY), "-udp", f"0.0.0.0:{port}", "-mtu", str(validate_mtu(config.get("mtu", 1232))), "-privkey-file", str(PRIVATE_KEY), zone, upstream])


if __name__ == "__main__" and sys.argv[1:] == ["serve"]:
    serve()
