"""Bounded, read-only diagnostics for the managed services and domain."""
from __future__ import annotations

import ipaddress
from contextlib import ExitStack
import shutil
import socket
import ssl
import subprocess
import time
from pathlib import Path

from common import SSH_UPGRADE_PATHS, DOMAIN_FILE, ValidationError, read_text, validate_domain
from xray_manager import CONFIG_FILE, PROTOCOLS, XRAY_BINARY, settings


def command(args: list[str], timeout: int = 8) -> tuple[bool, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode == 0, (p.stdout + p.stderr).strip()[-1800:]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, type(exc).__name__


def dns_lookup(params: dict) -> dict:
    domain = validate_domain(str(params.get("domain") or read_text(DOMAIN_FILE)))
    records = {}
    dig = shutil.which("dig")
    if not dig:
        raise RuntimeError("dig is missing; install the dnsutils package")
    for family in ("A", "AAAA"):
        ok, output = command([dig, "+time=2", "+tries=1", "+short", domain, family])
        addresses = []
        for line in output.splitlines():
            try:
                addresses.append(str(ipaddress.ip_address(line.strip())))
            except ValueError:
                continue
        records[family] = addresses
        if not ok:
            records[family + "_error"] = output
    return {"domain": domain, "records": records,
            "note": "Point A/AAAA records at this VPS. DNS provider records are managed at the provider; an incorrect AAAA record can break IPv6 clients."}


def ssh_upgrade(domain: str, port: int, tls: bool = False, timeout: float = 3, *,
                path: str = '/ssh/raw') -> tuple[bool, str]:
    """Read a bounded local HTTP Upgrade and SSH identification, not a login.

    Coalesced headers/banner and split TCP reads must produce the same result.
    The connection address is fixed loopback; Host/SNI uses the configured domain.
    """
    try:
        if path not in SSH_UPGRADE_PATHS:
            raise ValueError("Unsupported SSH Upgrade path")
        domain = validate_domain(domain)
        deadline = time.monotonic() + timeout
        with ExitStack() as stack:
            peer = stack.enter_context(socket.create_connection(('127.0.0.1', port), timeout=timeout))
            if tls:
                peer.settimeout(max(.01, deadline - time.monotonic()))
                peer = stack.enter_context(ssl.create_default_context().wrap_socket(peer, server_hostname=domain))
            peer.sendall((f'GET {path} HTTP/1.1\r\nHost: {domain}\r\n'
                          'Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n').encode())
            received = bytearray()
            while len(received) < 16384:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Waiting for HTTP Upgrade and SSH identification')
                peer.settimeout(remaining)
                chunk = peer.recv(min(4096, 16384 - len(received)))
                if not chunk:
                    raise ConnectionError('EOF before a complete HTTP Upgrade and SSH banner')
                received.extend(chunk)
                if b'\r\n\r\n' not in received:
                    continue
                head, body = bytes(received).split(b'\r\n\r\n', 1)
                lines = head.split(b'\r\n')
                status = lines[0].decode('ascii', errors='replace')
                fields = dict(line.lower().split(b':', 1) for line in lines[1:] if b':' in line)
                parts = status.split()
                if len(parts) < 2 or parts[0] not in ('HTTP/1.0', 'HTTP/1.1') or parts[1] != '101':
                    raise ValueError('Expected HTTP 101, received ' + status[:160])
                if (fields.get(b'upgrade', b'').strip() != b'websocket'
                        or b'upgrade' not in {value.strip() for value in fields.get(b'connection', b'').split(b',')}):
                    raise ValueError('HTTP 101 is missing valid Upgrade/Connection headers')
                if b'\n' in body:
                    banner = body.split(b'\n', 1)[0].rstrip(b'\r')
                    if not banner.startswith(b'SSH-2.0-') or len(banner) > 255:
                        raise ValueError('No valid SSH identification after HTTP 101')
                    return True, 'HTTP 101; ' + banner.decode('ascii', errors='replace')
                if len(body) > 255:
                    raise ValueError('SSH identification exceeds the limit')
        raise ValueError('HTTP/SSH response exceeds the limit')
    except (OSError, ValueError) as exc:
        return False, type(exc).__name__ + ': ' + str(exc)[:180]


def listener_detail(port: int) -> str:
    ok, rows = command([shutil.which("ss") or "/usr/bin/ss", "-H", "-ltnp",
                        "sport", "=", f":{port}"], timeout=2)
    if not ok:
        return f"Could not inspect TCP listener :{port} ({rows})"
    return rows or f"No local TCP listener on :{port}"


def report(_: dict) -> dict:
    checks = []
    def add(name, ok, detail, hint=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail, "hint": hint if not ok else ""})
    ok, detail = command([shutil.which("nginx") or "/usr/sbin/nginx", "-t"])
    add("Nginx configuration", ok, detail, "Resolve the reported config conflict before reloading Nginx.")
    import ssh_backend
    backend = ssh_backend.name()
    ok, detail = command(["/usr/sbin/sshd", "-V"] if backend == "openssh" else [ssh_backend.dropbear_binary(), "-V"])
    add(f"{backend} binary", ok, detail, f"Install/update the distribution's maintained {'openssh-server' if backend == 'openssh' else 'dropbear'} package.")
    for port in (109, 447):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as peer:
                peer.settimeout(2)
                banner = peer.recv(255).split(b"\n", 1)[0].decode("ascii", errors="replace").strip()
            ok = banner.startswith("SSH-2.0-OpenSSH_" if backend == "openssh" else "SSH-2.0-dropbear_")
        except OSError as exc:
            ok, banner = False, type(exc).__name__
        add(f"{backend} SSH greeting :{port}", ok, banner, "Check abdulbasit-sshd and /etc/abdulbasit-sshd/sshd_config." if backend == "openssh" else "Check Dropbear status, its systemd unit and listener conflicts.")
    import ssh_sessions as dropbear_sessions
    sessions = dropbear_sessions.snapshot()
    add("SSH session attribution", sessions["journal_ok"] and not sessions["unattributed_root_processes"],
        f"{sum(len(p) for p in sessions['sessions'].values())} authenticated managed sessions; "
        f"{sessions['unattributed_root_processes']} unattributed root connections (may be pre-authentication)",
        "Check managed account metadata and trusted SSH cgroup ancestry." if backend == "openssh" else "Older Dropbear builds need readable systemd authentication journals; missing/rotated records can leave sessions uncounted.")
    ports = {"SSH upgrade proxy": 2082, "Web dashboard": 9090}
    if ssh_backend.haproxy_enabled():
        ok, detail = command(["/usr/sbin/haproxy", "-c", "-f", "/etc/abdulbasit-haproxy/haproxy.cfg"])
        add("HAProxy configuration", ok, detail, "Inspect abdulbasit-haproxy and its managed configuration")
        ok, detail = command(["systemctl", "is-active", ssh_backend.HAPROXY_UNIT])
        add("HAProxy public gateway", ok, detail, "Inspect journalctl -u abdulbasit-haproxy")
        ports.update({"Private Nginx HTTP": 8080, "Private Nginx TLS": 8081})
    if settings()["enabled"]:
        ports.update({p.upper(): value[0] for p, value in PROTOCOLS.items()})
        if settings().get("vless_non_tls_enabled"):
            ports["VLESS Encryption non-TLS"] = 10005
        if settings().get("dns_tunnel_enabled"):
            ports["Private VLESS DNS"] = 10006
        if settings().get("xhttp_enabled"):
            ports["VLESS XHTTP"] = 10004
    for name, port in ports.items():
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                ok = True
        except OSError:
            ok = False
        add(name, ok, f"127.0.0.1:{port}", "Check its systemd service and port conflicts; do not expose this internal port.")
    if settings()["enabled"]:
        import traffic
        try:
            with socket.socket(socket.AF_UNIX) as local:
                local.settimeout(1); local.connect(str(traffic.API_SOCKET))
            api_ok = True
        except OSError:
            api_ok = False
        add("Private Xray statistics socket", api_ok, str(traffic.API_SOCKET), "Check the Xray runtime directory owner/mode and restart the managed core.")
        ok, detail = command([str(XRAY_BINARY), "run", "-test", "-config", str(CONFIG_FILE)], timeout=20)
        add("Xray configuration", ok, detail, "Review journalctl -u abdulbasit-xray.")
    domain = read_text(DOMAIN_FILE)
    if domain:
        try:
            for name, port, tls, paths in (
                    ('Local bridge', 2082, False, ('/ssh/raw',)),
                    ('Public HTTP listener', 80, False, SSH_UPGRADE_PATHS),
                    ('Public TLS listener', 443, True, SSH_UPGRADE_PATHS)):
                listener = None
                for path in paths:
                    ok, detail = ssh_upgrade(domain, port, tls, path=path)
                    if not ok:
                        if listener is None:
                            listener = listener_detail(port)
                        detail += ' | ' + listener
                    add(f'{name} :{port} {path}', ok, detail,
                        'Compare this loopback result with the client destination, HTTP Host and TLS/SNI. Check the gateway and SSH bridge logs.')
            dns = dns_lookup({"domain": domain})
            add("Domain DNS", bool(dns["records"]["A"] or dns["records"]["AAAA"]), str(dns["records"]), "Create the domain A/AAAA record in your DNS provider.")
            cert = Path("/etc/letsencrypt/live") / validate_domain(domain) / "fullchain.pem"
            ok, detail = command([shutil.which("openssl") or "/usr/bin/openssl", "x509", "-in", str(cert), "-noout", "-checkend", "604800", "-enddate"])
            add("TLS certificate (>7 days remaining)", ok, detail, "Check DNS/port 80, then issue or renew SSL.")
        except ValidationError as exc:
            add("Domain", False, str(exc))
    else:
        add("Domain and TLS", False, "No domain configured", "Set your domain and issue SSL before enabling Xray or public web login.")
    # timedatectl queries the actual synchronization state; systemctl unit properties do not.
    ok, detail = command([shutil.which("timedatectl") or "/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"])
    add("System clock synchronized", ok and detail == "yes", detail, "Enable an NTP service. VMess requires an accurate clock.")
    import slowdns
    tunnel = slowdns.settings()
    if tunnel["enabled"]:
        ok, detail = command([shutil.which("systemctl") or "/bin/systemctl", "is-active", "abdulbasit-dnstt"])
        add("SlowDNS service", ok and detail == "active", detail, "Inspect its journal, UDP port conflict and installed core.")
        try:
            delegation = slowdns.Manager(lambda args, **kw: subprocess.run(args, check=True, text=True, capture_output=True, timeout=kw.get("timeout", 6))).check({})
            add("SlowDNS delegation", delegation["dns_ok"], str(delegation["records"]), delegation["hint"])
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            add("SlowDNS delegation", False, type(exc).__name__, "Check NS/A records at the DNS provider and allow the UDP listener externally.")
    return {"checks": checks, "passed": sum(x["ok"] for x in checks), "total": len(checks),
            "external_test_required": "Local HTTP/TLS checks verify Upgrade and the SSH banner only. Authentication, provider firewall, real client/mobile-network access and sustained transfer require an external test."}
