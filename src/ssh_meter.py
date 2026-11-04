#!/usr/bin/env python3
"""Collect absolute channel-payload counters from the metered Dropbear build.

Identity comes from SO_PEERCRED, the installed root-owned executable and its
accepted TCP socket, never a client-supplied username/IP. Checkpointing is
sampled; an abrupt process/core crash can lose the final unreported interval.
"""
from __future__ import annotations

import json
import hashlib
import logging
import math
import os
import pwd
import socket
import socketserver
import struct
import threading
import time
from datetime import date, datetime, timezone
from pathlib import Path

from common import USERS_DIR, atomic_write_json, read_json, quota_bytes, validate_max_ips, validate_username
from account_policy import blocked_ips, ssh_id, ssh_quota_bytes, exact
import dropbear_sessions
import ssh_identity

STATE_DIR = Path("/var/lib/abdulbasit-meter")
STATE_FILE = STATE_DIR / "ssh.json"
SOCKET = Path("/run/abdulbasit-meter/ssh.sock")
STATUS_FILE = SOCKET.parent / "status.json"
BUILD_MARKER = Path("/usr/local/lib/abdulbasit/dropbear-meter.json")
LOCK = threading.RLock()
LOG = logging.getLogger("abdulbasit-ssh-meter")
FIELDS = ("upload_bytes", "download_bytes")
_BUILD_CACHE = None


def valid_build():
    global _BUILD_CACHE
    import ssh_backend
    try:
        marker = read_json(BUILD_MARKER, {})
        if not isinstance(marker, dict):
            return False
        binary = ssh_backend.DROPBEAR_BINARY
        info = binary.stat()
        if binary.is_symlink() or BUILD_MARKER.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            return False
        key = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size, marker.get("sha256"))
        if _BUILD_CACHE and _BUILD_CACHE[0] == key:
            return _BUILD_CACHE[1]
        valid = marker.get("schema") == "noway-dropbear-meter-v1" and hashlib.sha256(binary.read_bytes()).hexdigest() == marker.get("sha256")
        _BUILD_CACHE = key, valid
        return valid
    except OSError:
        return False


def now():
    return datetime.now(timezone.utc).isoformat()


def state():
    data = read_json(STATE_FILE, None) if STATE_FILE.exists() else {"accounts": {}, "sessions": {}}
    if not isinstance(data, dict) or not all(isinstance(data.get(k), dict) for k in ("accounts", "sessions")):
        raise RuntimeError("SSH usage ledger is corrupt; restore its backup before resuming capped accounts")
    for row in list(data["accounts"].values()) + list(data["sessions"].values()):
        if not isinstance(row, dict):
            raise RuntimeError("Invalid SSH ledger entry")
        reported = row.get("reported_at", 0)
        if type(reported) not in (int, float) or not 0 <= reported < 2**53 or not math.isfinite(reported):
            raise RuntimeError("Invalid SSH meter timestamp")
        for field in FIELDS:
            value = row.get(field, 0)
            if type(value) is not int or not 0 <= value < 2**63:
                raise RuntimeError("Invalid SSH byte counter; saved totals retained")
        ips = row.get("ips", {})
        if not isinstance(ips, dict) or any(not isinstance(value, dict) or any(type(value.get(key, 0)) is not int or not 0 <= value.get(key, 0) < 2**63 for key in FIELDS) for value in ips.values()):
            raise RuntimeError("Invalid SSH source counters; saved totals retained")
    return data


def available():
    try:
        import ssh_backend
        info = read_json(STATUS_FILE, {})
        return bool(ssh_backend.native_dropbear() and valid_build()
                    and info.get("ready") is True and time.time() - info["time"] < 12
                    and Path("/proc") .joinpath(str(info["pid"])).is_dir())
    except (OSError, ValueError, TypeError, KeyError):
        return False


def account_usage(account, data=None):
    data = state() if data is None else data
    entry = data["accounts"].get(ssh_id(account), {})
    ready = available()
    return {**exact(entry), "usage_available": ready, "quota_enforced": ready and account.get("quota_enforced") is True,
            "sampled_at": data.get("sampled_at"), "usage_scope": "SSH channel payload bytes",
            "ip_usage": entry.get("ips", {})}


class Ledger:
    def __init__(self):
        self.data = state()
        self.active = {}
        self.dirty = False

    def admit(self, token, account, address):
        if account.get("enabled", True) is False or date.fromisoformat(account["expiry"]) <= date.today():
            raise ValueError("Account locked or expired")
        identity = ssh_id(account)
        totals = self.data["accounts"].get(identity, {})
        limit = ssh_quota_bytes(account)
        if limit is not None and sum(totals.get(k, 0) for k in FIELDS) >= limit:
            raise ValueError("Data limit reached")
        if address in blocked_ips(account):
            raise ValueError("IP blocked for this account")
        cap = validate_max_ips(account.get("max_ips", 0))
        peers = {entry["ip"] for key, entry in self.active.items() if entry["identity"] == identity and key != token and entry["ip"]}
        if cap and (not address or address not in peers and len(peers) >= cap):
            raise ValueError("Unique-IP limit reached")
        self.active[token] = {"identity": identity, "ip": address}

    def update(self, token, account, address, up, down):
        if any(type(v) is not int or not 0 <= v < 2**63 for v in (up, down)):
            raise ValueError("Invalid absolute counters")
        identity = ssh_id(account)
        previous = self.data["sessions"].get(token, {})
        if previous and previous.get("identity") != identity:
            raise ValueError("Session account identity changed")
        old = [previous.get(k, 0) for k in FIELDS]
        if up < old[0] or down < old[1]:
            raise ValueError("SSH counter decreased within one process lifetime")
        delta = (up - old[0], down - old[1])
        row = self.data["accounts"].setdefault(identity, {"username": account["username"], "ips": {}})
        for key, value in zip(FIELDS, delta):
            row[key] = row.get(key, 0) + value
        ips = row.setdefault("ips", {})
        address_key = address or "unknown"
        if address_key not in ips and len(ips) >= 4096:
            address_key = "unknown"
            row["ip_attribution_incomplete"] = True
        ip = ips.setdefault(address_key, {})
        for key, value in zip(FIELDS, delta):
            ip[key] = ip.get(key, 0) + value
        ip["last_seen"] = now()
        self.data["sessions"][token] = {"identity": identity, "upload_bytes": up, "download_bytes": down}
        self.data["sessions"][token]["reported_at"] = time.time()
        self.dirty = True

    def reset(self, account):
        # Preserve absolute session baselines, including live connections.
        self.data["accounts"][ssh_id(account)] = {"username": account["username"], "upload_bytes": 0, "download_bytes": 0, "ips": {}}
        self.dirty = True
        self.flush()

    def flush(self):
        if self.dirty:
            # Final counters of dead processes need no reconnect baseline.
            # Keep live processes so collector restarts cannot double-bill them.
            for token in list(self.data["sessions"]):
                if token in self.active or token.count(":") != 2:
                    continue
                _, pid, ticks = token.split(":")
                try:
                    actual = Path("/proc", pid, "stat").read_text().rsplit(")", 1)[1].split()[19]
                    if actual == ticks:
                        continue
                except FileNotFoundError:
                    pass
                except (OSError, IndexError):
                    continue
                del self.data["sessions"][token]
            self.data["sampled_at"] = now()
            atomic_write_json(STATE_FILE, self.data)
            self.dirty = False


def identify(pid, uid):
    process = dropbear_sessions.process(pid)
    if process is None or process.uid != uid or uid < 1000:
        raise ValueError("Untrusted meter process")
    parent = dropbear_sessions.process(process.ppid)
    if parent is None or parent.uid != 0:
        raise ValueError("Meter must belong to the managed SSH listener")
    user = pwd.getpwuid(uid)
    name = validate_username(user.pw_name)
    if user.pw_shell != "/usr/local/lib/abdulbasit/tunnel-shell":
        raise ValueError("Not a managed tunnel account")
    account = read_json(USERS_DIR / (name + ".json"), {})
    if account.get("username") != name:
        raise ValueError("Managed account metadata missing")
    address = ssh_identity.session_ips({uid: [pid]}).get(pid)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return boot + ":" + str(pid) + ":" + str(process.start_ticks), account, address


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        token = None
        pid, uid, _ = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        self.request.settimeout(15)
        try:
            first = self.rfile.readline(256).decode("ascii").strip()
            if first.startswith("RESET "):
                if uid != 0:
                    raise ValueError("Reset requires the root command daemon")
                name = validate_username(first[6:])
                account = read_json(USERS_DIR / (name + ".json"), {})
                if account.get("username") != name:
                    raise ValueError("Unknown account")
                with LOCK:
                    self.server.ledger.reset(account)
                self.wfile.write(b"OK\n")
                return
            token, account, address = identify(pid, uid)
            try:
                with LOCK:
                    self.server.ledger.admit(token, account, address)
            except ValueError:
                self.wfile.write(b"DENY\n")
                raise
            line = first
            initial = True
            while line:
                parts = line.split()
                if len(parts) != 3 or parts[0] != "M" or any(not v.isdecimal() or len(v) > 19 for v in parts[1:]):
                    raise ValueError("Invalid meter message")
                with LOCK:
                    self.server.ledger.update(token, account, address, *map(int, parts[1:]))
                if initial:
                    self.wfile.write(b"OK\n")
                    initial = False
                line = self.rfile.readline(256).decode("ascii").strip()
        except (ValueError, OSError, KeyError, RuntimeError) as exc:
            LOG.warning("SSH meter rejected pid %s: %s", pid, exc)
        finally:
            if token:
                with LOCK:
                    self.server.ledger.active.pop(token, None)
                    self.server.ledger.flush()


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    request_queue_size = 128
    def verify_request(self, request, address):
        _, uid, _ = struct.unpack("3i", request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid == 0:
            return True
        try:
            return uid >= 1000 and pwd.getpwuid(uid).pw_shell == "/usr/local/lib/abdulbasit/tunnel-shell"
        except KeyError:
            return False
    def __init__(self, address):
        self.ledger = Ledger()
        self.slots = threading.BoundedSemaphore(512)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def reset(username):
    name = validate_username(username)
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(3)
        peer.connect(str(SOCKET))
        peer.sendall(("RESET " + name + "\n").encode())
        if peer.recv(32) != b"OK\n":
            raise RuntimeError("SSH meter did not confirm the reset")


def coverage(data):
    """Live kernel process identities with a recent authenticated meter report."""
    result = {}
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    current = time.time()
    for token, row in data["sessions"].items():
        try:
            token_boot, pid, ticks = token.split(":")
            if token_boot != boot or not 0 <= current - row.get("reported_at", 0) < 12:
                continue
            actual = Path("/proc", pid, "stat").read_text().rsplit(")", 1)[1].split()[19]
            if actual == ticks:
                result.setdefault(row["identity"], set()).add(int(pid))
        except (ValueError, KeyError, OSError, IndexError, TypeError):
            continue
    return result


def main():
    logging.basicConfig(level=logging.INFO)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    SOCKET.parent.mkdir(mode=0o711, parents=True, exist_ok=True)
    os.chmod(SOCKET.parent, 0o711)
    SOCKET.unlink(missing_ok=True)
    with Server(str(SOCKET)) as server:
        os.chmod(SOCKET, 0o666)  # SO_PEERCRED/executable validation authorizes clients.
        def checkpoint():
            while True:
                with LOCK:
                    server.ledger.flush()
                    atomic_write_json(STATUS_FILE, {"ready": True, "time": time.time(), "pid": os.getpid()}, 0o644)
                time.sleep(2)
        threading.Thread(target=checkpoint, daemon=True).start()
        server.serve_forever(poll_interval=.25)


if __name__ == "__main__":
    main()
