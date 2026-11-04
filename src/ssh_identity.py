"""Bind a Dropbear accepted TCP socket to its verified gateway viewer IP.

No IP is inferred from argv or process I/O. SlowDNS has no recoverable client
IP here, so it deliberately remains unknown rather than counting loopback.
"""
from __future__ import annotations

import ipaddress
import os
import pwd
from pathlib import Path

from common import atomic_write_json, read_json
from traffic import canonical_ip

PROC = Path("/proc")
PEER_DIR = Path("/run/abdulbasit-ws/peers")
SSH_PORTS = {109, 447}


def socket_inodes(pid):
    result = set()
    try:
        for path in (PROC / str(pid) / "fd").iterdir():
            try:
                link = os.readlink(path)
                if link.startswith("socket:[") and link.endswith("]"):
                    result.add(int(link[8:-1]))
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    return result


def decode_address(value):
    address, port = value.split(":")
    raw = bytes.fromhex(address)
    # /proc TCP addresses are native-endian 32-bit words on supported Linux.
    import sys
    if sys.byteorder == "little":
        raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    return canonical_ip(str(ipaddress.ip_address(raw))), int(port, 16)


def tcp_rows(state="01"):
    result = {}
    for name in ("tcp", "tcp6"):
        try:
            for line in (PROC / "net" / name).read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 10 and fields[3] == state:
                    try:
                        result[int(fields[9])] = (*decode_address(fields[1]), *decode_address(fields[2]))
                    except (ValueError, IndexError):
                        continue
        except OSError:
            pass
    return result


def tcp_sockets():
    return tcp_rows("01")


def register(target, ip, verified):
    """Only the private DynamicUser runtime directory is writable by the bridge."""
    PEER_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    port = target.getsockname()[1]
    path = PEER_DIR / f"{port}.json"
    atomic_write_json(path, {"pid": os.getpid(), "inode": os.fstat(target.fileno()).st_ino,
                            "port": port, "target_port": target.getpeername()[1],
                            "ip": canonical_ip(ip), "verified": verified}, 0o600)
    return path


def gateway_ip(port, sockets):
    path = PEER_DIR / f"{port}.json"
    try:
        owner = pwd.getpwnam("abdulbasit-ws").pw_uid
        if path.is_symlink() or PEER_DIR.is_symlink() or path.stat().st_uid != owner or PEER_DIR.stat().st_uid != owner:
            return None
        if path.stat().st_mode & 0o077 or PEER_DIR.stat().st_mode & 0o077:
            return None
        data = read_json(path, {})
        if not isinstance(data, dict) or data.get("verified") is not True or data.get("port") != port:
            return None
        inode = data["inode"]
        # A stale record cannot be inherited when an ephemeral TCP port is reused.
        if inode not in socket_inodes(data["pid"]):
            return None
        actual = sockets.get(inode)
        if actual != ("127.0.0.1", port, "127.0.0.1", data["target_port"]) or data["target_port"] not in SSH_PORTS:
            return None
        address = canonical_ip(data["ip"])
        return None if ipaddress.ip_address(address).is_loopback else address
    except (OSError, ValueError, TypeError, KeyError):
        return None


def session_ips(sessions):
    if not any(sessions.values()):
        return {}
    sockets = tcp_sockets()
    listeners = tcp_rows("0A")
    from openssh_sessions import listener_ports
    result = {}
    for pids in sessions.values():
        for pid in pids:
            result[pid] = None
            ports = SSH_PORTS | listener_ports(pid, listeners)
            for inode in socket_inodes(pid):
                row = sockets.get(inode)
                if row and row[1] in ports:
                    result[pid] = gateway_ip(row[3], sockets) if ipaddress.ip_address(row[2]).is_loopback else row[2]
                    break
    return result
