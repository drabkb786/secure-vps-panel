"""Private gateway marker: a local SSH forward cannot forge a viewer IP.

The marker is never exported to clients. Nginx and managed backends read it
from a root-controlled file; untrusted incoming IP headers are overwritten.
"""
from __future__ import annotations

import grp
import os
import re
import secrets
from pathlib import Path

from common import atomic_write

CONFIG_FILE = Path("/etc/abdulbasit-gateway/header.conf")


def header_name():
    try:
        name = CONFIG_FILE.read_text().strip()
    except OSError as exc:
        raise RuntimeError("Private gateway identity is missing; rerun install.sh") from exc
    if not re.fullmatch(r"X-Noway-Gateway-[a-f0-9]{64}", name):
        raise RuntimeError("Private gateway identity is invalid")
    return name


def backend_path(protocol):
    if protocol not in {"vless", "vmess", "trojan", "xhttp"}:
        raise ValueError("Unsupported backend protocol")
    return "/" + protocol + "/" + header_name().removeprefix("X-Noway-Gateway-") + ("/" if protocol == "xhttp" else "")


def initialize():
    if os.geteuid() != 0:
        raise RuntimeError("Gateway initialization requires root")
    if CONFIG_FILE.is_symlink() or CONFIG_FILE.parent.is_symlink():
        raise RuntimeError("Unsafe gateway identity path")
    group = grp.getgrnam("abdulbasit-gateway").gr_gid
    CONFIG_FILE.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(CONFIG_FILE.parent, 0, group)
    os.chmod(CONFIG_FILE.parent, 0o750)
    if CONFIG_FILE.exists():
        header_name()  # Preserve the marker on upgrades; never silently rotate.
    else:
        atomic_write(CONFIG_FILE, "X-Noway-Gateway-" + secrets.token_hex(32) + "\n", 0o640)
    os.chown(CONFIG_FILE, 0, group)
    os.chmod(CONFIG_FILE, 0o640)


if __name__ == "__main__":
    initialize()
