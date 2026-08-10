#!/usr/bin/env python3
"""Execute dnstt-server from the root-owned validated configuration."""

from __future__ import annotations

import os
from pathlib import Path

from common import DNSTT_FILE, read_json
from dnstt_config import build_config, host_port

DNSTT_BINARY = Path("/usr/local/bin/dnstt-server")


def main() -> None:
    raw = read_json(DNSTT_FILE)
    if not isinstance(raw, dict):
        raise SystemExit("DNSTT is not configured")
    if not raw.get("enabled"):
        raise SystemExit(0)
    config = build_config(
        zone=str(raw.get("zone", "")),
        nameserver=str(raw.get("nameserver", "")),
        listen_ip=str(raw.get("listen_ip", "")),
        public_key=str(raw.get("public_key", "")),
        private_key_file=str(raw.get("private_key_file", "")),
        target_host=str(raw.get("target_host", "")),
        target_port=raw.get("target_port", 109),
    )
    key_file = Path(config["private_key_file"])
    if not DNSTT_BINARY.is_file() or not os.access(DNSTT_BINARY, os.X_OK):
        raise SystemExit("dnstt-server binary is not installed")
    if not key_file.is_file() or key_file.is_symlink():
        raise SystemExit("DNSTT private key is missing or unsafe")
    listen = host_port(str(config["listen_ip"]), int(config["listen_port"]))
    target = host_port(str(config["target_host"]), int(config["target_port"]))
    os.execv(
        str(DNSTT_BINARY),
        [
            str(DNSTT_BINARY),
            "-udp",
            listen,
            "-privkey-file",
            str(key_file),
            str(config["zone"]),
            target,
        ],
    )


if __name__ == "__main__":
    main()
