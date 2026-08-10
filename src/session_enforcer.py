#!/usr/bin/env python3
"""Enforce per-account concurrent Dropbear session limits.

The previous implementation called the limit an "IP limit" and locked the whole
account after counting processes. This version is explicit: it limits concurrent
sessions, terminates only excess/newest sessions, and never permanently locks an
account because of a transient overage.
"""
from __future__ import annotations

import logging
import os
import pwd
import signal
import subprocess
import time
from datetime import date
from pathlib import Path

from common import USERS_DIR, read_json

LOG = logging.getLogger("abdulbasit-session-enforcer")
INTERVAL = 5


def dropbear_pids_by_uid() -> dict[int, list[int]]:
    result = subprocess.run(
        ["/bin/ps", "-eo", "pid=,euid=,comm="],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    mapping: dict[int, list[int]] = {}
    for line in result.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3 or "dropbear" not in parts[2].lower():
            continue
        try:
            pid, uid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        mapping.setdefault(uid, []).append(pid)
    for pids in mapping.values():
        pids.sort()
    return mapping


def is_expected_dropbear(pid: int, expected_uid: int) -> bool:
    try:
        if Path(f"/proc/{pid}").stat().st_uid != expected_uid:
            return False
        comm = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8", errors="ignore").strip().lower()
        return "dropbear" in comm
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return False


def terminate(pids: list[int], expected_uid: int) -> None:
    verified = [pid for pid in pids if is_expected_dropbear(pid, expected_uid)]
    for pid in verified:
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    time.sleep(1)
    for pid in verified:
        if not is_expected_dropbear(pid, expected_uid):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def enforce_once() -> None:
    by_uid = dropbear_pids_by_uid()
    today = date.today()
    for path in sorted(USERS_DIR.glob("*.json")):
        data = read_json(path, {})
        username = str(data.get("username", path.stem))
        try:
            uid = pwd.getpwnam(username).pw_uid
        except KeyError:
            continue
        pids = by_uid.get(uid, [])
        if not pids:
            continue

        expiry_text = str(data.get("expiry", ""))
        try:
            expired = date.fromisoformat(expiry_text) < today
        except ValueError:
            expired = False
        if expired:
            LOG.warning("Terminating %d expired sessions for %s", len(pids), username)
            terminate(pids, uid)
            continue

        try:
            limit = int(data.get("max_sessions", 1))
        except (TypeError, ValueError):
            limit = 1
        limit = min(max(limit, 1), 20)
        if len(pids) > limit:
            excess = pids[limit:]
            LOG.warning("Terminating %d excess sessions for %s (limit=%d)", len(excess), username, limit)
            terminate(excess, uid)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    while True:
        try:
            enforce_once()
        except Exception:
            LOG.exception("Session enforcement cycle failed")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
