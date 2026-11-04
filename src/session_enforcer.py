#!/usr/bin/env python3
"""Enforce per-account concurrent SSH session limits.

The previous implementation called the limit an "IP limit" and locked the whole
account after counting processes. This version is explicit: it limits concurrent
sessions, terminates only excess/newest sessions, and never permanently locks an
account because of a transient overage.
"""
from __future__ import annotations

import logging
import pwd
import time
from datetime import date

from common import USERS_DIR, read_json
import ssh_sessions as dropbear_sessions
import ssh_identity
import ssh_meter
from common import quota_bytes
from account_policy import blocked_ips, ssh_id, ssh_quota_bytes

LOG = logging.getLogger("abdulbasit-session-enforcer")
INTERVAL = 5


def dropbear_pids_by_uid() -> dict[int, list[int]]:
    return {uid: [p.pid for p in rows] for uid, rows in dropbear_sessions.snapshot(USERS_DIR)["sessions"].items()}


def is_expected_dropbear(pid: int, expected_uid: int) -> bool:
    return any(p.pid == pid for p in dropbear_sessions.snapshot(USERS_DIR)["sessions"].get(expected_uid, []))


def terminate(pids: list[int], expected_uid: int) -> None:
    dropbear_sessions.terminate(pids, expected_uid, USERS_DIR)


def enforce_once() -> None:
    by_uid = dropbear_pids_by_uid()
    meter_ready = ssh_meter.available()
    try:
        ledger = ssh_meter.state()
    except RuntimeError:
        ledger, meter_ready = {"accounts": {}}, False
    # One kernel socket snapshot per cycle, separate from authenticated identity.
    ips = None  # Most SSH/SlowDNS accounts have no IP cap; skip unused FD scans.
    today = date.today()
    for path in sorted(USERS_DIR.glob("*.json")):
        data = read_json(path, {})
        if not isinstance(data, dict) or data.get("username", path.stem) != path.stem:
            continue
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
            expired = date.fromisoformat(expiry_text) <= today
        except ValueError:
            expired = True
        if expired or data.get("enabled", True) is False:
            LOG.warning("Terminating %d expired sessions for %s", len(pids), username)
            terminate(pids, uid)
            continue

        quota = ssh_quota_bytes(data)
        usage = ledger["accounts"].get(ssh_id(data), {})
        if quota is not None and (not meter_ready or usage.get("upload_bytes", 0) + usage.get("download_bytes", 0) >= quota):
            terminate(pids, uid)
            continue

        try:
            limit = int(data.get("max_sessions", 1))
        except (TypeError, ValueError):
            limit = 1
        limit = min(max(limit, 1), 20)
        excess = pids[limit:]
        try:
            from common import validate_max_ips
            ip_limit = validate_max_ips(data.get("max_ips", 0))
        except ValueError:
            ip_limit = 1
        denied = set(blocked_ips(data))
        if (ip_limit or denied) and ips is None:
            ips = ssh_identity.session_ips(by_uid)
        admitted = set()
        for pid in pids[:limit]:
            address = ips.get(pid) if ips is not None else None
            if address in denied or ip_limit and (address is None or address not in admitted and len(admitted) >= ip_limit):
                excess.append(pid)
            elif address:
                admitted.add(address)
        if excess:
            LOG.warning("Terminating %d excess sessions for %s (limit=%d)", len(excess), username, limit)
            terminate(excess, uid)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    while True:
        started = time.monotonic()
        try:
            enforce_once()
        except Exception:
            LOG.exception("Session enforcement cycle failed")
        time.sleep(max(0.1, INTERVAL - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
