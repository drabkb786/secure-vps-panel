"""Attribute Dropbear sessions without treating process I/O as network traffic.

New Dropbear builds drop UID after authentication. Distribution versions such
as 2022.83 keep the forwarding process root, so they need trusted journal auth
records as well. Never infer a username from an untrusted process title.
"""
from __future__ import annotations

import json
import logging
import os
import pwd
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from common import USERS_DIR, ValidationError, read_json, validate_username

PROC = Path("/proc")
EXECUTABLES = (Path("/usr/sbin/dropbear"), Path("/usr/local/lib/abdulbasit/dropbear"))
AUTH = re.compile(r"^(?:Password|Pubkey|PAM password) auth succeeded for '([a-z_][a-z0-9_-]{0,30})'(?: with .+)? from \S+$")
LOG = logging.getLogger("abdulbasit-sessions")
_AUTH_CACHE: dict[tuple[int, int], int] = {}


@dataclass(frozen=True)
class Process:
    pid: int
    ppid: int
    uid: int
    start_ticks: int
    executable: str


def process(pid: int) -> Process | None:
    """Use kernel metadata and the actual executable, not comm/argv substrings."""
    try:
        root = PROC / str(pid)
        executable = (root / "exe").resolve(strict=True)
        allowed = {p.resolve() for p in EXECUTABLES}
        if executable not in allowed:
            return None
        st = executable.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            return None
        fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
        uid_line = next(x for x in (root / "status").read_text().splitlines() if x.startswith("Uid:"))
        return Process(pid, int(fields[1]), int(uid_line.split()[2]), int(fields[19]), str(executable))
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def managed_uids(directory: Path = USERS_DIR) -> dict[int, str]:
    users = {}
    for path in directory.glob("*.json"):
        try:
            row = read_json(path, {})
            if not isinstance(row, dict):
                continue
            name = validate_username(str(row.get("username", path.stem)))
            if name != path.stem:
                continue
            entry = pwd.getpwnam(name)
            if entry.pw_uid < 1000 or entry.pw_shell != "/usr/local/lib/abdulbasit/tunnel-shell":
                continue
            users[entry.pw_uid] = name
        except (KeyError, OSError, ValueError, ValidationError):
            continue
    return users


def journal_auth() -> list[dict]:
    # Kernel-supplied _PID/_UID/_EXE/_BOOT_ID are validated below. The free-text
    # SYSLOG_PID field is deliberately ignored. Bound time and journal records.
    result = subprocess.run([
        "/usr/bin/journalctl", "--boot", "--unit=dropbear.service", "--output=json",
        "--no-pager", "--lines=10000", "--grep=auth succeeded",
        "--output-fields=_PID,_UID,_EXE,_BOOT_ID,_SYSTEMD_UNIT,__MONOTONIC_TIMESTAMP,MESSAGE",
    ], capture_output=True, text=True, check=True, timeout=5,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    rows = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
        except ValueError:
            continue
    return rows


def attribute_auth(rows: list[dict], candidates: dict[int, Process], users: dict[int, str],
                   boot_id: str, ticks_per_second: int) -> dict[tuple[int, int], int]:
    by_name = {name: uid for uid, name in users.items()}
    matches = {}
    for row in rows:
        try:
            if row.get("_UID") != "0" or row.get("_BOOT_ID") != boot_id:
                continue
            if row.get("_SYSTEMD_UNIT") != "dropbear.service":
                continue
            match = AUTH.fullmatch(row.get("MESSAGE", ""))
            if not match or match[1] not in by_name:
                continue
            item = candidates.get(int(row["_PID"]))
            if not item or row.get("_EXE") != item.executable:
                continue
            # A reused PID must not inherit an older login's identity.
            if int(row["__MONOTONIC_TIMESTAMP"]) < item.start_ticks * 1_000_000 // ticks_per_second:
                continue
            matches[(item.pid, item.start_ticks)] = by_name[match[1]]
        except (KeyError, TypeError, ValueError):
            continue
    return matches


def snapshot(directory: Path = USERS_DIR) -> dict:
    users = managed_uids(directory)
    processes = {}
    for path in PROC.iterdir():
        if path.name.isdigit():
            item = process(int(path.name))
            if item:
                processes[item.pid] = item
    # The listening parent and unrelated invocations are not account sessions.
    children = {pid: p for pid, p in processes.items()
                if p.ppid in processes and processes[p.ppid].uid == 0}
    roots = {pid: p for pid, p in children.items() if p.uid == 0}
    sessions: dict[int, list[Process]] = {uid: [] for uid in users}
    journal_ok = True
    global _AUTH_CACHE
    identities = {(p.pid, p.start_ticks) for p in roots.values()}
    _AUTH_CACHE = {k: v for k, v in _AUTH_CACHE.items() if k in identities and v in users}
    if any(identity not in _AUTH_CACHE for identity in identities):
        try:
            boot_id = (PROC / "sys/kernel/random/boot_id").read_text().strip().replace("-", "")
            _AUTH_CACHE.update(attribute_auth(journal_auth(), roots, users, boot_id, os.sysconf("SC_CLK_TCK")))
        except (OSError, subprocess.SubprocessError):
            journal_ok = False
            LOG.warning("Dropbear authentication journal unavailable; root sessions cannot all be attributed")
    for item in children.values():
        uid = item.uid if item.uid in users else _AUTH_CACHE.get((item.pid, item.start_ticks))
        if uid in users:
            sessions[uid].append(item)
    for values in sessions.values():
        values.sort(key=lambda item: (item.start_ticks, item.pid))
    unknown = sum((p.pid, p.start_ticks) not in _AUTH_CACHE for p in roots.values())
    return {"users": users, "sessions": sessions, "journal_ok": journal_ok,
            "unattributed_root_processes": unknown}


def terminate(pids: list[int], expected_uid: int, directory: Path = USERS_DIR) -> None:
    """Pin the verified kernel process identity before sending either signal."""
    if expected_uid < 1000:
        return
    current = {p.pid: p for p in snapshot(directory)["sessions"].get(expected_uid, [])}
    handles = []
    try:
        for pid in pids:
            item = current.get(pid)
            if not item:
                continue
            try:
                fd = os.pidfd_open(pid)
                if process(pid) != item:
                    os.close(fd)
                    continue
                handles.append((fd, item))
                signal.pidfd_send_signal(fd, signal.SIGTERM)
            except (OSError, AttributeError):
                LOG.warning("Cannot pin/signal Dropbear PID %s; no unsafe PID fallback", pid)
        if handles:
            time.sleep(1)
        for fd, item in handles:
            if process(item.pid) == item:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except OSError:
                    pass
    finally:
        for fd, _ in handles:
            os.close(fd)
