"""Kernel-verified authenticated sessions of our dedicated OpenSSH instance.

sshd uses a privileged monitor and an unprivileged authenticated child. Count
the child once, never its root monitor or pre-authentication sandbox. Restrict
inspection to this unit's cgroup, so administrative SSH is never signalled.
Supports the sshd/sshd-session split introduced in newer OpenSSH versions.
"""
import os
import signal
import time
from pathlib import Path
from dataclasses import dataclass

from common import USERS_DIR
from dropbear_sessions import managed_uids

PROC = Path("/proc")
UNIT = "abdulbasit-sshd.service"
EXECUTABLES = (Path("/usr/sbin/sshd"), Path("/usr/lib/openssh/sshd-session"),
               Path("/usr/libexec/sshd-session"), Path("/usr/lib/openssh/sshd-auth"))


@dataclass(frozen=True)
class Process:
    pid: int
    ppid: int
    uid: int
    start_ticks: int
    executable: str


def process(pid):
    try:
        root = PROC / str(pid)
        if not any(UNIT in line.split(":", 2)[-1].strip().split("/")
                   for line in (root / "cgroup").read_text().splitlines()):
            return None
        executable = (root / "exe").resolve(strict=True)
        if executable not in {p.resolve() for p in EXECUTABLES}:
            return None
        st = executable.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            return None
        fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
        uid_line = next(line for line in (root / "status").read_text().splitlines() if line.startswith("Uid:"))
        return Process(pid, int(fields[1]), int(uid_line.split()[2]), int(fields[19]), str(executable))
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def snapshot(directory=USERS_DIR):
    users = managed_uids(directory)
    processes = {}
    for path in PROC.iterdir():
        if path.name.isdigit():
            item = process(int(path.name))
            if item:
                processes[item.pid] = item
    sessions = {uid: [] for uid in users}
    for item in processes.values():
        parent = processes.get(item.ppid)
        # Only post-authentication code runs with a managed user's effective UID.
        # Same-UID descendants must not inflate a single transport connection.
        if item.uid in users and parent and parent.uid == 0:
            sessions[item.uid].append(item)
    for rows in sessions.values():
        rows.sort(key=lambda p: (p.start_ticks, p.pid))
    return {"users": users, "sessions": sessions, "journal_ok": True,
            "unattributed_root_processes": 0}


def terminate(pids, expected_uid, directory=USERS_DIR):
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
                continue
        if handles:
            time.sleep(0.1)
        for fd, item in handles:
            if process(item.pid) == item:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except OSError:
                    pass
    finally:
        for fd, _ in handles:
            os.close(fd)
