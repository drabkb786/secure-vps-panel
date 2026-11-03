"""Shared accounting facade during OpenSSH migration and Dropbear rollback."""
from common import USERS_DIR
import dropbear_sessions
import openssh_sessions


def snapshot(directory=USERS_DIR):
    a, b = dropbear_sessions.snapshot(directory), openssh_sessions.snapshot(directory)
    users = a["users"] | b["users"]
    sessions = {uid: sorted(a["sessions"].get(uid, []) + b["sessions"].get(uid, []),
                            key=lambda p: (p.start_ticks, p.pid)) for uid in users}
    return {"users": users, "sessions": sessions, "journal_ok": a["journal_ok"],
            "unattributed_root_processes": a["unattributed_root_processes"]}


def terminate(pids, expected_uid, directory=USERS_DIR):
    openssh_sessions.terminate(pids, expected_uid, directory)
    dropbear_sessions.terminate(pids, expected_uid, directory)
