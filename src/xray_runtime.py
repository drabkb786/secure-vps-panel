#!/usr/bin/env python3
"""Validated, rollback-safe Xray configuration deployment."""

from __future__ import annotations

import grp
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from common import (
    USERS_DIR,
    XRAY_CONFIG_FILE,
    XRAY_DIR,
    XRAY_SYNC_PENDING_FILE,
    atomic_write,
    read_json,
)
from protocols import render_xray_config


def load_users() -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    for path in sorted(USERS_DIR.glob("*.json")):
        data = read_json(path)
        if isinstance(data, dict):
            users.append(data)
    return users


def rendered_text(users: list[dict[str, Any]] | None = None) -> str:
    config = render_xray_config(users if users is not None else load_users())
    return json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _run(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    )


def set_xray_permissions(path: Path) -> None:
    try:
        os.chown(path, 0, grp.getgrnam("abdulbasit-xray").gr_gid)
    except KeyError:
        pass
    os.chmod(path, 0o640)


def validate_config(path: Path) -> None:
    xray = shutil.which("xray")
    if not xray:
        raise RuntimeError(
            "Xray is not installed; run the installer before enabling Xray protocols"
        )
    result = _run([xray, "run", "-test", "-config", str(path)])
    if result.returncode != 0:
        detail = (
            (result.stderr or result.stdout or "Xray rejected the configuration")
            .strip()
            .splitlines()
        )
        raise RuntimeError(
            detail[-1][:500] if detail else "Xray rejected the configuration"
        )


def deploy_config(
    users: list[dict[str, Any]] | None = None, *, restart: bool = True
) -> dict[str, Any]:
    XRAY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(XRAY_DIR, 0o750)
    content = rendered_text(users)
    old = (
        XRAY_CONFIG_FILE.read_text(encoding="utf-8")
        if XRAY_CONFIG_FILE.exists()
        else None
    )

    fd, tmp_name = tempfile.mkstemp(
        prefix=".config.", suffix=".json", dir=str(XRAY_DIR), text=True
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o640)
        validate_config(tmp)
        os.replace(tmp, XRAY_CONFIG_FILE)
        set_xray_permissions(XRAY_CONFIG_FILE)
        if restart:
            result = _run(["/bin/systemctl", "restart", "abdulbasit-xray"], timeout=90)
            if result.returncode != 0:
                if old is None:
                    XRAY_CONFIG_FILE.unlink(missing_ok=True)
                else:
                    atomic_write(XRAY_CONFIG_FILE, old, 0o640)
                    set_xray_permissions(XRAY_CONFIG_FILE)
                    _run(["/bin/systemctl", "restart", "abdulbasit-xray"], timeout=90)
                detail = (
                    (result.stderr or result.stdout or "Xray service restart failed")
                    .strip()
                    .splitlines()
                )
                raise RuntimeError(
                    detail[-1][:500] if detail else "Xray service restart failed"
                )
        XRAY_SYNC_PENDING_FILE.unlink(missing_ok=True)
        return {
            "config": str(XRAY_CONFIG_FILE),
            "users": len(users if users is not None else load_users()),
        }
    except Exception:
        atomic_write(XRAY_SYNC_PENDING_FILE, "pending\n", 0o600)
        raise
    finally:
        tmp.unlink(missing_ok=True)
