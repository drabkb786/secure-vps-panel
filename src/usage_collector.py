#!/usr/bin/env python3
"""Collect Xray per-user byte counters and enforce quota/expiry."""

from __future__ import annotations

import json
import logging
import re
import secrets
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

from common import (
    USERS_DIR,
    XRAY_SYNC_PENDING_FILE,
    XRAY_USAGE_PENDING_FILE,
    atomic_write_json,
    read_json,
    state_lock,
)
from protocols import expired, protocol_email, quota_exceeded
from xray_runtime import deploy_config

LOG = logging.getLogger("abdulbasit-usage")
STAT_RE = re.compile(
    r'name:\s*"user>>>(?P<email>[^">]+)>>>traffic>>>(?P<direction>uplink|downlink)"'
    r".*?value:\s*(?P<value>[0-9]+)",
    re.DOTALL,
)
STAT_NAME_RE = re.compile(
    r'^user>>>(?P<email>[^">]+)>>>traffic>>>(?:uplink|downlink)$'
)


def parse_stats(text: str) -> dict[str, int]:
    totals: dict[str, int] = {}
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        document = None
    if isinstance(document, dict) and isinstance(document.get("stat"), list):
        for item in document["stat"]:
            if not isinstance(item, dict):
                continue
            match = STAT_NAME_RE.fullmatch(str(item.get("name", "")))
            if not match:
                continue
            try:
                value = max(0, int(item.get("value", 0)))
            except (TypeError, ValueError):
                continue
            email = match.group("email")
            totals[email] = totals.get(email, 0) + value
        return totals
    for match in STAT_RE.finditer(text):
        email = match.group("email")
        totals[email] = totals.get(email, 0) + int(match.group("value"))
    return totals


def query_stats() -> dict[str, int]:
    xray = shutil.which("xray")
    if not xray:
        raise RuntimeError("xray command is not installed")
    result = subprocess.run(
        [
            xray,
            "api",
            "statsquery",
            "--server=127.0.0.1:21085",
            "-pattern",
            "user>>>",
            "-reset",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    )
    if result.returncode != 0:
        detail = (
            (result.stderr or result.stdout or "Xray StatsService query failed")
            .strip()
            .splitlines()
        )
        raise RuntimeError(
            detail[-1][:500] if detail else "Xray StatsService query failed"
        )
    return parse_stats(result.stdout)


def _apply_usage_locked(
    totals: dict[str, int], *, transaction_id: str = ""
) -> tuple[int, bool]:
    changed = 0
    access_changed = False
    for path in sorted(USERS_DIR.glob("*.json")):
        data = read_json(path)
        if not isinstance(data, dict):
            continue
        username = str(data.get("username", path.stem))
        try:
            email = protocol_email(username)
        except ValueError:
            LOG.warning("Skipping invalid managed-user metadata file: %s", path.name)
            continue
        added = max(0, int(totals.get(email, 0)))
        already_applied = (
            bool(transaction_id)
            and data.get("usage_last_transaction") == transaction_id
        )
        old_blocked = bool(data.get("access_blocked"))
        if added and not already_applied:
            data["usage_bytes"] = max(0, int(data.get("usage_bytes", 0) or 0)) + added
            data["usage_updated_at"] = datetime.now(timezone.utc).isoformat()
            if transaction_id:
                data["usage_last_transaction"] = transaction_id
            changed += 1
        new_blocked = expired(data) or quota_exceeded(data)
        if new_blocked:
            data["access_blocked"] = True
            data["access_blocked_reason"] = "expired" if expired(data) else "quota"
            if not old_blocked:
                data["access_blocked_at"] = datetime.now(timezone.utc).isoformat()
        else:
            data.pop("access_blocked", None)
            data.pop("access_blocked_reason", None)
            data.pop("access_blocked_at", None)
        if old_blocked != new_blocked:
            access_changed = True
        if (added and not already_applied) or old_blocked != new_blocked:
            atomic_write_json(path, data, 0o600)
    if access_changed or XRAY_SYNC_PENDING_FILE.exists():
        deploy_config()
    return changed, access_changed


def apply_usage(
    totals: dict[str, int], *, transaction_id: str = ""
) -> tuple[int, bool]:
    with state_lock():
        return _apply_usage_locked(totals, transaction_id=transaction_id)


def _read_pending_transaction() -> tuple[str, dict[str, int]] | None:
    if not XRAY_USAGE_PENDING_FILE.exists():
        return None
    data = read_json(XRAY_USAGE_PENDING_FILE)
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("id"), str)
        or not isinstance(data.get("totals"), dict)
    ):
        raise RuntimeError(
            "Xray usage pending journal is invalid; inspect it before continuing"
        )
    transaction_id = data["id"]
    if not re.fullmatch(r"[0-9a-f]{32}", transaction_id):
        raise RuntimeError("Xray usage pending journal has an invalid transaction ID")
    totals: dict[str, int] = {}
    try:
        for email, value in data["totals"].items():
            amount = int(value)
            if not isinstance(email, str) or amount < 0:
                raise ValueError
            totals[email] = amount
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Xray usage pending journal has invalid counters") from exc
    return transaction_id, totals


def _write_pending_transaction(transaction_id: str, totals: dict[str, int]) -> None:
    atomic_write_json(
        XRAY_USAGE_PENDING_FILE,
        {
            "id": transaction_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "totals": totals,
        },
        0o600,
    )


def collect_once() -> dict[str, Any]:
    users_changed = 0
    access_changed = False
    replayed = False
    totals: dict[str, int] = {}
    with state_lock():
        pending = _read_pending_transaction()
        if pending is not None:
            transaction_id, pending_totals = pending
            changed, blocked = _apply_usage_locked(
                pending_totals, transaction_id=transaction_id
            )
            users_changed += changed
            access_changed = access_changed or blocked
            XRAY_USAGE_PENDING_FILE.unlink()
            replayed = True

        totals = query_stats()
        if totals:
            transaction_id = secrets.token_hex(16)
            _write_pending_transaction(transaction_id, totals)
            changed, blocked = _apply_usage_locked(
                totals, transaction_id=transaction_id
            )
            users_changed += changed
            access_changed = access_changed or blocked
            XRAY_USAGE_PENDING_FILE.unlink()
        else:
            changed, blocked = _apply_usage_locked({})
            users_changed += changed
            access_changed = access_changed or blocked
    return {
        "counters": len(totals),
        "users_changed": users_changed,
        "access_changed": access_changed,
        "journal_replayed": replayed,
    }


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    try:
        LOG.info("Usage collection result: %s", collect_once())
    except Exception:
        LOG.exception("Usage collection failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
