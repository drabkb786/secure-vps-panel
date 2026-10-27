"""Persistent, sampled Xray payload counters. No process-I/O estimates."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from datetime import datetime, timezone

from common import BASE_DIR, atomic_write_json, read_json

STATE_FILE = BASE_DIR / "traffic.json"
API_SOCKET = Path("/run/abdulbasit-xray/stats.sock")
API_ADDRESS = "unix://" + str(API_SOCKET)
COUNTER = re.compile(r"^user>>>(.+)>>>traffic>>>(uplink|downlink)$")


def state():
    data = read_json(STATE_FILE, None) if STATE_FILE.exists() else {}
    if not isinstance(data, dict):
        raise RuntimeError("Traffic state is corrupt; recover it before resetting counters")
    return data


def new_epoch():
    data = state(); data["counters"] = {}; data.pop("epoch", None)
    atomic_write_json(STATE_FILE, data)


def reset_profile(row):
    data = state()
    # Keep the current baselines: the next sample counts only new bytes.
    data.setdefault("totals", {})[row["uuid"]] = {"upload_bytes": 0, "download_bytes": 0}
    data.setdefault("resets", {})[row["name"]] = datetime.now(timezone.utc).isoformat()
    atomic_write_json(STATE_FILE, data)


def accumulate(rows, response, epoch):
    """Non-reset queries are idempotent; counters never add the same bytes twice."""
    data = state()
    previous = data.get("counters", {}) if epoch == data.get("epoch") else {}
    current = {}
    totals = {row["uuid"]: data.get("totals", {}).get(row["uuid"], {
        "upload_bytes": int(row.get("upload_bytes", 0)), "download_bytes": int(row.get("download_bytes", 0))}) for row in rows}
    mapped = {f"{row['name']}-{p}@noway.local": row for row in rows for p in [*row["protocols"], "xhttp"]}
    for item in response.get("stat", []):
        match = COUNTER.fullmatch(item.get("name", ""))
        if not match or match[1] not in mapped:
            continue
        value = int(item.get("value", 0))
        if value < 0:
            raise RuntimeError("Negative Xray counter")
        key = item["name"]; current[key] = value
        old = int(previous.get(key, 0))
        delta = value - old if value >= old else value
        row = mapped[match[1]]
        field = "upload_bytes" if match[2] == "uplink" else "download_bytes"
        totals[row["uuid"]][field] += delta
    for row in rows:
        row.update(totals[row["uuid"]])
        row["used_bytes"] = row["upload_bytes"] + row["download_bytes"]
    data.update(epoch=epoch, counters=current, totals=totals, sampled_at=datetime.now(timezone.utc).isoformat())
    return data


def ip_rows(response):
    """Normalize only actual IP strings from the core's online-IP API."""
    result = []
    for item in response.get("users", []):
        email = item.get("email", "")
        if not isinstance(email, str) or not email.endswith("@noway.local"):
            continue
        ips = item.get("ips", [])
        if not isinstance(ips, list):
            continue
        for entry in ips:
            value, accessed = entry.get("ip", ""), entry.get("lastSeen", entry.get("last_seen"))
            try:
                address = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            result.append({"email": email, "ip": address, "last_seen": accessed, "source": "Xray online API"})
    return result[:1000]
