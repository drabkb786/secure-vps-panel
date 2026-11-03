"""Persistent, sampled Xray payload counters. No process-I/O estimates."""
from __future__ import annotations

import ipaddress
import re
import copy
from pathlib import Path
from datetime import datetime, timezone

from common import BASE_DIR, atomic_write_json, read_json

STATE_FILE = BASE_DIR / "traffic.json"
API_SOCKET = Path("/run/abdulbasit-xray/stats.sock")
API_ADDRESS = "unix://" + str(API_SOCKET)
COUNTER = re.compile(r"^user>>>(.+)>>>traffic>>>(uplink|downlink)$")
SAMPLE_SECONDS = 5


def integer(value):
    # protobuf JSON uses decimal strings for int64. Reject floats and booleans.
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,19}", value):
        value = int(value)
    if type(value) is not int or not 0 <= value <= 2 ** 63 - 1:
        raise RuntimeError("Invalid traffic counter; saved totals retained")
    return value


def state():
    data = read_json(STATE_FILE, None) if STATE_FILE.exists() else {}
    if not isinstance(data, dict):
        raise RuntimeError("Traffic state is corrupt; recover it before resetting counters")
    for key in ("counters", "totals", "owners"):
        if not isinstance(data.get(key, {}), dict):
            raise RuntimeError("Traffic state is corrupt; recover its backup")
    for value in data.get("counters", {}).values():
        integer(value)
    for values in data.get("totals", {}).values():
        if not isinstance(values, dict):
            raise RuntimeError("Traffic totals are corrupt")
        for key in ("upload_bytes", "download_bytes"):
            integer(values.get(key))
    return data


def new_epoch():
    data = state(); data["counters"] = {}; data.pop("epoch", None)
    data["owners"] = {}
    atomic_write_json(STATE_FILE, data)


def hydrate(rows):
    """The checkpoint is authoritative even if a crash left the account cache stale."""
    saved = state().get("totals", {})
    for row in rows:
        if row["uuid"] in saved:
            row.update(saved[row["uuid"]])
            row["used_bytes"] = row["upload_bytes"] + row["download_bytes"]
    return rows


def emails(row):
    protocols = set(row["protocols"])
    if "vless" in protocols:
        protocols.update(("xhttp", "reality"))
    # Accept legacy names while upgrading; new configs use immutable UUIDs.
    return {f"{identity}-{p}@noway.local" for identity in (row["uuid"], row["name"]) for p in protocols}


def reset_profile(row):
    data = state()
    # Keep the current baselines: the next sample counts only new bytes.
    data.setdefault("totals", {})[row["uuid"]] = {"upload_bytes": 0, "download_bytes": 0}
    data.setdefault("resets", {})[row["name"]] = datetime.now(timezone.utc).isoformat()
    atomic_write_json(STATE_FILE, data)


def accumulate(rows, response, epoch):
    """Non-reset queries are idempotent; counters never add the same bytes twice."""
    if not isinstance(epoch, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", epoch) or int(epoch, 16) == 0:
        raise RuntimeError("Cannot identify the running Xray instance")
    if not isinstance(response, dict) or not isinstance(response.get("stat", []), list):
        raise RuntimeError("Invalid statistics response")
    data = state()
    same_epoch = epoch == data.get("epoch")
    previous = data.get("counters", {}) if same_epoch else {}
    # Omitted/temporarily inactive counters keep their baseline within an epoch.
    current = dict(previous)
    owners = dict(data.get("owners", {})) if same_epoch else {}
    totals = {row["uuid"]: copy.deepcopy(data.get("totals", {}).get(row["uuid"], {
        "upload_bytes": integer(row.get("upload_bytes", 0)), "download_bytes": integer(row.get("download_bytes", 0))})) for row in rows}
    mapped = {email: row for row in rows for email in emails(row)}
    seen = set()
    for item in response.get("stat", []):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise RuntimeError("Malformed Xray counter")
        key = item["name"]
        if key in seen:
            raise RuntimeError("Duplicate Xray counter; refusing an ambiguous sample")
        seen.add(key)
        match = COUNTER.fullmatch(key)
        if not match or match[1] not in mapped:
            continue
        value = integer(item.get("value", 0))
        row = mapped[match[1]]
        current[key] = value
        old = integer(previous.get(key, 0))
        if key in owners and owners[key] != row["uuid"]:
            # A recreated name must not inherit another identity's old counter.
            old = value
        owners[key] = row["uuid"]
        if value < old:
            data["counter_discontinuities"] = integer(data.get("counter_discontinuities", 0)) + 1
        delta = value - old if value >= old else value
        field = "upload_bytes" if match[2] == "uplink" else "download_bytes"
        totals[row["uuid"]][field] += delta
        integer(totals[row["uuid"]][field])
    for row in rows:
        row.update(totals[row["uuid"]])
        row["used_bytes"] = row["upload_bytes"] + row["download_bytes"]
    data.update(epoch=epoch, counters=current, owners=owners, totals=totals, sampled_at=datetime.now(timezone.utc).isoformat())
    return data


def canonical_ip(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Invalid IP")
    value = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def ip_rows(response):
    """Normalize only actual IP strings from the core's online-IP API."""
    if not isinstance(response, dict) or not isinstance(response.get("users", []), list):
        raise RuntimeError("Invalid online-IP response")
    result, seen = [], set()
    for item in response.get("users", []):
        if not isinstance(item, dict):
            raise RuntimeError("Invalid online-IP user")
        email = item.get("email", "")
        if not isinstance(email, str) or not email.endswith("@noway.local"):
            continue
        ips = item.get("ips", [])
        if not isinstance(ips, list):
            raise RuntimeError("Invalid online-IP list")
        for entry in ips:
            if not isinstance(entry, dict):
                raise RuntimeError("Invalid online-IP entry")
            value, accessed = entry.get("ip", ""), entry.get("lastSeen", entry.get("last_seen"))
            try:
                address = canonical_ip(value)
            except ValueError:
                raise RuntimeError("Invalid IP in the online response")
            if (email, address) not in seen:
                seen.add((email, address))
                result.append({"email": email, "ip": address, "last_seen": accessed, "source": "Xray active streams"})
    # Never truncate the set used for enforcement. Presentation can paginate it.
    return result


def profile_ips(rows, connections):
    by_email = {email: row["name"] for row in rows for email in emails(row)}
    result = {row["name"]: set() for row in rows}
    for entry in connections:
        name = by_email.get(entry["email"])
        if name:
            result[name].add(entry["ip"])
    return {name: sorted(ips) for name, ips in result.items()}
