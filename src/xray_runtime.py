"""Bounded live account additions using Xray's official HandlerService CLI.

Never treat exit status alone as success: `adu` prints per-user failures but can
return exit status zero. Removals intentionally use a full reconcile until the
core provides verified termination of each user's existing connections.
"""
import copy
import json
import os
import re
import tempfile
from pathlib import Path


def additions(before, after):
    a, b = copy.deepcopy(before), copy.deepcopy(after)
    delta = []
    if len(a.get("inbounds", [])) != len(b.get("inbounds", [])):
        return None
    for old, new in zip(a.get("inbounds", []), b.get("inbounds", [])):
        old_clients = old.get("settings", {}).pop("clients", [])
        new_clients = new.get("settings", {}).pop("clients", [])
        previous = {x["email"]: x for x in old_clients}
        current = {x["email"]: x for x in new_clients}
        if any(current.get(email) != client for email, client in previous.items()):
            return None
        added = [client for email, client in current.items() if email not in previous]
        if added:
            inbound = copy.deepcopy(new)
            inbound["settings"]["clients"] = added
            delta.append(inbound)
    return delta if a == b else None


def add(run, binary, address, inbounds, directory):
    expected = sum(len(x["settings"]["clients"]) for x in inbounds)
    if not expected:
        return
    fd, filename = tempfile.mkstemp(prefix=".live-users-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump({"inbounds": inbounds}, handle)
        output = run([str(binary), "api", "adu", "--server=" + address,
                      "-t=5", filename], timeout=8).stdout
        match = re.search(r"^Added (\d+) user\(s\) in total\.$", output, re.M)
        if not match or int(match[1]) != expected:
            raise RuntimeError("Xray did not acknowledge every live account addition")
    finally:
        Path(filename).unlink(missing_ok=True)
