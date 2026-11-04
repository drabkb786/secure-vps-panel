"""Account-scoped IP policy and stable identities shared by both transports."""
import hashlib
from common import ValidationError
from traffic import canonical_ip

MAX_BLOCKED_IPS = 512


def blocked_ips(account):
    values = account.get("blocked_ips", [])
    if not isinstance(values, list) or len(values) > MAX_BLOCKED_IPS:
        raise ValidationError("Invalid account IP policy")
    try:
        return sorted({canonical_ip(value) for value in values})
    except (ValueError, TypeError) as exc:
        raise ValidationError("Invalid account IP address") from exc


def change_ip(account, value, blocked):
    if type(blocked) is not bool:
        raise ValidationError("blocked must be a boolean")
    try:
        address = canonical_ip(value)
    except (ValueError, TypeError) as exc:
        raise ValidationError("Supply a valid IPv4 or IPv6 address") from exc
    values = set(blocked_ips(account))
    if blocked:
        values.add(address)
    else:
        values.discard(address)
    if len(values) > MAX_BLOCKED_IPS:
        raise ValidationError("Maximum 512 blocked addresses per account")
    account["blocked_ips"] = sorted(values)
    return address


def ssh_id(account):
    # Legacy accounts already have created_at. Recreating a username starts a
    # different ledger; atomic metadata replacement does not change identity.
    return account.get("account_id") or hashlib.sha256(
        (account["username"] + "\0" + account.get("created_at", "legacy")).encode()
    ).hexdigest()


def ssh_quota_bytes(account):
    # Older SSH quota fields were informational. Do not silently turn those
    # notes into an enforced restriction during an application update.
    from common import quota_bytes
    return quota_bytes(account) if account.get("quota_enforced") is True else None


def exact(values):
    up, down = int(values.get("upload_bytes", 0)), int(values.get("download_bytes", 0))
    return {"upload_bytes": up, "download_bytes": down, "used_bytes": up + down,
            "exact_bytes": {"upload_bytes": str(up), "download_bytes": str(down), "used_bytes": str(up + down)}}
