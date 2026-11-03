"""Compact terminal dashboard using actual daemon state, with no demo metrics."""
import sys
from panel_client import request


def render(data, live, *, color=False):
    palette = {"green": "\033[38;2;52;211;153m", "cyan": "\033[38;2;34;211;238m", "muted": "\033[38;2;148;163;184m", "reset": "\033[0m"} if color else {x: "" for x in ("green", "cyan", "muted", "reset")}
    safe = lambda x: "".join(c for c in str(x) if ord(c) >= 32 and ord(c) != 127)
    gb = lambda value: f"{value / 1024 ** 3:.2f} GiB"
    system, accounts = data["system"], data["accounts"]
    measured = sum(x.get("used_bytes", 0) for x in accounts)
    online = live.get("xray", {})
    ips = str(len({x["ip"] for x in online.get("connections", [])})) if online.get("available") else "unavailable"
    p = palette
    print(f"{p['green']}N / NOWAY{p['reset']}   VPS CONTROL ROOM   {p['muted']}v4.0 · Abdul Basit{p['reset']}\n")
    print(f"{p['cyan']}{safe(system['hostname'])}{p['reset']}  /  {safe(data['domain'])}")
    print(f"Memory {gb(system['memory_total'] - system['memory_available'])} / {gb(system['memory_total'])}    Xray payload {gb(measured)}")
    print(f"Profiles {len(accounts)}    SSH accounts {len(data['users'])}    Authenticated recent IPs {ips}")
    statuses = data["services"]
    print("  ·  ".join(f"{label} {safe(statuses.get(unit, 'unavailable'))}" for label, unit in (("NGINX", "nginx"), ("XRAY", "abdulbasit-xray"), ("SSH", "abdulbasit-sshd" if data.get("ssh_backend") == "openssh" else "dropbear"), ("WEB", "abdulbasit-web"))))
    print(f"UDP policy {'allowed' if data['network'].get('udp_enabled', True) else 'blocked'}  ·  SlowDNS {'enabled' if data.get('slowdns', {}).get('enabled') else 'disabled'}  ·  Telegram {safe(statuses.get('abdulbasit-bot', 'unavailable'))}\n")
    groups = [
        ("ACCESS & ACCOUNTS", [(1,"Create VIP Xray profile"),(2,"Fast 24-hour trial"),(3,"Measured GB & live connections"),(4,"Telegram bot menu"),(5,"Renew / edit GB limit"),(6,"Lock Xray / SSH account"),(7,"Unlock / reset Xray usage"),(8,"Delete managed account"),(9,"View config · secrets redacted"),(10,"List Xray & SSH accounts")]),
        ("SYSTEM & NETWORK", [(11,"Memory / journal retention"),(12,"Restart managed gateway"),(13,"Auto-doctor / repair"),(14,"Live service error journal"),(15,"UDP / SlowDNS transport menu"),(16,"15-second packet loss test"),(17,"Domain / SSL menu"),(18,"SSH banner menu"),(19,"Reinstall · private checkpoint"),(20,"Uninstall · root confirmation")]),
        ("DELIVERY & RECOVERY", [(21,"Web login / resolvers / diagnostics"),(22,"Xray links / exports / subscriptions"),(23,"Private Xray backup / restore"),(0,"Exit")])]
    for title, items in groups:
        print(f"{p['green']}{title}{p['reset']}")
        for number, label in items: print(f"  {p['cyan']}{number:02}{p['reset']}  {label}")
        print()


if __name__ == "__main__":
    try: render(request("dashboard_status"), request("live_connections"), color=sys.stdout.isatty())
    except (RuntimeError, OSError, KeyError) as exc: print(f"NOWAY dashboard unavailable: {exc}. Use diagnostics / journal to inspect the daemon.")
