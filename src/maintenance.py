"""Explicit root-terminal maintenance, never exposed through HTTP or Telegram."""
from __future__ import annotations

import os
import shutil
import pwd
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from common import BASE_DIR, ValidationError, validate_username, read_json

INSTALL_DIR = Path("/usr/local/lib/abdulbasit")
BACKUP_DIR = BASE_DIR / "backups"
UNIT_DIR = Path("/etc/systemd/system")
NGINX_FILE = Path("/etc/nginx/conf.d/abdulbasit-vpn.conf")


def execute(args, timeout=60):
    completed = subprocess.run(args, check=False, text=True, capture_output=True, timeout=timeout)
    if completed.returncode: raise RuntimeError((completed.stderr or completed.stdout)[-1500:])
    return completed.stdout


def backup_installation():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = BACKUP_DIR / ("installation-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".tar.gz")
    # Backups are outside the config snapshot traversal, avoiding recursion.
    with path.open("xb") as handle:
        os.chmod(path, 0o600)
        with tarfile.open(fileobj=handle, mode="w:gz", dereference=False) as archive:
            paths = [INSTALL_DIR, NGINX_FILE, Path("/etc/default/dropbear"), Path("/etc/abdulbasit-xray"), Path("/etc/abdulbasit-dnstt")]
            paths += [p for p in BASE_DIR.iterdir() if p != BACKUP_DIR]
            paths += list(UNIT_DIR.glob("abdulbasit-*"))
            for item in paths:
                if item.exists(): archive.add(item, arcname=str(item).lstrip("/"))
    return str(path)


def run(action, *, source=None, reclaim=False, confirm=input):
    if os.geteuid() != 0: raise ValidationError("Maintenance requires the root terminal")
    prompts = {"clean-logs": "CLEAN OLD LOGS", "reinstall": "REINSTALL NOWAY", "uninstall": "UNINSTALL NOWAY", "memory": "RECLAIM CACHE"}
    if action == "memory" and not reclaim:
        from operations import Manager
        return Manager(None, None, None, None).memory({})
    if action not in prompts: raise ValidationError("Unknown maintenance action")
    if action == "clean-logs": print("This permanently removes old archived SYSTEM journal entries (7-day / 256-MiB retention).")
    if action == "memory": print("This reclaims file caches; automatic Linux cache management is normally preferable.")
    if action == "uninstall": print("This removes panel services/code/routes and locks managed tunnel accounts. Private configuration/backups and normal OpenSSH are retained.")
    if action == "reinstall":
        source = Path(source or "").resolve()
        if not (source / "install.sh").is_file(): raise ValidationError("Provide --source with the reviewed repository checkout")
        for path in (source, source / "install.sh"):
            if path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
                raise ValidationError("Reinstall source and installer must be root-owned and not writable by other users")
    if confirm(f"Type {prompts[action]} to confirm: ").strip() != prompts[action]:
        raise ValidationError("Maintenance cancelled")
    if action == "memory":
        os.sync(); Path("/proc/sys/vm/drop_caches").write_text("3\n")
        return {"done": True, "notice": "File caches reclaimed; Linux normally handles this automatically"}
    if action == "clean-logs":
        # journalctl vacuum operates on the system journal, not per-unit files.
        return {"text": execute([shutil.which("journalctl") or "/bin/journalctl", "--rotate", "--vacuum-time=7d", "--vacuum-size=256M"]),
                "scope": "System journal retention: seven days / 256 MiB; irreversible removal of older archived logs"}
    backup = backup_installation()
    if action == "reinstall":
        return {"backup": backup, "text": execute(["/bin/bash", str(source / "install.sh"), "--non-interactive"], timeout=900)}
    # Require working normal SSH administration before removing panel services.
    if not any(subprocess.run(["/bin/systemctl", "is-active", "--quiet", name]).returncode == 0 for name in ("ssh", "sshd")):
        raise ValidationError("Normal OpenSSH must be active before uninstalling the panel")
    units = sorted({p.name for p in UNIT_DIR.glob("abdulbasit-*") if p.suffix in (".service", ".timer")})
    for unit in units: execute(["/bin/systemctl", "disable", "--now", unit])
    # Lock only managed tunnel accounts. Keep data and a private recovery archive.
    for path in (BASE_DIR / "users").glob("*.json"):
        row = read_json(path, {})
        username = validate_username(str(row.get("username", path.stem)))
        try: account = pwd.getpwnam(username)
        except KeyError: continue
        if account.pw_uid < 1000 or account.pw_shell != "/usr/local/lib/abdulbasit/tunnel-shell": continue
        execute(["/usr/sbin/usermod", "--lock", "--expiredate", "1970-01-02", username])
    if NGINX_FILE.exists():
        original = NGINX_FILE.read_bytes(); NGINX_FILE.unlink()
        try: execute([shutil.which("nginx") or "/usr/sbin/nginx", "-t"])
        except Exception: NGINX_FILE.write_bytes(original); raise
        execute(["/bin/systemctl", "reload", "nginx"])
    for unit in units: (UNIT_DIR / unit).unlink(missing_ok=True)
    for path in (Path("/usr/local/bin/menu"), Path("/usr/bin/menu"), Path("/usr/local/sbin/abdulbasit-menu"), Path("/usr/local/sbin/abdulbasit-panelctl"), Path("/usr/local/sbin/abdulbasit-security-check")):
        if path.is_symlink() or path.is_file(): path.unlink()
    if INSTALL_DIR.is_dir() and not INSTALL_DIR.is_symlink(): shutil.rmtree(INSTALL_DIR)
    execute(["/bin/systemctl", "daemon-reload"])
    return {"uninstalled": True, "backup": backup, "preserved": "Private configuration/backups, locked managed SSH accounts, OpenSSH, Dropbear/Nginx packages and TLS certificates"}
