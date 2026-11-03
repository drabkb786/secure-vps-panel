#!/usr/bin/env bash
# Run by install.sh after application files exist. Never edits admin sshd_config.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
config_dir=/etc/abdulbasit-sshd
backup_dir="/etc/abdulbasit/backups/openssh-$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -m 0700 "$backup_dir" "$config_dir"
install -d -m 0755 /run/sshd
getent group abdulbasit-tunnel >/dev/null || groupadd --system abdulbasit-tunnel
PYTHONPATH=/usr/local/lib/abdulbasit python3 - <<'PY'
import pwd, subprocess
from common import USERS_DIR, read_json, validate_username
for path in USERS_DIR.glob('*.json'):
    data = read_json(path, {})
    name = validate_username(str(data.get('username', path.stem)))
    if name != path.stem:
        raise SystemExit('Managed username does not match metadata filename')
    try:
        user = pwd.getpwnam(name)
    except KeyError:
        continue
    if user.pw_uid >= 1000 and user.pw_shell == '/usr/local/lib/abdulbasit/tunnel-shell':
        subprocess.run(['/usr/sbin/usermod', '-a', '-G', 'abdulbasit-tunnel', name], check=True)
PY
for type in ed25519 rsa; do
  key="$config_dir/ssh_host_${type}_key"
  if [[ ! -f "$key" ]]; then
    ssh-keygen -q -t "$type" -N '' -f "$key"
  fi
done
PYTHONPATH=/usr/local/lib/abdulbasit python3 -m ssh_backend > "$config_dir/sshd_config.candidate"
/usr/sbin/sshd -t -f "$config_dir/sshd_config.candidate"
was_dropbear=0
was_openssh=0
systemctl is-active --quiet dropbear && was_dropbear=1
systemctl is-active --quiet abdulbasit-sshd && was_openssh=1
[[ ! -f "$config_dir/sshd_config" ]] || cp -a "$config_dir/sshd_config" "$backup_dir/sshd_config"
[[ ! -f /etc/abdulbasit/ssh-backend ]] || cp -a /etc/abdulbasit/ssh-backend "$backup_dir/ssh-backend"
for port in 109 447; do
  listener="$(ss -H -ltnp "sport = :$port")"
  if [[ -n "$listener" ]]; then
    if [[ "$was_openssh" == 1 ]]; then
      if printf '%s' "$listener" | grep -qv '"sshd"'; then
        echo "Port $port has an unexpected owner; refusing migration" >&2; exit 1
      fi
    elif ! printf '%s' "$listener" | grep -q '"dropbear"'; then
      echo "Port $port belongs to another service; refusing migration" >&2; exit 1
    fi
  fi
done
rollback() {
  trap - ERR
  systemctl stop abdulbasit-sshd || true
  if [[ -f "$backup_dir/sshd_config" ]]; then
    cp -a "$backup_dir/sshd_config" "$config_dir/sshd_config"
  else
    rm -f "$config_dir/sshd_config"
  fi
  if [[ -f "$backup_dir/ssh-backend" ]]; then
    cp -a "$backup_dir/ssh-backend" /etc/abdulbasit/ssh-backend
  else
    rm -f /etc/abdulbasit/ssh-backend
  fi
  if [[ $was_dropbear == 1 ]]; then systemctl start dropbear || true; fi
  if [[ $was_openssh == 1 ]]; then systemctl start abdulbasit-sshd || true; fi
  echo "Managed SSH migration rolled back. Inspect journalctl -u abdulbasit-sshd. Admin SSH was not reconfigured." >&2
  exit 1
}
trap rollback ERR
install -m 0644 "$root_dir/systemd/abdulbasit-sshd.service" /etc/systemd/system/abdulbasit-sshd.service
mv "$config_dir/sshd_config.candidate" "$config_dir/sshd_config"
systemctl daemon-reload
if [[ $was_dropbear == 1 ]]; then systemctl stop dropbear; fi
if [[ $was_openssh == 1 ]]; then systemctl reload abdulbasit-sshd; else systemctl start abdulbasit-sshd; fi
python3 - <<'PY'
import socket, time
for port in (109, 447):
    deadline = time.monotonic() + 10
    while True:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1) as s:
                s.settimeout(1)
                if s.recv(255).startswith(b'SSH-2.0-OpenSSH_'):
                    break
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise SystemExit(f'OpenSSH readiness failed on {port}')
        time.sleep(.1)
PY
systemctl enable abdulbasit-sshd
systemctl disable dropbear
printf '%s\n' openssh > /etc/abdulbasit/ssh-backend
chmod 0644 /etc/abdulbasit/ssh-backend
cat > /etc/fail2ban/jail.d/abdulbasit-sshd.local <<'EOF'
[abdulbasit-sshd]
enabled = true
filter = sshd
backend = systemd
journalmatch = _SYSTEMD_UNIT=abdulbasit-sshd.service
port = 109,447
ignoreip = 127.0.0.1/8 ::1
maxretry = 5
findtime = 10m
bantime = 1h
EOF
rm -f /etc/fail2ban/jail.d/abdulbasit-dropbear.local
trap - ERR
echo 'Managed OpenSSH ready on 109/447. Host keys changed from Dropbear; verify these fingerprints in clients:'
ssh-keygen -lf "$config_dir/ssh_host_ed25519_key.pub"
ssh-keygen -lf "$config_dir/ssh_host_rsa_key.pub"
