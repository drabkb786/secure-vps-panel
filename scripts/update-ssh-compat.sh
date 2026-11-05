#!/usr/bin/env bash
# Apply backed-up application updates to either managed SSH backend.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
app_dir=/usr/local/lib/abdulbasit
ssh_config=/etc/abdulbasit-sshd/sshd_config
nginx_config=/etc/nginx/conf.d/abdulbasit-vpn.conf
generator_args=()
sync_source=0
for option in "$@"; do
  case "$option" in
    --legacy-crypto) generator_args+=(--legacy-crypto) ;;
    --sync-source) sync_source=1 ;;
    *) echo 'Usage: update-ssh-compat.sh [--legacy-crypto] [--sync-source]' >&2; exit 1 ;;
  esac
done
backend="$(cat /etc/abdulbasit/ssh-backend)"
case "$backend" in
  openssh) ssh_unit=abdulbasit-sshd ;;
  dropbear|dropbear-2026) ssh_unit=dropbear ;;
  *) echo 'Requires an existing managed SSH installation' >&2; exit 1 ;;
esac
[[ $backend == openssh || ${#generator_args[@]} == 0 ]] || { echo '--legacy-crypto applies only to managed OpenSSH' >&2; exit 1; }
exec 9>/run/noway-ssh-update.lock
flock -n 9 || { echo 'Another SSH compatibility update is running' >&2; exit 1; }
modules=(common ws_proxy paneld panel_client panelctl web_server ssh_backend ssh_identity ssh_sessions dropbear_sessions openssh_sessions session_enforcer traffic account_policy ssh_meter cdn_manager bunny_manager diagnostics operations ssh_profiles ssh_ws_client xray_manager client_formats profile_backup reality_transport)
assets=(index.html app.js accounts.js accounts.css)
files=("$nginx_config")
if [[ $backend == openssh ]]; then files+=("$ssh_config"); fi
for module in "${modules[@]}"; do files+=("$app_dir/$module.py"); done
for asset in "${assets[@]}"; do files+=("$app_dir/web/$asset"); done
if [[ $sync_source == 1 ]]; then
  [[ -d $project_dir/src && ! -L $project_dir/src ]] || { echo 'Unsafe source directory' >&2; exit 1; }
  for module in "${modules[@]}"; do files+=("$project_dir/src/$module.py"); done
  for asset in "${assets[@]}"; do files+=("$project_dir/src/web/$asset"); done
fi
for file in "${files[@]}"; do
  [[ ! -L $file ]] || { echo "Unsafe update path: $file" >&2; exit 1; }
  if [[ ! -f $file ]]; then
    case "$file" in
      "$app_dir/"*.py|"$app_dir/web/"*)
        [[ ! -e $file ]] || { echo "Non-regular application file: $file" >&2; exit 1; } ;;
      *) echo "Missing required update file: $file" >&2; exit 1 ;;
    esac
  fi
done
PYTHONPATH="$app_dir" /usr/bin/python3 - <<'CHECK'
from common import DOMAIN_FILE, read_text, validate_domain
validate_domain(read_text(DOMAIN_FILE))
CHECK
backup_dir="/etc/abdulbasit/backups/ssh-compat-$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -m 0700 "$backup_dir/files"
for file in "${files[@]}"; do
  if [[ -f $file ]]; then cp -a --parents -- "$file" "$backup_dir/files/"; fi
done
# A manually edited working copy must not silently become the installed release.
# Stage one pinned HEAD; keep original working/installed copies in the backup.
/usr/bin/python3 "$project_dir/scripts/source-snapshot.py" "$project_dir" "$backup_dir/source" "${modules[@]}" --web-assets > "$backup_dir/source-release.json"
cat "$backup_dir/source-release.json"
rollback() {
  local result=${1:-$?}
  local rollback_failed=0
  trap - ERR INT TERM
  echo "Compatibility update failed; restoring files from $backup_dir" >&2
  for file in "${files[@]}"; do
    if [[ -f "$backup_dir/files$file" ]]; then
      cp -a -- "$backup_dir/files$file" "$file" || rollback_failed=1
    else
      rm -f -- "$file" || rollback_failed=1
    fi
  done
  if [[ $backend == openssh ]]; then systemctl reload abdulbasit-sshd || rollback_failed=1; fi
  PYTHONPATH="$app_dir" /usr/bin/python3 - <<'RELOAD' || rollback_failed=1
from paneld import binary
import subprocess
subprocess.run([binary('nginx'), '-t'], check=True)
subprocess.run(['systemctl', 'reload', 'nginx'], check=True)
RELOAD
  systemctl restart abdulbasit-ws abdulbasit-paneld || rollback_failed=1
  systemctl try-restart abdulbasit-web abdulbasit-session-enforcer || rollback_failed=1
  if [[ $rollback_failed == 1 ]]; then echo "Automatic recovery was incomplete; inspect services and $backup_dir" >&2; fi
  exit "$result"
}
trap rollback ERR
trap 'rollback 130' INT
trap 'rollback 143' TERM
for module in "${modules[@]}"; do
  if [[ $sync_source == 1 ]]; then
    cp -- "$backup_dir/source/$module.py" "$project_dir/src/$module.py"
  fi
  install -o root -g root -m 0755 "$backup_dir/source/$module.py" "$app_dir/$module.py"
done
for asset in "${assets[@]}"; do
  if [[ $sync_source == 1 ]]; then cp -- "$backup_dir/source/web/$asset" "$project_dir/src/web/$asset"; fi
  install -o root -g root -m 0644 "$backup_dir/source/web/$asset" "$app_dir/web/$asset"
done
if [[ $backend == openssh ]]; then
  PYTHONPATH="$app_dir" /usr/bin/python3 -m ssh_backend "${generator_args[@]}" > "$backup_dir/sshd.candidate"
  /usr/sbin/sshd -t -f "$backup_dir/sshd.candidate"
  install -o root -g root -m 0644 "$backup_dir/sshd.candidate" "$ssh_config"
  systemctl reload abdulbasit-sshd
fi
PYTHONPATH="$app_dir" /usr/bin/python3 - <<'NGINX'
import paneld
from common import DOMAIN_FILE, read_text, validate_domain
paneld.install_nginx_config(validate_domain(read_text(DOMAIN_FILE)))
NGINX
systemctl restart abdulbasit-ws abdulbasit-paneld
systemctl try-restart abdulbasit-web abdulbasit-session-enforcer
systemctl is-active --quiet "$ssh_unit" abdulbasit-ws abdulbasit-paneld nginx
PYTHONPATH="$app_dir" /usr/bin/python3 - <<'READY'
from panel_client import wait_ready
wait_ready()
print('Panel daemon socket and read-only RPC verified')
READY
PYTHONPATH="$app_dir" /usr/bin/python3 - <<'PROBE'
import socket, time
from common import DOMAIN_FILE, read_text, validate_domain
import ssh_backend
domain = validate_domain(read_text(DOMAIN_FILE))
banner = b'SSH-2.0-OpenSSH_' if ssh_backend.name() == 'openssh' else b'SSH-2.0-dropbear_'
request = (f'GET /ssh/raw HTTP/1.1\r\nHost: {domain}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n').encode()
deadline = time.monotonic() + 12
last = 'No HTTP/SSH reply'
while time.monotonic() < deadline:
    try:
        with socket.create_connection(('127.0.0.1', 80), timeout=1) as peer:
            peer.settimeout(1); peer.sendall(request); data = b''
            while len(data) < 16384:
                chunk = peer.recv(4096)
                if not chunk: break
                data += chunk
                if b'\r\n\r\n' in data:
                    header, body = data.split(b'\r\n\r\n', 1)
                    if not header.startswith(b'HTTP/1.1 101 '):
                        raise RuntimeError(header.split(b'\r\n', 1)[0].decode(errors='replace'))
                    if body.startswith(banner):
                        print('Local gateway -> raw bridge -> managed ' + ssh_backend.name() + ': 101 and SSH banner verified')
                        raise SystemExit(0)
            last = repr(data[:180])
    except (OSError, RuntimeError) as exc:
        last = str(exc)
    time.sleep(.2)
raise SystemExit('Local SSH transport probe failed: ' + last)
PROBE
trap - ERR INT TERM
echo "SSH compatibility update complete. Recovery copy: $backup_dir"
echo 'Public reachability and the actual mobile/NetMod connection still require a client test.'
