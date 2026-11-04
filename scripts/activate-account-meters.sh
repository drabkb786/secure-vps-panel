#!/usr/bin/env bash
# Explicit installed-VPS activation, with backup and a scoped Xray rollback.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
app_dir=/usr/local/lib/abdulbasit
exec 7>/run/noway-meter-upgrade.lock
flock -n 7 || { echo 'Another meter activation is running' >&2; exit 1; }
bash "$project_dir/scripts/update-ssh-compat.sh" --sync-source
install -m 0644 "$project_dir/systemd/abdulbasit-ssh-meter.service" /etc/systemd/system/abdulbasit-ssh-meter.service
systemctl daemon-reload
systemctl enable --now abdulbasit-ssh-meter
# The migration has its own backed-up gateway/SSH rollback and preserves users.
bash "$project_dir/scripts/migrate-dropbear-haproxy.sh"
systemctl restart abdulbasit-ssh-meter dropbear
if [[ -x "$app_dir/xray" ]]; then
  if ! "$app_dir/xray" version | grep -q 'noway-ip-meter-v1'; then
    install -d -m 0700 /var/cache/abdulbasit /etc/abdulbasit/backups
    build_dir="$(mktemp -d /var/cache/abdulbasit/xray-meter.XXXXXXXX)"
    echo "Building metered Xray from pinned upstream source. Log: $build_dir/build.log"
    bash "$project_dir/scripts/build-xray-meter.sh" "$build_dir" > "$build_dir/build.log" 2>&1 &
    build_pid=$!
    trap 'kill "$build_pid" 2>/dev/null || true; wait "$build_pid" 2>/dev/null || true; exit 130' INT TERM
    while kill -0 "$build_pid" 2>/dev/null; do
      sleep 5
      if kill -0 "$build_pid" 2>/dev/null; then echo "Xray meter build is running; log: $build_dir/build.log"; fi
    done
    if ! wait "$build_pid"; then tail -n 30 "$build_dir/build.log" >&2; exit 1; fi
    trap - INT TERM
    if [[ -f /etc/abdulbasit-xray/config.json ]]; then "$build_dir/xray" run -test -config /etc/abdulbasit-xray/config.json; fi
    "$app_dir/panelctl.py" traffic
    backup="/etc/abdulbasit/backups/xray-before-meter-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    cp -a "$app_dir/xray" "$backup"
    active=0; systemctl is-active --quiet abdulbasit-xray && active=1
    rollback() {
      trap - ERR
      install -m 0755 "$backup" "$app_dir/xray"
      if [[ $active == 1 ]]; then systemctl restart abdulbasit-xray || true; fi
      echo "Previous Xray restored from $backup" >&2
      exit 1
    }
    trap rollback ERR
    install -m 0755 "$build_dir/xray" "$app_dir/xray.new"
    mv -f "$app_dir/xray.new" "$app_dir/xray"
    if [[ $active == 1 ]]; then
      systemctl restart abdulbasit-xray
      for attempt in {1..40}; do
        if "$app_dir/xray" api statsquery --server=unix:///run/abdulbasit-xray/stats.sock -t=1 -pattern=user\>\>\>noway-meter | grep -q 'version'; then break; fi
        [[ $attempt != 40 ]]; sleep .25
      done
    fi
    trap - ERR
    install -m 0644 "$build_dir/XRAY-LICENSE" "$app_dir/XRAY-METER-LICENSE"
  fi
fi
systemctl try-restart abdulbasit-paneld abdulbasit-web abdulbasit-session-enforcer
"$app_dir/panelctl.py" diagnostics
echo 'Metered backend activation complete. Existing traffic before activation cannot be reconstructed.'
