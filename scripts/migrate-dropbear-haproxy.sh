#!/usr/bin/env bash
# Explicit managed-tunnel migration; never rebuilds Python/OpenSSL/Nginx.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec 8>/run/noway-gateway-prepare.lock
flock -n 8 || { echo 'Another gateway preparation is running' >&2; exit 1; }
if [[ $# -gt 0 ]]; then
  [[ $# == 2 && $1 == --rollback ]] || { echo 'Usage: migrate-dropbear-haproxy.sh [--rollback BACKUP_DIRECTORY]' >&2; exit 1; }
  exec /usr/bin/python3 "$project_dir/scripts/migrate-dropbear-haproxy.py" "$@"
fi
bash "$project_dir/scripts/update-ssh-compat.sh" --sync-source
if ! command -v haproxy >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends haproxy
fi
bash "$project_dir/scripts/install-dropbear-2026.sh"
exec /usr/bin/python3 "$project_dir/scripts/migrate-dropbear-haproxy.py"
