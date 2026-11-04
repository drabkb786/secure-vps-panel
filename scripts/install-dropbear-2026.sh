#!/usr/bin/env bash
# Install the same checksum-pinned upstream release used by native acceptance.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
app_dir=/usr/local/lib/abdulbasit
version=2026.94
for target in "$app_dir" "$app_dir/dropbear" "$app_dir/dropbearkey"; do
  [[ ! -L $target ]] || { echo "Unsafe Dropbear install path: $target" >&2; exit 1; }
done
if /usr/bin/python3 - "$app_dir/dropbear" "$app_dir/dropbearkey" <<'TRUST'
import os, stat, sys
for name in sys.argv[1:]:
    try: info = os.stat(name, follow_symlinks=False)
    except FileNotFoundError: raise SystemExit(1)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit(1)
TRUST
then
  installed_version="$($app_dir/dropbear -V 2>&1)"
  if [[ $installed_version == "Dropbear v$version"* ]]; then
    echo "Pinned Dropbear $version already installed; compilation skipped"
    exit 0
  fi
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends build-essential libcrypt-dev bzip2 curl ca-certificates
install -d -m 0700 /var/cache/abdulbasit
build_dir="$(mktemp -d /var/cache/abdulbasit/dropbear-build.XXXXXXXX)"
build_log="$build_dir/build.log"
echo "Building official Dropbear $version; log: $build_log"
setsid env -u CFLAGS -u CPPFLAGS -u LDFLAGS CC=/usr/bin/gcc \
  bash "$project_dir/scripts/fetch-test-dropbear.sh" "$build_dir" >"$build_log" 2>&1 &
build_pid=$!
trap 'kill -- -"$build_pid" 2>/dev/null || true; wait "$build_pid" 2>/dev/null || true; exit 130' INT TERM
while kill -0 "$build_pid" 2>/dev/null; do
  sleep 5
  if kill -0 "$build_pid" 2>/dev/null; then echo "Dropbear $version build is running; details: $build_log"; fi
done
if ! wait "$build_pid"; then tail -n 30 "$build_log" >&2; exit 1; fi
trap - INT TERM
candidate="$build_dir/dropbear-$version"
[[ $("$candidate/dropbear" -V 2>&1) == "Dropbear v$version"* ]] || { echo 'Unexpected built Dropbear version' >&2; exit 1; }
install -o root -g root -m 0755 "$candidate/dropbear" "$app_dir/dropbear"
install -o root -g root -m 0755 "$candidate/dropbearkey" "$app_dir/dropbearkey"
echo "Installed Dropbear $version in $app_dir; services have not been switched"
