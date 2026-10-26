#!/usr/bin/env bash
# Install only the panel's private copy of the official XTLS binary.
set -Eeuo pipefail
umask 077
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
requested_version="${1:-}"
destination=/usr/local/lib/abdulbasit/xray
if [[ -x "$destination" && -z "$requested_version" ]]; then
  "$destination" version
  exit 0
fi
if [[ -z "$requested_version" ]]; then
  requested_version="$(cat "$(dirname -- "${BASH_SOURCE[0]}")/../XRAY_VERSION")"
fi
[[ "$requested_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid Xray release tag' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) asset=Xray-linux-64.zip ;;
  aarch64|arm64) asset=Xray-linux-arm64-v8a.zip ;;
  *) echo 'Supported Xray architectures: x86_64 and arm64' >&2; exit 1 ;;
esac
workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
base_url="https://github.com/XTLS/Xray-core/releases/download/$requested_version"
curl --fail --location --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 --max-time 180 "$base_url/$asset" -o "$workdir/$asset"
curl --fail --location --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 --max-time 60 "$base_url/$asset.dgst" -o "$workdir/digest"
python3 - "$workdir" "$asset" <<'PY'
import hashlib, pathlib, re, sys, zipfile
root = pathlib.Path(sys.argv[1]); archive = root / sys.argv[2]
digest = (root / 'digest').read_text()
match = re.search(r'(?:SHA2-256|SHA256)\s*(?:\([^)]*\))?\s*=\s*([a-f0-9]{64})\b', digest, re.I)
if not match or hashlib.sha256(archive.read_bytes()).hexdigest().lower() != match[1].lower():
    raise SystemExit('Official release SHA256 verification failed')
with zipfile.ZipFile(archive) as handle:
    binary = handle.getinfo('xray')
    if binary.file_size > 300 * 1024 * 1024:
        raise SystemExit('Unexpected Xray binary size')
    (root / 'xray').write_bytes(handle.read(binary))
PY
chmod 0755 "$workdir/xray"
"$workdir/xray" version
if [[ -f /etc/abdulbasit-xray/config.json ]]; then
  "$workdir/xray" run -test -config /etc/abdulbasit-xray/config.json
fi
if [[ -f "$destination" ]]; then
  install -d -m 0700 /etc/abdulbasit/backups
  cp -a "$destination" "/etc/abdulbasit/backups/xray.$(date -u +%Y%m%dT%H%M%SZ)"
fi
install -m 0755 -o root -g root "$workdir/xray" "$destination.new"
mv -f "$destination.new" "$destination"
echo "Installed official Xray $requested_version (SHA256 verified)"
