#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

XRAY_VERSION="v26.3.27"
BASE_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }

case "$(uname -m)" in
  x86_64|amd64)
    asset='Xray-linux-64.zip'
    expected='23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae'
    ;;
  aarch64|arm64)
    asset='Xray-linux-arm64-v8a.zip'
    expected='4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c'
    ;;
  armv7l|armv7)
    asset='Xray-linux-arm32-v7a.zip'
    expected='c7265ae13c63ca0241a037df4ef960ad37938c8a67d984cc08834b2cfdf5654b'
    ;;
  *) echo "Unsupported Xray architecture: $(uname -m)" >&2; exit 1 ;;
esac

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "$BASE_URL/$asset" -o "$tmp_dir/$asset"
actual="$(sha256sum "$tmp_dir/$asset" | awk '{print $1}')"
[[ "$actual" == "$expected" ]] || { echo 'Xray SHA-256 verification failed' >&2; exit 1; }

unzip -q "$tmp_dir/$asset" xray geoip.dat geosite.dat -d "$tmp_dir/unpacked"
install -m 0755 -o root -g root "$tmp_dir/unpacked/xray" /usr/local/bin/xray
install -d -m 0755 -o root -g root /usr/local/share/xray
install -m 0644 -o root -g root "$tmp_dir/unpacked/geoip.dat" /usr/local/share/xray/geoip.dat
install -m 0644 -o root -g root "$tmp_dir/unpacked/geosite.dat" /usr/local/share/xray/geosite.dat
/usr/local/bin/xray version
