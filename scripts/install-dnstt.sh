#!/usr/bin/env bash
# Build the official pinned module through the public Go checksum database.
set -Eeuo pipefail
umask 077
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root'; exit 1; }
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
case "$(uname -m)" in
  x86_64) arch=amd64; digest=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
  aarch64|arm64) arch=arm64; digest=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
  *) echo 'Supported build architectures: amd64, arm64'; exit 1 ;;
esac
curl --fail --location --proto '=https' --tlsv1.2 --max-time 180 \
  "https://go.dev/dl/go1.27.3.linux-$arch.tar.gz" --output "$work_dir/go.tar.gz"
printf '%s  %s\n' "$digest" "$work_dir/go.tar.gz" | sha256sum --check --status
tar -xzf "$work_dir/go.tar.gz" -C "$work_dir"
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export GOPRIVATE='' GONOSUMDB='' GONOPROXY='' GOINSECURE='' GOTOOLCHAIN=local
export GOBIN="$work_dir/bin" GOPATH="$work_dir/gopath" GOCACHE="$work_dir/cache"
"$work_dir/go/bin/go" install www.bamsoftware.com/git/dnstt.git/dnstt-server@v1.20260501.0
"$work_dir/go/bin/go" version -m "$work_dir/bin/dnstt-server"
install -d -m 0755 -o root -g root /usr/local/lib/abdulbasit
install -m 0755 -o root -g root "$work_dir/bin/dnstt-server" /usr/local/lib/abdulbasit/dnstt-server
echo 'Official dnstt v1.20260501.0 installed. Configure zone/NS and UDP port in NOWAY; it is not automatically exposed.'
