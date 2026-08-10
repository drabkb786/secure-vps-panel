#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

DNSTT_COMMIT="${DNSTT_COMMIT:-0c5c52a57d899c05428c116898941761a2ed83c2}"
GO_VERSION="1.26.5"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ "$DNSTT_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo 'DNSTT_COMMIT must be a full commit SHA' >&2; exit 1; }

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

case "$(uname -m)" in
  x86_64|amd64)
    go_arch='amd64'
    go_sha256='5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053'
    ;;
  aarch64|arm64)
    go_arch='arm64'
    go_sha256='fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49'
    ;;
  armv7l|armv7)
    go_arch='armv6l'
    go_sha256='6dae9edab81c13bccf962dec15f1fd2ec26c14a6821b4d2c92dab4130c289d7a'
    ;;
  *) echo "Unsupported Go/DNSTT architecture: $(uname -m)" >&2; exit 1 ;;
esac

go_archive="go${GO_VERSION}.linux-${go_arch}.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "https://go.dev/dl/${go_archive}" -o "$tmp_dir/$go_archive"
printf '%s  %s\n' "$go_sha256" "$tmp_dir/$go_archive" | sha256sum --check
mkdir -p "$tmp_dir/toolchain"
tar -xzf "$tmp_dir/$go_archive" -C "$tmp_dir/toolchain"
go_bin="$tmp_dir/toolchain/go/bin/go"

git clone --quiet https://www.bamsoftware.com/git/dnstt.git "$tmp_dir/dnstt"
git -C "$tmp_dir/dnstt" checkout --quiet --detach "$DNSTT_COMMIT"
git -C "$tmp_dir/dnstt" verify-commit "$DNSTT_COMMIT" >/dev/null 2>&1 || \
  echo 'NOTICE: upstream commit has no verifiable Git signature; exact pinned SHA is being built.' >&2
(
  cd "$tmp_dir/dnstt/dnstt-server"
  GOCACHE="$tmp_dir/go-build" GOMODCACHE="$tmp_dir/go-mod" GOPATH="$tmp_dir/go-path" \
    GOTOOLCHAIN=local CGO_ENABLED=0 "$go_bin" build -trimpath -buildvcs=false \
    -ldflags='-s -w' -o "$tmp_dir/dnstt-server" .
)
install -m 0755 -o root -g root "$tmp_dir/dnstt-server" /usr/local/bin/dnstt-server
/usr/local/bin/dnstt-server -h >/dev/null 2>&1 || true
