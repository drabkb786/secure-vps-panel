#!/usr/bin/env bash
# Reproducible modified build; official source pinned to an immutable commit.
set -Eeuo pipefail
build_dir="${1:?Usage: build-xray-meter.sh BUILD_DIRECTORY}"
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$build_dir"
build_dir="$(cd -- "$build_dir" && pwd)"
if [[ ! -d "$build_dir/source/.git" ]]; then
  git clone --depth 1 --branch v26.10.31 https://github.com/XTLS/Xray-core.git "$build_dir/source"
fi
[[ $(git -C "$build_dir/source" rev-parse HEAD) == a4a3dff5b20c2faae567b742c172c7b95e75c083 ]] || { echo 'Pinned Xray source verification failed' >&2; exit 1; }
[[ -z $(git -C "$build_dir/source" status --porcelain) ]] || { echo 'Build source must be a clean pinned checkout; choose a new directory' >&2; exit 1; }
go_binary="${NOWAY_GO_BINARY:-}"
if [[ -z "$go_binary" ]]; then
  case "$(uname -m)" in
    x86_64) go_arch=amd64; go_sha=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
    aarch64|arm64) go_arch=arm64; go_sha=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
    *) echo 'Supported build architectures: amd64/arm64' >&2; exit 1 ;;
  esac
  curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --max-time 180 "https://go.dev/dl/go1.27.3.linux-$go_arch.tar.gz" -o "$build_dir/go.tar.gz"
  printf '%s  %s\n' "$go_sha" "$build_dir/go.tar.gz" | sha256sum --check --status
  tar -xzf "$build_dir/go.tar.gz" -C "$build_dir"
  go_binary="$build_dir/go/bin/go"
fi
python3 "$project_dir/scripts/patch-xray-meter.py" "$build_dir/source"
cd "$build_dir/source"
GOMAXPROCS=2 CGO_ENABLED=0 "$go_binary" build -p 2 -trimpath \
  -ldflags='-s -w -X github.com/xtls/xray-core/core.build=noway-ip-meter-v1' -o "$build_dir/xray" ./main
"$build_dir/xray" version
cp LICENSE "$build_dir/XRAY-LICENSE"
echo "Modified metered Xray build: $build_dir/xray"
