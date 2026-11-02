#!/usr/bin/env bash
# Build an official, pinned Dropbear only in a caller-supplied test directory.
# Does not install or restart the system SSH service.
set -euo pipefail
test_dir="${1:?Usage: fetch-test-dropbear.sh TEST_DIRECTORY}"
mkdir -p "$test_dir"
test_dir="$(cd -- "$test_dir" && pwd)"
version=2026.94
archive="$test_dir/dropbear-$version.tar.bz2"
curl --fail --location --proto '=https' --tlsv1.2 --retry 2 --max-time 90 \
  "https://matt.ucc.asn.au/dropbear/releases/dropbear-$version.tar.bz2" -o "$archive"
printf '%s  %s\n' 'e098034a843699200c8c977a991fff73159735bf795d5f72ef672c41a6b1ae81' "$archive" | sha256sum --check --status
tar -xjf "$archive" -C "$test_dir"
cd "$test_dir/dropbear-$version"
./configure --disable-zlib
make -j2 PROGRAMS='dropbear dropbearkey'
printf 'Native test binaries: %s\n' "$PWD"
