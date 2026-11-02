#!/usr/bin/env python3
"""Download pinned official client binaries for isolated compatibility checks only."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import urllib.request

RELEASES = {
    "singbox": ("https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz", "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"),
    "mihomo": ("https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-compatible-v1.19.33.gz", "386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6"),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    for name, (url, digest) in RELEASES.items():
        destination = args.directory / name
        if destination.exists():
            raise SystemExit(f"Refusing to overwrite {destination}; use a fresh test directory")
        with urllib.request.urlopen(url, timeout=90) as response:
            data = response.read(80 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit(f"Official release SHA256 mismatch: {name}")
        if name == "singbox":
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                member = next(item for item in archive.getmembers() if item.name.endswith("/sing-box") and item.isfile())
                binary = archive.extractfile(member).read()
        else:
            binary = gzip.decompress(data)
        destination.write_bytes(binary); destination.chmod(0o755)
        print(f"Verified {name}: {destination}")


if __name__ == "__main__":
    main()
