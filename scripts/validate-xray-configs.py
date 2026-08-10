#!/usr/bin/env python3
"""Validate generated server and client configs with a real Xray binary."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cdn_manager import configure_profile  # noqa: E402
from exporter import client_json  # noqa: E402
from protocols import enable_protocols, render_xray_config  # noqa: E402


def validate(xray: Path, name: str, config: dict, directory: Path) -> None:
    path = directory / f"{name}.json"
    path.write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    result = subprocess.run(
        [str(xray), "run", "-test", "-config", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout or "Xray rejected config").strip()
        raise RuntimeError(f"{name}: {detail}")
    print(f"{name}: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", type=Path, default=Path("/usr/local/bin/xray"))
    args = parser.parse_args()
    if not args.xray.is_file():
        parser.error(f"Xray binary not found: {args.xray}")

    user = enable_protocols(
        {
            "username": "configcheck",
            "expiry": (date.today() + timedelta(days=30)).isoformat(),
            "quota_gb": 10,
            "usage_bytes": 0,
        },
        ["vmess", "vless", "trojan"],
    )
    cloudfront = configure_profile(
        {},
        provider="cloudfront",
        endpoint="d123example.cloudfront.net",
        origin="vpn.example.com",
        origin_secret="C" * 32,
    )
    with tempfile.TemporaryDirectory(
        prefix="abdulbasit-xray-config-check-"
    ) as raw_directory:
        directory = Path(raw_directory)
        validate(args.xray, "server", render_xray_config([user]), directory)
        for provider, cdn in (("direct", {}), ("cloudfront", cloudfront)):
            for protocol in ("vmess", "vless", "trojan"):
                validate(
                    args.xray,
                    f"client-{protocol}-{provider}",
                    client_json(
                        user,
                        protocol,
                        domain="vpn.example.com",
                        provider=provider,
                        cdn_config=cdn,
                    ),
                    directory,
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
