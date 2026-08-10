#!/usr/bin/env python3
"""Exercise VMess, VLESS and Trojan through real Xray SOCKS/WS data paths."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from exporter import client_json  # noqa: E402
from protocols import enable_protocols, protocol_email, render_xray_config  # noqa: E402
from usage_collector import parse_stats  # noqa: E402


class SmokeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = f"abdulbasit-xray-smoke:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def reserve_port(used: set[int]) -> int:
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in used:
            used.add(port)
            return port


def process_detail(process: subprocess.Popen[bytes], log_path: Path) -> str:
    if process.poll() is None:
        return "process is still running"
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    return lines[-1][:500] if lines else f"exit status {process.returncode}"


def wait_tcp(
    port: int, process: subprocess.Popen[bytes], log_path: Path, timeout: float = 10
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(process_detail(process, log_path))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for TCP port {port}")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("SOCKS proxy closed the connection early")
        data.extend(chunk)
    return bytes(data)


def socks_http_request(socks_port: int, target_port: int, protocol: str) -> bytes:
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS proxy rejected no-auth negotiation")
        sock.sendall(
            b"\x05\x01\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + struct.pack("!H", target_port)
        )
        reply = recv_exact(sock, 4)
        if reply[:2] != b"\x05\x00":
            raise RuntimeError(f"SOCKS connect failed with status {reply[1]}")
        if reply[3] == 1:
            recv_exact(sock, 4)
        elif reply[3] == 3:
            recv_exact(sock, recv_exact(sock, 1)[0])
        elif reply[3] == 4:
            recv_exact(sock, 16)
        else:
            raise RuntimeError("SOCKS proxy returned an unknown address type")
        recv_exact(sock, 2)
        path = f"/smoke/{protocol}"
        sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: smoke.invalid\r\nConnection: close\r\n\r\n".encode(
                "ascii"
            )
        )
        response = bytearray()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
        return bytes(response)


def xray_environment(xray: Path) -> dict[str, str]:
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    local_assets = xray.resolve().parent
    if (local_assets / "geoip.dat").is_file():
        environment["XRAY_LOCATION_ASSET"] = str(local_assets)
    elif Path("/usr/local/share/xray/geoip.dat").is_file():
        environment["XRAY_LOCATION_ASSET"] = "/usr/local/share/xray"
    return environment


def start_xray(
    xray: Path, config: Path, log_path: Path, environment: dict[str, str]
) -> tuple[subprocess.Popen[bytes], BinaryIO]:
    log_handle = log_path.open("wb")
    process = subprocess.Popen(
        [str(xray), "run", "-config", str(config)],
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        cwd=config.parent,
        env=environment,
    )
    return process, log_handle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", type=Path, default=Path("/usr/local/bin/xray"))
    args = parser.parse_args()
    xray = args.xray.resolve()
    if not xray.is_file() or not os.access(xray, os.X_OK):
        parser.error(f"Xray binary is not executable: {xray}")

    used_ports: set[int] = set()
    protocol_ports = {
        protocol: reserve_port(used_ports)
        for protocol in ("vmess", "vless", "trojan")
    }
    api_port = reserve_port(used_ports)
    user = enable_protocols(
        {
            "username": "smoketest",
            "expiry": (date.today() + timedelta(days=2)).isoformat(),
            "quota_gb": 1,
            "usage_bytes": 0,
        },
        ["vmess", "vless", "trojan"],
    )

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), SmokeHandler)
    http_port = int(httpd.server_address[1])
    http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    http_thread.start()

    environment = xray_environment(xray)
    try:
        with tempfile.TemporaryDirectory(prefix="abdulbasit-xray-live-") as raw_dir:
            directory = Path(raw_dir)
            server_config = render_xray_config([user])
            server_config["api"]["listen"] = f"127.0.0.1:{api_port}"
            for inbound in server_config["inbounds"]:
                inbound["port"] = protocol_ports[inbound["protocol"]]
            server_config["routing"]["rules"].insert(
                0,
                {
                    "type": "field",
                    "ip": ["127.0.0.1"],
                    "port": str(http_port),
                    "outboundTag": "direct",
                },
            )
            server_path = directory / "server.json"
            server_path.write_text(
                json.dumps(server_config, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            server_log = directory / "server.log"
            server_process, server_log_handle = start_xray(
                xray, server_path, server_log, environment
            )
            try:
                for port in (*protocol_ports.values(), api_port):
                    wait_tcp(port, server_process, server_log)

                for protocol in ("vmess", "vless", "trojan"):
                    socks_port = reserve_port(used_ports)
                    config = client_json(
                        user, protocol, domain="vpn.example.com", cdn_config={}
                    )
                    config["inbounds"][0]["port"] = socks_port
                    outbound = config["outbounds"][0]
                    if protocol in {"vmess", "vless"}:
                        target_server = outbound["settings"]["vnext"][0]
                    else:
                        target_server = outbound["settings"]["servers"][0]
                    target_server["address"] = "127.0.0.1"
                    target_server["port"] = protocol_ports[protocol]
                    stream = outbound["streamSettings"]
                    stream["security"] = "none"
                    stream.pop("tlsSettings", None)
                    client_path = directory / f"client-{protocol}.json"
                    client_path.write_text(
                        json.dumps(config, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    client_log = directory / f"client-{protocol}.log"
                    client, client_log_handle = start_xray(
                        xray, client_path, client_log, environment
                    )
                    try:
                        wait_tcp(socks_port, client, client_log)
                        response = socks_http_request(
                            socks_port, http_port, protocol
                        )
                        expected = f"abdulbasit-xray-smoke:/smoke/{protocol}".encode()
                        if b"HTTP/1.1 200 OK" not in response or expected not in response:
                            client_log_handle.flush()
                            server_log_handle.flush()
                            client_detail = client_log.read_text(
                                encoding="utf-8", errors="replace"
                            ).strip()[-1000:]
                            server_detail = server_log.read_text(
                                encoding="utf-8", errors="replace"
                            ).strip()[-1000:]
                            raise RuntimeError(
                                f"{protocol} did not carry the expected HTTP response: "
                                f"{response[:500]!r}; client={client_detail!r}; "
                                f"server={server_detail!r}"
                            )
                        print(f"live-{protocol}-ws-socks: PASS")
                    finally:
                        stop_process(client)
                        client_log_handle.close()

                query = subprocess.run(
                    [
                        str(xray),
                        "api",
                        "statsquery",
                        f"--server=127.0.0.1:{api_port}",
                        "-pattern",
                        "user>>>",
                        "-reset",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=15,
                    env=environment,
                )
                if query.returncode:
                    raise RuntimeError(
                        (query.stderr or query.stdout or "Stats API query failed")
                        .strip()
                        .splitlines()[-1]
                    )
                totals = parse_stats(query.stdout)
                if totals.get(protocol_email("smoketest"), 0) <= 0:
                    raise RuntimeError(
                        "Stats API did not report live user traffic: "
                        + query.stdout.strip()[-2000:]
                    )
                after_reset = subprocess.run(
                    [
                        str(xray),
                        "api",
                        "statsquery",
                        f"--server=127.0.0.1:{api_port}",
                        "-pattern",
                        "user>>>",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=15,
                    env=environment,
                )
                if after_reset.returncode:
                    raise RuntimeError(
                        (
                            after_reset.stderr
                            or after_reset.stdout
                            or "Stats API reset verification failed"
                        )
                        .strip()
                        .splitlines()[-1]
                    )
                if parse_stats(after_reset.stdout).get(
                    protocol_email("smoketest"), 0
                ):
                    raise RuntimeError("Stats API counters were not reset")
                print("live-stats-query-reset: PASS")
            finally:
                stop_process(server_process)
                server_log_handle.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        http_thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
