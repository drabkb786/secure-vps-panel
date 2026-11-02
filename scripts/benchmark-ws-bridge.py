#!/usr/bin/env python3
"""Reproducible loopback WS bridge benchmark; not an internet/SSH/CDN speed claim."""
import argparse
import hashlib
import json
import platform
import socketserver
import statistics
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websockets.sync.client import connect
import ws_proxy as bridge


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536): self.request.sendall(data)
        except OSError: pass


@contextmanager
def running(server):
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
    thread.start()
    try: yield server.server_address[1]
    finally: server.shutdown(); server.server_close(); thread.join(3)


def measure(port, payload):
    with connect(f"ws://127.0.0.1:{port}/ssh/ws", compression=None, proxy=None, max_size=None, open_timeout=5, close_timeout=2) as ws:
        started = time.perf_counter()
        sender = threading.Thread(target=lambda: ws.send([payload[i:i+65536] for i in range(0, len(payload), 65536)]), daemon=True)
        sender.start()
        result = bytearray()
        while len(result) < len(payload): result.extend(ws.recv(timeout=10))
        sender.join(10)
        elapsed = time.perf_counter() - started
        assert not sender.is_alive() and hashlib.sha256(result).digest() == hashlib.sha256(payload).digest()
        return round(len(payload) / 1024**2 / elapsed, 2)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--mib", type=int, default=1)
    args = p.parse_args()
    if not 3 <= args.rounds <= 30 or not 1 <= args.mib <= 8: p.error("Use 3-30 rounds and 1-8 MiB")
    payload = bytes(range(256)) * (args.mib * 4096)
    results = {16384: [], 65536: []}
    with running(socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)) as target:
        bridge.TARGET_PORT = target
        with running(bridge.Server(("127.0.0.1", 0), bridge.Handler)) as port:
            measure(port, payload)  # warm-up, excluded
            for i in range(args.rounds):
                for chunk in ([16384, 65536] if i % 2 == 0 else [65536, 16384]):
                    bridge.IO_CHUNK = chunk
                    bridge.TCP_NODELAY = chunk == 65536
                    value = measure(port, payload)
                    results[chunk].append(value)
                    print(f"round={i+1} chunk={chunk} nodelay={bridge.TCP_NODELAY} MiB/s={value}", file=sys.stderr, flush=True)
    print(json.dumps({"profiles": {"16384": "previous: 16 KiB reads, default Nagle", "65536": "candidate: 64 KiB reads, TCP_NODELAY"}, "scope": "Loopback RFC6455 binary WS to TCP echo; excludes SSH encryption, TLS, AWS and WAN", "python": platform.python_version(), "platform": platform.machine(), "payload_mib": args.mib, "rounds": args.rounds, "unit": "MiB/s of verified round-trip payload (not summed send+receive)", "measurements": {str(k): {"samples": v, "median": statistics.median(v)} for k, v in results.items()}}, indent=2))


if __name__ == "__main__": main()
