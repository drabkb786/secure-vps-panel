#!/usr/bin/env python3
"""Opt-in, reversible BBR/fq tuning. Does not change MTU, firewall, or DNS."""
import argparse
import json
import os
import subprocess
from pathlib import Path

CONFIG = Path('/etc/sysctl.d/90-noway-network.conf')
BACKUP = Path('/etc/abdulbasit/backups/network-tuning.json')
VALUES = {'net.core.default_qdisc': 'fq', 'net.ipv4.tcp_congestion_control': 'bbr'}


def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True, timeout=10).stdout.strip()


def restore(data):
    for key, value in data['runtime'].items():
        run('sysctl', '-w', key + '=' + value)
    if data['config'] is None:
        CONFIG.unlink(missing_ok=True)
    else:
        CONFIG.write_text(data['config'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['status', 'apply', 'rollback'])
    args = parser.parse_args()
    if args.action == 'status':
        print(json.dumps({key: run('sysctl', '-n', key) for key in VALUES}, indent=2)); return
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    if CONFIG.is_symlink() or BACKUP.is_symlink():
        raise SystemExit('Unsafe configuration path')
    if args.action == 'rollback':
        restore(json.loads(BACKUP.read_text())); BACKUP.unlink(); return
    if BACKUP.exists():
        raise SystemExit('Tuning already applied; rollback first')
    try:
        run('modprobe', 'tcp_bbr')
    except subprocess.CalledProcessError:
        pass  # Can be built into the kernel.
    if 'bbr' not in run('sysctl', '-n', 'net.ipv4.tcp_available_congestion_control').split():
        raise SystemExit('This kernel does not offer BBR; no settings changed')
    data = {'runtime': {key: run('sysctl', '-n', key) for key in VALUES},
            'config': CONFIG.read_text() if CONFIG.exists() else None}
    BACKUP.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(BACKUP, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f)
    try:
        CONFIG.write_text(''.join(key + '=' + value + '\n' for key, value in VALUES.items()))
        for key, value in VALUES.items():
            run('sysctl', '-w', key + '=' + value)
    except Exception:
        restore(data); BACKUP.unlink(); raise
    print('BBR/fq configured for new connections/interfaces. Benchmark your route; throughput improvement is not guaranteed.')


if __name__ == '__main__':
    main()
