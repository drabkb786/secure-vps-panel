#!/usr/bin/env python3
"""Opt-in reversible BBR/fq and optional PMTU-based TCP MSS clamping."""
import argparse
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

CONFIG = Path('/etc/sysctl.d/90-noway-network.conf')
BACKUP = Path('/etc/abdulbasit/backups/network-tuning.json')
UNIT = Path('/etc/systemd/system/noway-network-mss.service')
HELPER = Path('/usr/local/lib/abdulbasit/network-tuning-helper.py')
VALUES = {'net.core.default_qdisc': 'fq', 'net.ipv4.tcp_congestion_control': 'bbr'}
RULE = ('-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-m', 'comment',
        '--comment', 'NOWAY managed PMTU MSS', '-j', 'TCPMSS', '--clamp-mss-to-pmtu')


def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True, timeout=10).stdout.strip()


def secure_parent(path, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True, mode=mode)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f'Unsafe maintenance directory: {parent}')


def save(data):
    with tempfile.NamedTemporaryFile(mode='w', dir=BACKUP.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle)
            handle.flush()
            os.fsync(handle.fileno())
            temporary.replace(BACKUP)
        finally:
            temporary.unlink(missing_ok=True)


def rule_present(tool, chain):
    try:
        run(tool, '--wait', '5', '-t', 'mangle', '-C', chain, *RULE)
        return True
    except subprocess.CalledProcessError as exc:
        if exc.returncode != 1:
            raise
        return False


def mss_entries(data):
    entries = data.get('mss', [])
    if not isinstance(entries, list):
        raise RuntimeError('Invalid managed firewall receipt')
    for entry in entries:
        if (not isinstance(entry, dict) or entry.get('tool') not in ('iptables', 'ip6tables')
                or entry.get('chain') not in ('OUTPUT', 'FORWARD') or type(entry.get('owned')) is not bool):
            raise RuntimeError('Invalid managed firewall receipt')
    return entries


def apply_mss(data):
    for entry in mss_entries(data):
        tool, chain = entry['tool'], entry['chain']
        if not rule_present(tool, chain):
            # Persist ownership intent before insertion so rollback survives an
            # interruption. Only this exact tagged rule can ever be removed.
            entry['owned'] = True
            save(data)
            run(tool, '--wait', '5', '-t', 'mangle', '-I', chain, '1', *RULE)


def install_persistence(data):
    data['persistence'] = True
    save(data)
    HELPER.write_bytes(Path(__file__).read_bytes())
    HELPER.chmod(0o755)
    UNIT.write_text('[Unit]\nDescription=NOWAY managed TCP MSS rules\n'
                    'After=network-pre.target ufw.service\nBefore=network.target\n'
                    '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                    f'ExecStart=/usr/bin/python3 {HELPER} reapply-mss\n'
                    '[Install]\nWantedBy=multi-user.target\n')
    UNIT.chmod(0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', UNIT.name)


def restore(data):
    for entry in reversed(mss_entries(data)):
        tool, chain = entry['tool'], entry['chain']
        if entry['owned'] and rule_present(tool, chain):
            run(tool, '--wait', '5', '-t', 'mangle', '-D', chain, *RULE)
    if data.get('persistence'):
        if UNIT.exists():
            run('systemctl', 'disable', '--now', UNIT.name)
        UNIT.unlink(missing_ok=True)
        HELPER.unlink(missing_ok=True)
        run('systemctl', 'daemon-reload')
    for key, value in data['runtime'].items():
        run('sysctl', '-w', key + '=' + value)
    if data['config'] is None:
        CONFIG.unlink(missing_ok=True)
    else:
        CONFIG.write_text(data['config'])


def apply(with_mss=False, bbr=True):
    if BACKUP.exists():
        raise SystemExit('Tuning already applied; rollback first')
    tools = []
    if with_mss:
        if UNIT.exists() or HELPER.exists():
            raise RuntimeError('MSS helper/service already exists without a tuning receipt; inspect it first')
        tools = [name for name in ('iptables', 'ip6tables') if shutil.which(name)]
        if 'iptables' not in tools:
            raise RuntimeError('iptables is required for optional MSS clamping')
    if bbr:
        try:
            run('modprobe', 'tcp_bbr')
        except subprocess.CalledProcessError:
            pass  # Can be built into the kernel.
        if 'bbr' not in run('sysctl', '-n', 'net.ipv4.tcp_available_congestion_control').split():
            raise SystemExit('This kernel does not offer BBR; no settings changed')
    selected = VALUES if bbr else {}
    data = {'runtime': {key: run('sysctl', '-n', key) for key in selected},
            'config': CONFIG.read_text() if CONFIG.exists() else None,
            'mss': [{'tool': tool, 'chain': chain, 'owned': False}
                    for tool in tools for chain in ('OUTPUT', 'FORWARD')]}
    fd = os.open(BACKUP, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle)
    try:
        if bbr:
            CONFIG.write_text(''.join(key + '=' + value + '\n' for key, value in selected.items()))
        for key, value in selected.items():
            run('sysctl', '-w', key + '=' + value)
        if with_mss:
            apply_mss(data)
            install_persistence(data)
    except Exception:
        restore(data)
        BACKUP.unlink()
        raise
    print(('BBR/fq configured' if bbr else 'BBR/fq unchanged') + (' with persistent PMTU MSS rules' if with_mss else '') +
          '. Interface MTU and DNS unchanged. Benchmark the route; speed improvement is not guaranteed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['status', 'apply', 'rollback', 'reapply-mss'])
    mss = parser.add_mutually_exclusive_group()
    mss.add_argument('--mss-clamp', action='store_true', help='Add tagged IPv4/IPv6 PMTU MSS rules and persist at boot')
    mss.add_argument('--mss-only', action='store_true', help='Apply MSS rules without changing congestion control')
    args = parser.parse_args()
    if (args.mss_clamp or args.mss_only) and args.action != 'apply':
        parser.error('MSS options are only valid with apply')
    if args.action == 'status':
        result = {key: run('sysctl', '-n', key) for key in VALUES}
        result['tuning_applied'] = BACKUP.exists()
        result['mss_rules'] = []
        if BACKUP.exists():
            try:
                for entry in mss_entries(json.loads(BACKUP.read_text())):
                    row = {'tool': entry['tool'], 'chain': entry['chain']}
                    try:
                        row['active'] = rule_present(entry['tool'], entry['chain'])
                    except (OSError, subprocess.SubprocessError) as exc:
                        row.update(active=None, error=type(exc).__name__)
                    result['mss_rules'].append(row)
            except PermissionError:
                result['mss_error'] = 'Run status as root to inspect the private tuning receipt'
        print(json.dumps(result, indent=2))
        return
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    for path in (CONFIG, BACKUP, UNIT, HELPER):
        secure_parent(path, 0o700 if path == BACKUP else 0o755)
        if path.is_symlink() or (path.exists() and (path.stat().st_uid != 0 or path.stat().st_mode & 0o022)):
            raise RuntimeError(f'Unsafe configuration path: {path}')
    if args.action == 'rollback':
        restore(json.loads(BACKUP.read_text()))
        BACKUP.unlink()
        return
    if args.action == 'reapply-mss':
        apply_mss(json.loads(BACKUP.read_text()))
        return
    apply(args.mss_clamp or args.mss_only, bbr=not args.mss_only)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        raise SystemExit('Network tuning failed: ' + str(exc))
