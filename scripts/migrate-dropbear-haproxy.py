#!/usr/bin/env python3
"""Root-only, backed-up migration of managed tunnels; administrative SSH is separate."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time

APP = Path('/usr/local/lib/abdulbasit')
sys.path.insert(0, str(APP))
import paneld
import ssh_backend
from common import BASE_DIR, DOMAIN_FILE, USERS_DIR, atomic_write, atomic_write_json, read_json, read_text, validate_domain, validate_username

HAPROXY_CONFIG = Path('/etc/abdulbasit-haproxy/haproxy.cfg')
DEFAULT_SITE = Path('/etc/nginx/sites-enabled/default')
UNITS = ('abdulbasit-haproxy', 'nginx', 'dropbear', 'abdulbasit-sshd',
         'abdulbasit-paneld', 'abdulbasit-ws', 'abdulbasit-session-enforcer')
FILES = (Path('/etc/abdulbasit/ssh-backend'), Path('/etc/abdulbasit/gateway-backend'),
         Path('/etc/abdulbasit/haproxy-verify'), Path('/etc/nginx/conf.d/abdulbasit-vpn.conf'), HAPROXY_CONFIG,
         Path('/etc/systemd/system/dropbear.service'), Path('/etc/systemd/system/abdulbasit-haproxy.service'),
         Path('/etc/fail2ban/jail.d/abdulbasit-dropbear.local'), Path('/etc/fail2ban/jail.d/abdulbasit-sshd.local'))

DROPBEAR_UNIT = '''[Unit]
Description=NOWAY pinned Dropbear 2026 managed tunnel SSH
After=network.target
Before=abdulbasit-ws.service
[Service]
Type=simple
ExecStart=/usr/local/lib/abdulbasit/dropbear -F -E -m -w -k -G abdulbasit-tunnel -T 3 -K 30 -I 3600 -W 262144 -p 109 -p 447 -r /etc/dropbear/dropbear_ed25519_host_key -r /etc/dropbear/dropbear_rsa_host_key -c /usr/local/lib/abdulbasit/tunnel-shell -b /etc/abdulbasit/ssh-banner.txt -P /run/abdulbasit-dropbear/dropbear.pid
Restart=on-failure
RestartSec=2
RuntimeDirectory=abdulbasit-dropbear
RuntimeDirectoryMode=0750
UMask=0077
LimitNOFILE=16384
TasksMax=1024
MemoryMax=256M
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=read-only
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
[Install]
WantedBy=multi-user.target
'''

HAPROXY_UNIT = '''[Unit]
Description=NOWAY public HTTP/TLS TCP multiplexer on ports 80 and 443
After=network-online.target nginx.service
Wants=network-online.target
[Service]
Type=notify
NotifyAccess=all
ExecStartPre=/usr/sbin/haproxy -c -q -f /etc/abdulbasit-haproxy/haproxy.cfg
ExecStart=/usr/sbin/haproxy -Ws -f /etc/abdulbasit-haproxy/haproxy.cfg -p /run/abdulbasit-haproxy/master.pid
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=2
RuntimeDirectory=abdulbasit-haproxy
RuntimeDirectoryMode=0750
LimitNOFILE=32768
TasksMax=256
MemoryMax=256M
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
[Install]
WantedBy=multi-user.target
'''


def run(args, *, timeout=30, check=True):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        lines = (result.stderr or result.stdout).strip().splitlines()
        detail = re.sub(r'[a-f0-9]{64}', '[private]', lines[-1][:400]) if lines else str(result.returncode)
        raise RuntimeError(Path(str(args[0])).name + ' failed: ' + detail)
    return result


class Migration:
    def __init__(self, *, root=Path('/'), runner=run):
        self.root, self.run = Path(root), runner
        self.backup = None
        self.switched = False

    def path(self, path):
        return self.root / Path(path).relative_to('/')

    def safe_path(self, target):
        path = self.path(target)
        for ancestor in (path, *path.parents):
            if ancestor.is_symlink():
                raise RuntimeError('Unsafe migration path: ' + str(target))
            if ancestor == self.root:
                break
        return path

    def unit(self, action, name, *, check=True):
        if name not in UNITS:
            raise ValueError('Unmanaged service')
        return self.run(['systemctl', action, name], check=check, timeout=30)

    def snapshot(self):
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        self.backup = self.path(BASE_DIR / 'backups' / f'dropbear-haproxy-{stamp}-{os.getpid()}-{secrets.token_hex(3)}')
        self.backup.mkdir(parents=True, mode=0o700)
        state = {'schema': 'noway-dropbear-haproxy-v1', 'files': {}, 'services': {}, 'default_site': self.stock_default_link()}
        for target in FILES:
            path = self.safe_path(target)
            saved = self.backup / 'files' / target.relative_to('/')
            if path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode): raise RuntimeError('Not a regular configuration: ' + str(target))
                saved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copy2(path, saved)
                state['files'][str(target)] = {'exists': True, 'uid': info.st_uid, 'gid': info.st_gid}
            else:
                state['files'][str(target)] = {'exists': False}
        for unit in UNITS:
            state['services'][unit] = {'active': self.unit('is-active', unit, check=False).returncode == 0,
                                       'enabled': self.unit('is-enabled', unit, check=False).stdout.strip()}
        atomic_write_json(self.backup / 'state.json', state)
        return state

    def stock_default_link(self):
        link = self.path(DEFAULT_SITE)
        if not link.is_symlink():
            return None
        target = os.readlink(link)
        if target not in ('/etc/nginx/sites-available/default', '../sites-available/default'):
            return None
        config = self.safe_path('/etc/nginx/sites-available/default')
        installed = self.run(['dpkg-query', '-W', '-f=${Conffiles}', 'nginx-common'], check=False)
        matches = re.findall(r'^ /etc/nginx/sites-available/default ([a-f0-9]{32})(?:\s|$)', installed.stdout, re.M)
        if config.is_file() and matches and hashlib.md5(config.read_bytes(), usedforsecurity=False).hexdigest() == matches[0]:
            return target
        return None

    def rollback(self, backup=None, *, restart=True):
        backup = Path(backup or self.backup)
        expected = self.path(BASE_DIR / 'backups').resolve()
        if backup.is_symlink() or not backup.resolve().is_relative_to(expected):
            raise RuntimeError('Rollback must use a managed backup directory')
        state = read_json(backup / 'state.json', {})
        if (state.get('schema') != 'noway-dropbear-haproxy-v1' or set(state.get('files', {})) != {str(p) for p in FILES}
                or set(state.get('services', {})) != set(UNITS)):
            raise RuntimeError('Invalid migration recovery state')
        failures = []
        if restart:
            for unit in ('abdulbasit-haproxy', 'abdulbasit-ws', 'abdulbasit-paneld', 'abdulbasit-session-enforcer', 'nginx', 'dropbear', 'abdulbasit-sshd'):
                try: self.unit('stop', unit, check=False)
                except Exception as exc: failures.append(str(exc))
            # Remove newly created enablement links while their units still exist.
            for unit in UNITS:
                if state['services'][unit]['enabled'] not in ('enabled', 'enabled-runtime'):
                    self.unit('disable', unit, check=False)
        for target in FILES:
            item = state['files'][str(target)]
            try:
                path = self.safe_path(target)
                if item['exists']:
                    saved = backup / 'files' / target.relative_to('/')
                    if saved.is_symlink() or not saved.is_file(): raise RuntimeError('Missing recovery file: ' + str(target))
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                    shutil.copy2(saved, path)
                    os.chown(path, item['uid'], item['gid'])
                else: path.unlink(missing_ok=True)
            except Exception as exc: failures.append(str(exc))
        if state.get('default_site'):
            try:
                if state['default_site'] not in ('/etc/nginx/sites-available/default', '../sites-available/default'):
                    raise RuntimeError('Invalid default-site recovery link')
                link = self.path(DEFAULT_SITE)
                if link.exists() or link.is_symlink():
                    if not link.is_symlink(): raise RuntimeError('Default-site recovery path was replaced')
                    link.unlink()
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(state['default_site'])
            except Exception as exc: failures.append(str(exc))
        self.run(['systemctl', 'daemon-reload'])
        if restart:
            for unit in ('dropbear', 'abdulbasit-sshd', 'nginx', 'abdulbasit-haproxy', 'abdulbasit-paneld', 'abdulbasit-ws', 'abdulbasit-session-enforcer'):
                item = state['services'][unit]
                try:
                    if item['enabled'] in ('enabled', 'enabled-runtime'): self.unit('enable', unit)
                    if item['active']: self.unit('start', unit)
                except Exception as exc: failures.append(str(exc))
        self.run(['fail2ban-client', 'reload'], check=False)
        if failures: raise RuntimeError('Recovery needs attention: ' + '; '.join(failures))
        print('Previous managed SSH/gateway layout restored from ' + str(backup))

    def listeners(self, port, allowed):
        output = self.run(['ss', '-Hltnp', f'sport = :{port}']).stdout
        for line in output.splitlines():
            pids = re.findall(r'pid=(\d+)', line)
            if not pids:
                raise RuntimeError(f'Cannot verify the service owning port {port}')
            for pid in pids:
                groups = self.path(f'/proc/{pid}/cgroup').read_text().splitlines()
                if not any(row.rsplit('/', 1)[-1] in {unit + '.service' for unit in allowed} for row in groups):
                    raise RuntimeError(f'Port {port} belongs to an unrelated service; it will not be replaced')
        return output

    def verify_layout(self):
        for port in (80, 443):
            if not self.listeners(port, {'abdulbasit-haproxy'}):
                raise RuntimeError(f'HAProxy is not listening on {port}')
        for port in (8080, 8081):
            rows = self.listeners(port, {'nginx'}).splitlines()
            if not rows or any(row.split()[3] != f'127.0.0.1:{port}' for row in rows):
                raise RuntimeError(f'Nginx port {port} must be loopback-only')
        for port in (109, 447):
            if not self.listeners(port, {'dropbear'}):
                raise RuntimeError(f'Dropbear is not listening on {port}')
            with socket.create_connection(('127.0.0.1', port), timeout=2) as peer:
                peer.settimeout(2)
                if not peer.recv(255).startswith(('SSH-2.0-dropbear_' + ssh_backend.DROPBEAR_VERSION).encode()):
                    raise RuntimeError(f'Unexpected Dropbear identification on {port}')

    def preflight(self):
        if not self.path('/etc/abdulbasit/ssh-backend').is_file(): raise RuntimeError('Install the panel before migration')
        version = self.run([APP / 'dropbear', '-V'])
        if not (version.stdout + version.stderr).startswith('Dropbear v' + ssh_backend.DROPBEAR_VERSION):
            raise RuntimeError('Install the pinned official Dropbear binary first')
        nginx = paneld.binary('nginx')
        options = self.run([nginx, '-V'])
        if '--with-http_realip_module' not in options.stderr + options.stdout:
            raise RuntimeError('Nginx needs its realip module before a PROXY-protocol gateway can be enabled')
        for port in (8080, 8081):
            listener = self.listeners(port, {'nginx'})
            if listener and not ssh_backend.haproxy_enabled():
                raise RuntimeError(f'Internal port {port} is already in use; no listener will be replaced')
        for port in (80, 443, 109, 447):
            self.listeners(port, {'nginx', 'abdulbasit-haproxy'} if port in (80, 443) else {'abdulbasit-sshd', 'dropbear'})
        return nginx

    def apply(self):
        nginx = self.preflight()
        domain = validate_domain(read_text(DOMAIN_FILE))
        cert_dir = Path('/etc/letsencrypt/live') / domain
        if not all((cert_dir / n).is_file() for n in ('fullchain.pem', 'privkey.pem')):
            raise RuntimeError('Keep the working origin TLS certificate before migration')
        state = self.snapshot()
        print('Recovery copy: ' + str(self.backup))
        try:
            try: grp.getgrnam(ssh_backend.GROUP)
            except KeyError: self.run(['groupadd', '--system', ssh_backend.GROUP])
            for path in USERS_DIR.glob('*.json'):
                row = read_json(path, {})
                name = validate_username(str(row.get('username', path.stem)))
                if name != path.stem: raise RuntimeError('Managed username/metadata mismatch')
                user = pwd.getpwnam(name)
                if user.pw_uid < 1000 or user.pw_shell != str(APP / 'tunnel-shell'):
                    raise RuntimeError('Unexpected managed account identity: ' + name)
                self.run(['usermod', '-a', '-G', ssh_backend.GROUP, name])
            keys = Path('/etc/dropbear')
            if keys.is_symlink(): raise RuntimeError('Unsafe Dropbear key directory')
            keys.mkdir(mode=0o755, exist_ok=True)
            for kind in ('ed25519', 'rsa'):
                key = keys / f'dropbear_{kind}_host_key'
                if key.is_symlink(): raise RuntimeError('Unsafe Dropbear host key')
                if not key.exists():
                    self.run([APP / 'dropbearkey', '-t', kind, '-f', key] + (['-s', '3072'] if kind == 'rsa' else []), timeout=30)
                key.chmod(0o600)
            secret = read_text(ssh_backend.HAPROXY_SECRET_FILE) or secrets.token_hex(32)
            if not re.fullmatch(r'[a-f0-9]{64}', secret): raise RuntimeError('Invalid existing HAProxy identity; it was not rotated')
            atomic_write(ssh_backend.HAPROXY_SECRET_FILE, secret + '\n')
            HAPROXY_CONFIG.parent.mkdir(mode=0o700, exist_ok=True)
            atomic_write(HAPROXY_CONFIG, ssh_backend.haproxy_config(secret, ipv6=paneld.ipv6_enabled()))
            atomic_write(self.path('/etc/systemd/system/dropbear.service'), DROPBEAR_UNIT, 0o644)
            atomic_write(self.path('/etc/systemd/system/abdulbasit-haproxy.service'), HAPROXY_UNIT, 0o644)
            atomic_write(paneld.NGINX_CONFIG, paneld.nginx_text(domain, True, multiplexed=True))
            if state['default_site']:
                self.path(DEFAULT_SITE).unlink()
            self.run(['/usr/sbin/haproxy', '-c', '-f', HAPROXY_CONFIG])
            self.run([nginx, '-t'])
            rendered = self.run([nginx, '-T']).stdout
            if re.search(r'^\s*listen\s+(?:(?:\[[^\]]+\]|[^\s:;]+):)?(?:80|443)(?:\s|;)', rendered, re.M):
                raise RuntimeError('Another Nginx site still binds public 80/443; its configuration was not changed')
            self.run(['systemctl', 'daemon-reload'])
            self.switched = True
            for unit in ('abdulbasit-session-enforcer', 'abdulbasit-ws', 'abdulbasit-paneld', 'abdulbasit-haproxy', 'nginx', 'abdulbasit-sshd', 'dropbear'):
                self.unit('stop', unit, check=False)
            atomic_write(ssh_backend.BACKEND_FILE, 'dropbear-2026\n', 0o644)
            atomic_write(ssh_backend.GATEWAY_FILE, 'haproxy\n', 0o644)
            for unit in ('dropbear', 'nginx', 'abdulbasit-haproxy', 'abdulbasit-paneld', 'abdulbasit-ws', 'abdulbasit-session-enforcer'):
                self.unit('start', unit)
            self.verify_layout()
            from panel_client import wait_ready
            wait_ready()
            deadline = time.monotonic() + 15
            while True:
                checks = [paneld.diagnostics.ssh_upgrade(domain, port, tls=secure, timeout=2)
                          for port, secure in ((80, False), (443, True))]
                if all(ok and 'SSH-2.0-dropbear_' + ssh_backend.DROPBEAR_VERSION in detail for ok, detail in checks): break
                if time.monotonic() >= deadline: raise RuntimeError('Public HTTP/TLS to Dropbear did not become ready: ' + repr(checks))
                time.sleep(.2)
            jail = Path('/etc/fail2ban/jail.d/abdulbasit-dropbear.local')
            atomic_write(jail, '[dropbear]\nenabled = true\nport = 109,447\nbackend = systemd\nignoreip = 127.0.0.1/8 ::1\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n', 0o644)
            self.path('/etc/fail2ban/jail.d/abdulbasit-sshd.local').unlink(missing_ok=True)
            self.run(['fail2ban-client', 'reload'])
            self.unit('disable', 'abdulbasit-sshd', check=False)
            self.unit('enable', 'dropbear'); self.unit('enable', 'abdulbasit-haproxy')
        except BaseException:
            try: self.rollback(restart=self.switched)
            except Exception as exc: print('Automatic recovery needs attention: ' + str(exc), file=sys.stderr)
            raise
        print('HAProxy public 80/443 -> Nginx loopback 8080/8081 -> WS proxy 2082 -> Dropbear 2026.94 verified')
        print('Managed users/passwords and administrative SSH configuration were preserved. Verify the Dropbear host key in clients:')
        print(self.run([APP / 'dropbearkey', '-y', '-f', '/etc/dropbear/dropbear_ed25519_host_key']).stdout)
        return self.backup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rollback', type=Path, help='Restore a specific managed migration backup')
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Run as root')
    with open('/run/noway-gateway-migrate.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        task = Migration()
        if args.rollback: task.rollback(args.rollback)
        else: task.apply()


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        print('Gateway migration failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
