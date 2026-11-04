#!/usr/bin/env python3
"""Pinned private runtime build and reversible systemd activation (root terminal).

OS Python/OpenSSL/sshd and package-owned executables are never replaced. Builds
finish and pass compatibility checks before touching the current runtime.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shlex
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

PROJECT = Path(__file__).resolve().parents[1]
ROOT = Path('/opt/noway/runtime')
STATE = Path('/var/lib/noway-runtime')
UNITS = Path('/etc/systemd/system')
LOCAL_BIN = Path('/usr/local/bin')
APP = Path('/usr/local/lib/abdulbasit')
PANEL_UNITS = ('abdulbasit-paneld', 'abdulbasit-ws', 'abdulbasit-web',
               'abdulbasit-session-enforcer', 'abdulbasit-bot', 'abdulbasit-dnstt')
UNITS_TO_RESTART = ('nginx', 'fail2ban', *PANEL_UNITS)
TOOLS = {'nginx': '/usr/sbin/nginx', 'certbot': '/usr/bin/certbot',
         'fail2ban-client': '/usr/bin/fail2ban-client', 'openssl': '/usr/bin/openssl'}
ALLOWED_HOSTS = {'github.com', 'www.python.org'}
CONFIG_PATHS = ('/etc/nginx', '/etc/fail2ban', '/etc/letsencrypt')


def log(message):
    print(message, flush=True)


def run(args, *, cwd=None, timeout=60, env=None):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f'{Path(args[0]).name} failed: {(result.stderr or result.stdout)[-1800:]}')
    return result.stdout + result.stderr


BUILD_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
BUILD_INPUTS = (
    'CC', 'CXX', 'CPP', 'LD', 'AR', 'AS', 'RANLIB', 'STRIP', 'NM', 'OBJCOPY',
    'OBJDUMP', 'CROSS_COMPILE', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS',
    'LDLIBS', 'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH',
    'LD_LIBRARY_PATH', 'LD_PRELOAD', 'CONFIG_SITE', 'CONFIG_OPTIONS',
    'OPENSSL_LOCAL_CONFIG_DIR', 'OPENSSL_CONFIG', 'MAKE', 'MAKEFLAGS', 'MFLAGS',
    'MAKELEVEL', 'PERL5LIB', 'PERL5OPT', 'PERL', 'PYTHONPATH', 'PYTHONHOME',
    'VIRTUAL_ENV', 'PKG_CONFIG', 'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR',
    'PKG_CONFIG_SYSROOT_DIR', 'GCC_EXEC_PREFIX', 'COMPILER_PATH',
)


def build_environment(overrides=None):
    """Use Ubuntu/Debian's native toolchain, independent of login/build aliases."""
    environment = {key: value for key, value in os.environ.items() if key not in BUILD_INPUTS}
    environment.update(PATH=BUILD_PATH, LC_ALL='C.UTF-8', CC='/usr/bin/gcc',
                       CXX='/usr/bin/g++', AR='/usr/bin/ar', RANLIB='/usr/bin/ranlib',
                       CONFIG_SITE='/dev/null', PYTHONNOUSERSITE='1', PYTHON_JIT='0')
    if overrides:
        environment.update(overrides)
    return environment


def verify_toolchain():
    """A package being installed does not prove its compiler can link and run."""
    environment = build_environment()
    try:
        with tempfile.TemporaryDirectory(prefix='.compiler-check-', dir=ROOT) as directory:
            for suffix, compiler in (('c', environment['CC']), ('cc', environment['CXX'])):
                run([compiler, '--version'], env=environment)
                source = Path(directory) / ('check.' + suffix)
                program = Path(directory) / ('check-' + suffix)
                source.write_text('#include <stdio.h>\nint main(void) { return puts("NOWAY native compiler ready") < 0; }\n')
                run([compiler, str(source), '-o', str(program)], env=environment)
                if 'NOWAY native compiler ready' not in run([program], env=environment):
                    raise RuntimeError('Compiled toolchain check returned unexpected output')
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        raise RuntimeError(
            'Native C/C++ compiler check failed before downloads/activation: ' + str(exc) +
            '. Repair the distribution toolchain with apt-get install --reinstall '
            'build-essential gcc g++ make binutils libc6-dev, and check execution permissions on /opt.'
        ) from exc
    log('Native C/C++ compile, link and execution checks passed (/usr/bin/gcc, /usr/bin/g++)')


class RuntimeInterrupted(KeyboardInterrupt):
    def __init__(self, signum):
        self.signum = signum


def interrupt_runtime(signum, _frame):
    # Turn terminal disconnects/service stops into the same cleanup path as Ctrl+C.
    raise RuntimeInterrupted(signum)


BUILD_PROGRESS_SECONDS = 10


def build_log_tail(path, limit=1800):
    with path.open('rb') as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - limit))
        return handle.read(limit).decode('utf-8', errors='replace')


def stop_build(process):
    """Cancel the build's session, including make's compiler/linker descendants."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        pass
    # A make leader can exit before a child that ignores SIGTERM. Reap/kill the
    # entire original group even when the leader has already returned.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


def build_run(args, directory, log_file, timeout=1800, env=None):
    command = [str(argument) for argument in args]
    label = shlex.join(command[:2])
    log(f'Running {label}; status every {BUILD_PROGRESS_SECONDS}s; full log: {log_file}')
    started = time.monotonic()
    deadline = started + timeout
    with log_file.open('a') as output:
        output.write('\n$ ' + shlex.join(command) + '\n')
        output.flush()
        process = subprocess.Popen(command, cwd=directory, env=build_environment(env),
                                   stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    process.wait(timeout=min(BUILD_PROGRESS_SECONDS, remaining))
                    break
                except subprocess.TimeoutExpired:
                    elapsed = time.monotonic() - started
                    if elapsed >= timeout:
                        raise subprocess.TimeoutExpired(command, timeout) from None
                    lines = build_log_tail(log_file, 512).splitlines()
                    preview = ''.join(c if c.isprintable() else ' ' for c in lines[-1])[-220:] if lines else '(no output yet)'
                    log(f'Still running {label}: {elapsed:.0f}s elapsed; latest log: {preview}')
        except BaseException:
            stop_build(process)
            raise
    if process.returncode:
        raise RuntimeError(f'{Path(command[0]).name} failed; inspect {log_file}\n' + build_log_tail(log_file))
    log(f'Finished {label} in {time.monotonic() - started:.1f}s')


def read_manifest(path):
    data = json.loads(path.read_text())
    required = {'nginx', 'openssl', 'python', 'certbot', 'acme', 'fail2ban'}
    if data.get('schema') != 1 or set(data.get('components', {})) != required:
        raise ValueError('Unsupported runtime manifest')
    for item in data['components'].values():
        url = urlparse(item['url'])
        if (not re.fullmatch(r'\d+\.\d+\.\d+', item['version']) or
                not re.fullmatch(r'[0-9a-f]{64}', item['sha256']) or
                url.scheme != 'https' or url.hostname not in ALLOWED_HOSTS or
                url.username or url.password or url.fragment or url.query):
            raise ValueError('Unsafe version, digest or source URL')
    return data


def verify_archive(path, digest):
    hasher = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            hasher.update(chunk)
    if hasher.hexdigest() != digest:
        raise RuntimeError(f'SHA256 mismatch: {path.name}; no activation performed')


def download(item, cache):
    target = cache / Path(urlparse(item['url']).path).name
    if not target.exists():
        partial = target.with_name(target.name + '.part')
        run(['curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
             '--tlsv1.2', '--retry', '2', '--connect-timeout', '20', '--max-time', '600',
             item['url'], '-o', str(partial)], timeout=1850)
        verify_archive(partial, item['sha256'])
        partial.replace(target)
    verify_archive(target, item['sha256'])
    return target


def extract(archive, directory):
    # data_filter rejects absolute paths, escaping links and special devices.
    if not hasattr(tarfile, 'data_filter'):
        raise RuntimeError('Install OS Python security updates (tarfile.data_filter is required)')
    directory.mkdir(mode=0o700)
    with tarfile.open(archive) as source:
        source.extractall(directory, filter='data')
    entries = list(directory.iterdir())
    if len(entries) != 1 or not entries[0].is_dir():
        raise RuntimeError('Unexpected source archive layout')
    return entries[0]


def write_file(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = path.with_name(path.name + '.noway-new')
    temporary.unlink(missing_ok=True)
    with temporary.open('x') as handle:
        handle.write(content)
        os.fchmod(handle.fileno(), mode)
    temporary.replace(path)


def script(path, command, environment=None):
    exports = ''.join(f'export {key}={shlex.quote(str(value))}\n' for key, value in (environment or {}).items())
    write_file(path, '#!/bin/sh\n' + exports + 'exec ' + shlex.join([str(a) for a in command]) + ' "$@"\n', 0o755)


def build(manifest, jobs):
    recipe = Path(__file__).read_bytes()
    fingerprint = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode() + recipe).hexdigest()[:12]
    releases = ROOT / 'releases'
    releases.mkdir(mode=0o755, exist_ok=True)
    info = releases.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(f'Unsafe runtime release directory: {releases} (uid={info.st_uid}, mode={stat.S_IMODE(info.st_mode):04o})')
    existing = releases / fingerprint
    if (existing / 'READY').is_file():
        log('Verified runtime build already exists; checking versions again')
        return completed_release(fingerprint, manifest)
    # Absolute rpaths and venv shebangs refer to this immutable release directory.
    # Never rename a built runtime, and never reuse a partial build.
    if existing.exists():
        # Preserve failed work for inspection, and let a normal retry start clean.
        failed = existing.with_name('failed-build-' + fingerprint + '-' + str(time.time_ns()))
        existing.rename(failed)
        log(f'Previous incomplete build retained at {failed}')
    existing.mkdir(parents=True, mode=0o755)
    cache = STATE / 'downloads'
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    archives = {}
    for name, item in manifest['components'].items():
        log(f'Downloading and verifying {name} {item["version"]}')
        archives[name] = download(item, cache)
    sources = existing / 'sources'
    sources.mkdir(mode=0o700)
    log_file = existing / 'build.log'
    ssl_source = extract(archives['openssl'], sources / 'openssl')
    ssl_prefix = existing / 'openssl'
    log('Building OpenSSL LTS in the private runtime')
    build_run(['./config', f'--prefix={ssl_prefix}', '--openssldir=/etc/ssl', '--libdir=lib',
               'shared', '-Wl,-rpath,' + str(ssl_prefix / 'lib')], ssl_source, log_file)
    build_run(['make', f'-j{jobs}'], ssl_source, log_file)
    build_run(['make', 'install_sw'], ssl_source, log_file)
    python_source = extract(archives['python'], sources / 'python')
    python_prefix = existing / 'python'
    log('Building panel Python (JIT disabled for the production sandbox)')
    build_run(['./configure', f'--prefix={python_prefix}', f'--with-openssl={ssl_prefix}',
               '--with-openssl-rpath=auto', '--with-ensurepip=install', '--disable-test-modules',
               '--enable-experimental-jit=no'], python_source, log_file)
    build_run(['make', f'-j{jobs}'], python_source, log_file)
    build_run(['make', 'altinstall'], python_source, log_file)
    python = python_prefix / 'bin/python3.15'
    build_run([python, '-m', 'venv', existing / 'venv'], existing, log_file)
    private_python = existing / 'venv/bin/python'
    log('Installing Certbot/ACME from verified official sources and the panel WebSocket dependency')
    build_run([private_python, '-m', 'pip', 'install', '--disable-pip-version-check',
               '--index-url', 'https://pypi.org/simple', '--upgrade',
               archives['acme'], archives['certbot'], 'wsproto==1.3.2', 'h11==0.16.0'], existing, log_file)
    write_file(existing / 'python-packages.txt', run([private_python, '-m', 'pip', 'freeze']))
    nginx_source = extract(archives['nginx'], sources / 'nginx')
    log('Building Nginx stable against the private OpenSSL LTS library')
    build_run(['./configure', '--prefix=/usr/share/nginx', '--conf-path=/etc/nginx/nginx.conf',
               '--pid-path=/run/nginx.pid', '--lock-path=/run/lock/nginx.lock',
               '--error-log-path=/var/log/nginx/error.log', '--http-log-path=/var/log/nginx/access.log',
               '--user=www-data', '--group=www-data', '--with-http_ssl_module', '--with-http_v2_module',
               '--with-http_realip_module', '--with-http_stub_status_module', '--with-http_auth_request_module',
               '--with-http_gzip_static_module', '--with-http_sub_module', '--with-threads',
               '--with-stream', '--with-stream_ssl_module', '--with-stream_realip_module',
               '--with-stream_ssl_preread_module', '--with-compat',
               f'--with-cc-opt=-I{ssl_prefix}/include',
               f'--with-ld-opt=-L{ssl_prefix}/lib -Wl,-rpath,{ssl_prefix}/lib',
               *[f'--http-{name}-temp-path=/var/lib/nginx/{folder}' for name, folder in
                 (('client-body', 'body'), ('proxy', 'proxy'), ('fastcgi', 'fastcgi'), ('uwsgi', 'uwsgi'), ('scgi', 'scgi'))]],
              nginx_source, log_file)
    build_run(['make', f'-j{jobs}'], nginx_source, log_file)
    bindir = existing / 'bin'
    bindir.mkdir(mode=0o755)
    shutil.copy2(nginx_source / 'objs/nginx', bindir / 'nginx')
    script(bindir / 'python3', [private_python], {'PYTHON_JIT': '0', 'PYTHONNOUSERSITE': '1'})
    script(bindir / 'certbot', [existing / 'venv/bin/certbot'], {'PYTHON_JIT': '0', 'PYTHONNOUSERSITE': '1'})
    script(bindir / 'openssl', [ssl_prefix / 'bin/openssl'])
    # The upstream architecture-independent DEB is extracted, never dpkg-installed.
    # Fail2ban uses Ubuntu's Python so the native systemd journal binding matches.
    f2b = existing / 'fail2ban'
    run(['dpkg-deb', '--extract', str(archives['fail2ban']), str(f2b)])
    packages = list(f2b.glob('usr/lib/python3*/dist-packages/fail2ban'))
    if not packages:
        packages = list(f2b.glob('usr/lib/python3*/site-packages/fail2ban'))
    if len(packages) != 1:
        raise RuntimeError('Unexpected upstream Fail2ban package layout')
    for name in ('fail2ban-client', 'fail2ban-server', 'fail2ban-regex'):
        # A sealed release must not gain bytecode directories with the caller's
        # umask during later jail checks or rollback/reactivation.
        script(bindir / name, ['/usr/bin/python3', '-B', f2b / 'usr/bin' / name],
               {'PYTHONPATH': packages[0].parent, 'PYTHONNOUSERSITE': '1'})
    write_file(existing / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
    # Source trees are not needed to run the release. Keep logs, licenses and
    # source URLs/digests, so a failing build can be audited and reproduced.
    licenses = existing / 'licenses'
    licenses.mkdir(mode=0o755)
    for name, source in (('nginx', nginx_source), ('python', python_source), ('openssl', ssl_source)):
        for filename in ('LICENSE', 'LICENSE.txt', 'LICENSE.md'):
            if (source / filename).is_file():
                shutil.copy2(source / filename, licenses / (name + '-' + filename))
    shutil.rmtree(sources)
    seal_fresh_release(existing)
    verify_versions(existing, manifest)
    write_file(existing / 'READY', fingerprint + '\n')
    return existing


def seal_fresh_release(release):
    """Remove inherited write permissions from a build we have just created.

    This is never applied to cached/completed releases: those must pass the
    existing strict trust checks without changing their ownership or modes.
    """
    for path in (release, *release.rglob('*')):
        info = path.lstat()
        if info.st_uid != 0:
            raise RuntimeError(f'Unsafe fresh build owner: {path}')
        if stat.S_ISLNK(info.st_mode):
            continue
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise RuntimeError(f'Unsafe fresh build file type: {path}')
        if info.st_mode & 0o022:
            path.chmod(stat.S_IMODE(info.st_mode) & ~0o022)


def verify_versions(release, manifest):
    expected = {name: data['version'] for name, data in manifest['components'].items()}
    commands = {'nginx': ['nginx', '-v'], 'python': ['python3', '--version'],
                'openssl': ['openssl', 'version'], 'certbot': ['certbot', '--version'],
                'fail2ban': ['fail2ban-client', '--version']}
    for name, args in commands.items():
        output = run([release / 'bin' / args[0], *args[1:]])
        if not re.search(r'(?<![\d.])' + re.escape(expected[name]) + r'(?![\d.])', output):
            raise RuntimeError(f'{name} version mismatch: {output.strip()}')
    output = run([release / 'bin/python3', '-c',
                  'import ssl,sqlite3,hashlib,wsproto,acme,certbot; '
                  'from importlib.metadata import version; '
                  'assert version("acme")=="' + expected['acme'] + '"; '
                  'assert version("wsproto")=="1.3.2" and version("h11")=="0.16.0"; '
                  'assert hasattr(hashlib,"scrypt"); print(ssl.OPENSSL_VERSION)'])
    if expected['openssl'] not in output or expected['openssl'] not in run([release / 'bin/nginx', '-V']):
        raise RuntimeError('Nginx and Python must actually link to the selected OpenSSL LTS')


def check_renewal_plugins(directory=Path('/etc/letsencrypt/renewal')):
    # Certbot uses ConfigObj: root-level keys and nested [[webroot_map]] sections
    # are valid. A generic INI parser incorrectly rejects normal renewal files.
    paths = sorted(directory.glob('*.conf'))
    if not paths:
        return
    try:
        from configobj import ConfigObj, ConfigObjError
    except ImportError as exc:
        raise RuntimeError('Install python3-configobj to read Certbot renewal files') from exc
    for path in paths:
        try:
            config = ConfigObj(str(path), encoding='utf-8', file_error=True, raise_errors=True)
            params = config.get('renewalparams')
            values = {field: params.get(field, '') for field in ('authenticator', 'installer')} if isinstance(params, dict) else {}
        except (ConfigObjError, OSError, UnicodeError) as exc:
            raise RuntimeError(f'Cannot parse Certbot renewal file {path}: {exc}') from exc
        if not isinstance(params, dict):
            raise RuntimeError(f'Invalid Certbot renewal file {path}: missing [renewalparams] section')
        for field in ('authenticator', 'installer'):
            value = values[field]
            if not isinstance(value, str):
                raise RuntimeError(f'Invalid {field} value in Certbot renewal file {path}')
            plugin = value.strip()
            if plugin and plugin not in ('None', 'manual', 'standalone', 'webroot'):
                raise RuntimeError(f'Existing certificate needs the {plugin} Certbot plugin; install and validate that plugin in the private venv before activation')


def completed_release(identifier, manifest):
    """Explicitly reuse a finished, root-controlled build after activation failure."""
    if not re.fullmatch(r'[0-9a-f]{12}', identifier):
        raise ValueError('Invalid completed build ID; use the 12-hex release directory name')
    releases = ROOT / 'releases'
    release = releases / identifier
    for directory in (releases, release):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f'Unsafe completed build directory: {directory} (uid={info.st_uid}, mode={stat.S_IMODE(info.st_mode):04o})')
    for name in ('READY', 'manifest.json'):
        if (release / name).is_symlink() or not (release / name).is_file():
            raise RuntimeError(f'Build {identifier} is incomplete: missing regular {name}')
    # Do not execute a build with writable/foreign-owned libraries or links into
    # writable directories. Normal venv links into this release or /usr are valid.
    for path in release.rglob('*'):
        info = path.lstat()
        if info.st_uid != 0:
            raise RuntimeError(f'Unsafe completed build owner: {path}')
        if stat.S_ISLNK(info.st_mode):
            candidate = path
            # This DEB binding is relative to /usr/bin on an installed system.
            # Extraction under a private prefix leaves it dangling. The managed
            # Fail2ban wrappers invoke the OS interpreter explicitly, so check
            # that same interpreter without rewriting the completed package.
            staged_python = path.with_name('python3')
            if (path == release / 'fail2ban/usr/bin/fail2ban-python'
                    and os.readlink(path) == 'python3'
                    and not staged_python.exists() and not staged_python.is_symlink()):
                candidate = Path('/usr/bin/python3')
            try:
                target = candidate.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise RuntimeError(f'Unsafe or missing completed build link target: {path}') from exc
            for part in (target, *target.parents):
                details = part.stat()
                if details.st_uid != 0 or details.st_mode & 0o022:
                    raise RuntimeError(f'Unsafe completed build link target: {path}')
                if part == ROOT:
                    break
        elif not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or info.st_mode & 0o022:
            raise RuntimeError(f'Unsafe completed build permissions/type: {path} (mode={stat.S_IMODE(info.st_mode):04o})')
    try:
        receipt = (release / 'READY').read_text().strip()
        recorded = json.loads((release / 'manifest.json').read_text())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f'Cannot read completed build metadata: {identifier}') from exc
    if receipt != identifier or recorded != manifest:
        raise RuntimeError('Completed build receipt or selected versions do not match; no activation performed')
    verify_versions(release, manifest)
    log(f'Reusing verified completed build {identifier}; no downloads or compilation needed')
    return release


def config_checks(release):
    log('Validating existing Nginx config, Fail2ban jails and panel modules before activation')
    check_renewal_plugins()
    if active('certbot.service'):
        raise RuntimeError('A certificate renewal is running; retry after certbot.service finishes')
    run([release / 'bin/nginx', '-t'])
    run([release / 'bin/fail2ban-client', '-t'], timeout=30)
    run([release / 'bin/certbot', 'plugins', '--text'], timeout=30)
    run([release / 'bin/python3', '-c',
         'import sys; sys.path.insert(0,"' + str(APP) + '"); '
         'import common,paneld,ws_proxy,web_auth,web_server,slowdns,tgbot,session_enforcer; '
         'print("Panel runtime imports OK")'])


def active(unit):
    return subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def switch_current(target):
    temporary = ROOT / 'current.new'
    temporary.unlink(missing_ok=True)
    if target:
        temporary.symlink_to(target)
        temporary.replace(ROOT / 'current')
    else:
        (ROOT / 'current').unlink(missing_ok=True)


def managed_files():
    return [UNITS / name / '90-noway-runtime.conf' for name in
            ('nginx.service.d', 'fail2ban.service.d', 'certbot.service.d')] + [LOCAL_BIN / name for name in TOOLS]


def snapshot():
    identifier = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = STATE / 'backups' / identifier
    backup.mkdir(parents=True, mode=0o700)
    current = ROOT / 'current'
    if current.exists() and not current.is_symlink():
        raise RuntimeError('Refusing non-symlink runtime/current')
    state = {'schema': 1, 'previous': str(current.resolve()) if current.is_symlink() else None,
             'active': [name for name in UNITS_TO_RESTART if active(name)], 'files': {}}
    for index, path in enumerate(managed_files()):
        if path.is_symlink():
            state['files'][str(path)] = {'link': os.readlink(path)}
        elif path.is_file():
            filename = f'file-{index}'
            shutil.copy2(path, backup / filename)
            state['files'][str(path)] = {'backup': filename, 'mode': stat.S_IMODE(path.stat().st_mode)}
        elif path.exists():
            raise RuntimeError(f'Refusing non-file managed path {path}')
        else:
            state['files'][str(path)] = None
    # Recovery copy only: activation/rollback do not replace these configurations.
    with tarfile.open(backup / 'configuration.tar.gz', 'w:gz', dereference=False) as archive:
        for path in CONFIG_PATHS:
            if Path(path).exists():
                archive.add(path, arcname=path.lstrip('/'))
    (backup / 'configuration.tar.gz').chmod(0o600)
    write_file(backup / 'state.json', json.dumps(state, indent=2) + '\n', 0o600)
    return backup, state


def restore(backup, state):
    if set(state['files']) != {str(path) for path in managed_files()}:
        raise RuntimeError('Invalid rollback file list')
    for filename, data in state['files'].items():
        path = Path(filename)
        if data is None:
            path.unlink(missing_ok=True)
        elif 'link' in data:
            path.unlink(missing_ok=True)
            path.symlink_to(data['link'])
        else:
            source = backup / data['backup']
            if source.parent != backup:
                raise RuntimeError('Invalid rollback backup entry')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.unlink(missing_ok=True)
            shutil.copy2(source, path)
    switch_current(state['previous'])
    run(['systemctl', 'daemon-reload'])
    for name in state['active']:
        if name not in UNITS_TO_RESTART:
            raise RuntimeError('Invalid rollback unit')
        run(['systemctl', 'restart', name], timeout=90)


def activate(release):
    config_checks(release)
    backup, state = snapshot()
    try:
        # Paths in unit files remain stable when switching/rolling back releases.
        base = ROOT / 'current/bin'
        write_file(UNITS / 'nginx.service.d/90-noway-runtime.conf',
                   '[Service]\nExecStartPre=\nExecStartPre=' + str(base / 'nginx') + ' -t -q\n'
                   'ExecStart=\nExecStart=' + str(base / 'nginx') + ' -g "daemon on; master_process on;"\n'
                   'ExecReload=\nExecReload=' + str(base / 'nginx') + ' -t -q\n'
                   'ExecReload=/bin/kill -s HUP $MAINPID\nExecStop=\nExecStop=/bin/kill -s QUIT $MAINPID\n')
        write_file(UNITS / 'fail2ban.service.d/90-noway-runtime.conf',
                   '[Service]\nType=simple\nExecStart=\nExecStart=' + str(base / 'fail2ban-server') + ' -xf start\n'
                   'ExecReload=\nExecReload=' + str(base / 'fail2ban-client') + ' reload\n'
                   'ExecStop=\nExecStop=' + str(base / 'fail2ban-client') + ' stop\n')
        write_file(UNITS / 'certbot.service.d/90-noway-runtime.conf',
                   '[Service]\nExecStart=\nExecStart=' + str(base / 'certbot') + ' -q renew\n')
        for name in TOOLS:
            script(LOCAL_BIN / name, [base / name])
        switch_current(release)
        run(['systemctl', 'daemon-reload'])
        for name in state['active']:
            run(['systemctl', 'restart', name], timeout=90)
        # Give Type=simple services time to exit on initialization errors.
        time.sleep(2)
        for name in state['active']:
            if not active(name):
                raise RuntimeError(f'{name} failed after activation')
        if 'fail2ban' in state['active']:
            run([base / 'fail2ban-client', 'ping'])
        config_checks(release)
        log(f'Runtime activated. Rollback ID: {backup.name}')
    except BaseException:
        log('Activation failed; restoring previous runtime and service commands')
        try:
            restore(backup, state)
        except Exception as recovery:
            log(f'Automatic recovery failed: {recovery}. Recovery state: {backup}')
        raise
    write_file(STATE / 'last-activation.json', json.dumps({'backup': backup.name, 'release': str(release)}) + '\n', 0o600)


def status(manifest):
    current = ROOT / 'current'
    release = current.resolve() if current.is_symlink() else None
    output = {'managed': bool(release), 'release': str(release) if release else None,
              'expected': {key: item['version'] for key, item in manifest['components'].items()},
              'active': {}, 'system': {}, 'note': 'System Python/OpenSSL are maintained by Ubuntu/Debian; panel runtime is independent.'}
    for name, executable, args in (('nginx', 'nginx', ['-v']), ('python', 'python3', ['--version']),
                                    ('openssl', 'openssl', ['version']), ('certbot', 'certbot', ['--version']),
                                    ('fail2ban', 'fail2ban-client', ['--version'])):
        os_path = '/usr/bin/python3' if name == 'python' else TOOLS[executable]
        for group, path in (('system', Path(os_path)), ('active', release / 'bin' / executable if release else Path(os_path))):
            try:
                output[group][name] = run([path, *args]).strip()
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                output[group][name] = str(exc)
    if release:
        output['python_ssl'] = run([release / 'bin/python3', '-c', 'import ssl; print(ssl.OPENSSL_VERSION)']).strip()
        output['nginx_ssl'] = run([release / 'bin/nginx', '-V']).splitlines()[:3]
    log(json.dumps(output, indent=2))


def preflight():
    if os.geteuid() != 0:
        raise RuntimeError('Run this maintenance command in the root terminal')
    os.umask(0o022)
    if not (APP / 'python').is_file() or not (APP / 'paneld.py').is_file():
        raise RuntimeError('First run the 4.1 installer to install the panel interpreter selector')
    if not Path('/run/systemd/system').is_dir():
        raise RuntimeError('A running systemd host is required')
    for directory in (ROOT, STATE):
        directory.mkdir(parents=True, exist_ok=True, mode=0o755 if directory == ROOT else 0o700)
        # Walk all existing parents; an unprivileged owner must never redirect
        # a root build, interpreter, backup or activation through a symlink.
        for parent in (directory, *directory.parents):
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError(f'Unsafe maintenance directory: {parent} (uid={info.st_uid}, mode={stat.S_IMODE(info.st_mode):04o})')
    if (ROOT / 'current').exists() and not (ROOT / 'current').is_symlink():
        raise RuntimeError('Runtime current must be a managed symlink')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--apply', action='store_true')
    action.add_argument('--status', action='store_true')
    action.add_argument('--rollback', metavar='BACKUP_ID')
    action.add_argument('--activate-built', metavar='BUILD_ID', help='Verify and activate an already completed private build')
    parser.add_argument('--jobs', type=int, default=min(2, os.cpu_count() or 1))
    args = parser.parse_args()
    manifest = read_manifest(PROJECT / 'RUNTIME_VERSIONS.json')
    if args.status:
        status(manifest)
        return
    if not 1 <= args.jobs <= 8:
        parser.error('--jobs must be between 1 and 8')
    preflight()
    with (STATE / 'upgrade.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.rollback:
            if not re.fullmatch(r'\d{8}T\d{12}Z', args.rollback):
                raise ValueError('Invalid backup ID')
            backup = STATE / 'backups' / args.rollback
            state = json.loads((backup / 'state.json').read_text())
            restore(backup, state)
            log('Previous runtime and service commands restored; certificates/configuration retained')
            return
        if args.activate_built is not None:
            release = completed_release(args.activate_built, manifest)
        else:
            log('Installing build prerequisites; package-owned Python/OpenSSL/sshd remain in place')
            run(['apt-get', 'update'], timeout=600)
            run(['apt-get', 'install', '-y', '--no-install-recommends', 'build-essential', 'gcc', 'g++',
                 'make', 'binutils', 'libc6-dev', 'pkg-config',
                 'perl', 'ca-certificates', 'curl', 'xz-utils', 'libpcre2-dev', 'zlib1g-dev',
                 'libffi-dev', 'libsqlite3-dev', 'libbz2-dev', 'liblzma-dev', 'libreadline-dev',
                 'uuid-dev', 'python3-systemd', 'python3-configobj'], timeout=1200,
                env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
            verify_toolchain()
            release = build(manifest, args.jobs)
        if (ROOT / 'current').is_symlink() and (ROOT / 'current').resolve() == release:
            verify_versions(release, manifest)
            config_checks(release)
            log('All selected runtime versions are already active')
        else:
            activate(release)
        status(manifest)


if __name__ == '__main__':
    for cancellation_signal in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(cancellation_signal, interrupt_runtime)
    try:
        main()
    except KeyboardInterrupt as exc:
        signum = getattr(exc, 'signum', signal.SIGINT)
        reason = 'Ctrl+C' if signum == signal.SIGINT else signal.Signals(signum).name
        print(f'\nRuntime command cancelled ({reason}). Build logs and recovery snapshots are retained. '
              'Check service health before retrying.', file=sys.stderr)
        raise SystemExit(128 + signum)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f'Runtime upgrade failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
