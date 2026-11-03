"""Opt-in acceptance on a disposable systemd CI host, after the real build."""
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('NOWAY_RUNTIME_NATIVE') != '1' or os.geteuid() != 0,
    reason='Requires explicit disposable systemd runner opt-in after the runtime build')

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout + result.stderr


def test_actual_versions_preserved_configs_renewal_command_and_reversible_activation():
    spec = importlib.util.spec_from_file_location('runtime_native', ROOT / 'scripts/upgrade-runtime.py')
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    manifest = runtime.read_manifest(ROOT / 'RUNTIME_VERSIONS.json')
    active = Path('/opt/noway/runtime/current').resolve()
    runtime.verify_versions(active, manifest)
    assert '3.15.2' in run('/usr/local/lib/abdulbasit/python', '--version')
    assert '5.9.0' in run('/usr/local/bin/certbot', '--version')
    assert '1.1.1' in run('/usr/local/bin/fail2ban-client', '--version')
    assert 'PONG' in run('/usr/local/bin/fail2ban-client', 'ping')
    assert 'abdulbasit-sshd' in run('/usr/local/bin/fail2ban-client', 'status')
    renewal = run('systemctl', 'show', 'certbot.service', '-p', 'ExecStart')
    assert '/opt/noway/runtime/current/bin/certbot' in renewal and '-q renew' in renewal
    assert 'active' in run('systemctl', 'is-active', 'certbot.timer')
    # Snapshot every config/certificate/key and symlink, then round-trip activation.
    def contents():
        result = {}
        for directory in ('/etc/nginx', '/etc/fail2ban', '/etc/letsencrypt'):
            for path in Path(directory).rglob('*'):
                if path.is_symlink():
                    result[str(path)] = ('link', os.readlink(path))
                elif path.is_file():
                    result[str(path)] = ('file', hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode)
        return result
    before = contents()
    state = json.loads(Path('/var/lib/noway-runtime/last-activation.json').read_text())
    run('/usr/bin/python3', ROOT / 'scripts/upgrade-runtime.py', '--rollback', state['backup'])
    assert not Path('/opt/noway/runtime/current').is_symlink()
    assert run('/usr/local/lib/abdulbasit/python', '--version') == run('/usr/bin/python3', '--version')
    for unit in ('nginx', 'fail2ban', 'abdulbasit-paneld', 'abdulbasit-ws', 'abdulbasit-web'):
        assert 'active' in run('systemctl', 'is-active', unit)
    # Cached immutable build is reused; downloads/build commands are not needed.
    runtime.config_checks(active)
    runtime.activate(active)
    assert Path('/opt/noway/runtime/current').resolve() == active
    assert contents() == before
    assert 'PONG' in run('/usr/local/bin/fail2ban-client', 'ping')
    for unit in ('nginx', 'fail2ban', 'abdulbasit-paneld', 'abdulbasit-ws', 'abdulbasit-web'):
        assert 'active' in run('systemctl', 'is-active', unit)
