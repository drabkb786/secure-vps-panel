"""Failed builds/activation must not damage the live panel or package binaries."""
import hashlib
import importlib.util
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_upgrade', ROOT / 'scripts/upgrade-runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def test_all_selected_sources_are_pinned_and_manifest_rejects_redirected_sources(tmp_path):
    manifest = runtime.read_manifest(ROOT / 'RUNTIME_VERSIONS.json')
    assert manifest['components']['openssl']['version'] == '3.5.9'
    manifest['components']['python']['url'] = 'https://github.com.attacker.invalid/python.tar.xz'
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='Unsafe'):
        runtime.read_manifest(path)


def test_corrupt_cached_source_is_rejected_without_running_build(tmp_path, monkeypatch):
    path = tmp_path / 'source.tar.gz'
    path.write_bytes(b'corrupt archive')
    monkeypatch.setattr(runtime, 'run', lambda *a, **kw: pytest.fail('must not trust/redownload bad cached content'))
    with pytest.raises(RuntimeError, match='SHA256 mismatch'):
        runtime.download({'url': 'https://github.com/source.tar.gz', 'sha256': '0' * 64}, tmp_path)
    runtime.verify_archive(path, hashlib.sha256(path.read_bytes()).hexdigest())


@pytest.mark.parametrize('plugin', ['webroot', 'dns-cloudflare', 'nginx'])
def test_existing_certificates_cannot_lose_required_renewal_plugin(tmp_path, plugin):
    (tmp_path / 'example.conf').write_text('[renewalparams]\nauthenticator = ' + plugin + '\n')
    if plugin == 'webroot':
        runtime.check_renewal_plugins(tmp_path)
    else:
        with pytest.raises(RuntimeError, match='Existing certificate needs'):
            runtime.check_renewal_plugins(tmp_path)


@pytest.mark.parametrize('kind', ['path', 'symlink'])
def test_source_extraction_cannot_escape_directory(tmp_path, kind):
    path = tmp_path / 'source.tar.gz'
    with tarfile.open(path, 'w:gz') as archive:
        item = tarfile.TarInfo('../escaped' if kind == 'path' else 'source/link')
        if kind == 'symlink':
            item.type = tarfile.SYMTYPE
            item.linkname = '../../escaped'
            archive.addfile(item)
        else:
            item.size = 1
            archive.addfile(item, io.BytesIO(b'x'))
    with pytest.raises(tarfile.FilterError):
        runtime.extract(path, tmp_path / 'extracted')
    assert not (tmp_path / 'escaped').exists()


@pytest.fixture
def installation(tmp_path, monkeypatch):
    paths = {'ROOT': tmp_path / 'runtime', 'STATE': tmp_path / 'state',
             'UNITS': tmp_path / 'systemd', 'LOCAL_BIN': tmp_path / 'bin'}
    for name, path in paths.items():
        path.mkdir()
        monkeypatch.setattr(runtime, name, path)
    monkeypatch.setattr(runtime, 'CONFIG_PATHS', ())
    monkeypatch.setattr(runtime, 'config_checks', lambda release: None)
    monkeypatch.setattr(runtime.time, 'sleep', lambda _: None)
    old = paths['ROOT'] / 'releases/old'
    old.mkdir(parents=True)
    (paths['ROOT'] / 'current').symlink_to(old)
    for path in runtime.managed_files():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('previous local configuration\n')
        path.chmod(0o640)
    custom = paths['LOCAL_BIN'] / 'certbot'
    custom.unlink()
    custom.symlink_to('/usr/bin/certbot')
    active_units = ['nginx', 'fail2ban', 'abdulbasit-web']
    monkeypatch.setattr(runtime, 'active', lambda unit: unit in active_units)
    return paths, old, active_units


def test_partial_activation_restores_previous_symlink_overrides_modes_and_services(installation, monkeypatch):
    paths, old, active_units = installation
    candidate = paths['ROOT'] / 'releases/new'
    candidate.mkdir()
    calls = []
    failed = False
    def command(args, **kwargs):
        nonlocal failed
        calls.append(args)
        if args == ['systemctl', 'restart', 'fail2ban'] and not failed:
            failed = True
            raise RuntimeError('native jail failed to start')
        return ''
    monkeypatch.setattr(runtime, 'run', command)
    with pytest.raises(RuntimeError, match='native jail'):
        runtime.activate(candidate)
    assert (paths['ROOT'] / 'current').resolve() == old
    for path in runtime.managed_files():
        if path.name == 'certbot':
            assert path.is_symlink() and os.readlink(path) == '/usr/bin/certbot'
        else:
            assert path.read_text() == 'previous local configuration\n'
            assert path.stat().st_mode & 0o777 == 0o640
    for unit in active_units:
        assert ['systemctl', 'restart', unit] in calls
    assert not (paths['STATE'] / 'last-activation.json').exists()
    archives = list((paths['STATE'] / 'backups').glob('*/configuration.tar.gz'))
    assert len(archives) == 1 and archives[0].stat().st_mode & 0o777 == 0o600


def test_config_failure_prevents_any_live_mutation(installation, monkeypatch):
    paths, old, _ = installation
    def invalid(_):
        raise RuntimeError('incompatible dynamic module')
    monkeypatch.setattr(runtime, 'config_checks', invalid)
    monkeypatch.setattr(runtime, 'run', lambda *a, **kw: pytest.fail('no service command permitted'))
    with pytest.raises(RuntimeError, match='dynamic module'):
        runtime.activate(paths['ROOT'] / 'candidate')
    assert (paths['ROOT'] / 'current').resolve() == old
    assert not (paths['STATE'] / 'backups').exists()


def test_activation_can_be_rolled_back_to_package_commands_when_no_private_runtime_exists(installation, monkeypatch):
    paths, _, active_units = installation
    (paths['ROOT'] / 'current').unlink()
    for path in runtime.managed_files():
        path.unlink()
    candidate = paths['ROOT'] / 'releases/new'
    candidate.mkdir()
    monkeypatch.setattr(runtime, 'run', lambda *a, **kw: '')
    runtime.activate(candidate)
    assert (paths['ROOT'] / 'current').resolve() == candidate
    activation = json.loads((paths['STATE'] / 'last-activation.json').read_text())
    backup = paths['STATE'] / 'backups' / activation['backup']
    state = json.loads((backup / 'state.json').read_text())
    assert state['previous'] is None and state['active'] == active_units
    runtime.restore(backup, state)
    assert not (paths['ROOT'] / 'current').is_symlink()
    assert all(not path.exists() for path in runtime.managed_files())


def test_source_build_uses_native_compiler_despite_poisoned_login_environment(tmp_path, monkeypatch):
    from types import SimpleNamespace
    for name, value in {'PATH': '/not-a-toolchain', 'CC': '/missing/compiler', 'CXX': '/missing/cxx',
                        'CROSS_COMPILE': 'missing-cross-', 'CFLAGS': '-invalid-login-flag',
                        'CPPFLAGS': '-invalid-preprocessor-flag', 'LDFLAGS': '-invalid-linker-flag',
                        'LD_LIBRARY_PATH': '/foreign-libraries', 'CONFIG_SITE': '/foreign-config',
                        'MAKEFLAGS': '--invalid-make-flag'}.items():
        monkeypatch.setenv(name, value)
    inherited = dict(os.environ)
    observed = []
    def execute(args, **kwargs):
        observed.append(kwargs['env'])
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(runtime.subprocess, 'run', execute)
    runtime.build_run(['./config'], tmp_path, tmp_path / 'build.log')
    environment = observed[0]
    assert environment['CC'] == '/usr/bin/gcc' and environment['CXX'] == '/usr/bin/g++'
    assert environment['PATH'] == '/usr/sbin:/usr/bin:/sbin:/bin'
    assert environment['CONFIG_SITE'] == '/dev/null'
    for name in ('CROSS_COMPILE', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LD_LIBRARY_PATH', 'MAKEFLAGS'):
        assert name not in environment
    assert dict(os.environ) == inherited, 'Build sanitization must not alter caller/service environment'


@pytest.mark.skipif(not (Path('/usr/bin/gcc').is_file() and Path('/usr/bin/g++').is_file()),
                    reason='Requires distribution C and C++ compilers')
def test_native_compiler_probe_links_and_executes_with_bad_inherited_flags(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, 'ROOT', tmp_path)
    monkeypatch.setenv('CC', '/missing/compiler')
    monkeypatch.setenv('CROSS_COMPILE', 'missing-cross-')
    monkeypatch.setenv('CFLAGS', '-not-a-valid-compiler-option')
    monkeypatch.setenv('LDFLAGS', '-not-a-valid-linker-option')
    runtime.verify_toolchain()
    assert not list(tmp_path.glob('.compiler-check-*')), 'Compiler probes must clean up their temporary binaries'


def test_missing_or_broken_compiler_fails_before_any_source_build(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, 'STATE', tmp_path)
    monkeypatch.setattr(runtime, 'preflight', lambda: None)
    monkeypatch.setattr(runtime, 'run', lambda *args, **kwargs: '')
    monkeypatch.setattr(runtime.sys, 'argv', ['upgrade-runtime.py', '--apply'])
    def broken():
        raise RuntimeError('Native C/C++ compiler check failed before downloads/activation')
    monkeypatch.setattr(runtime, 'verify_toolchain', broken)
    monkeypatch.setattr(runtime, 'build', lambda *a: pytest.fail('No downloads or builds after failed compiler probe'))
    monkeypatch.setattr(runtime, 'activate', lambda *a: pytest.fail('No activation after failed compiler probe'))
    with pytest.raises(RuntimeError, match='compiler check failed'):
        runtime.main()


def test_compiler_failure_reports_the_actual_problem_and_repair_command(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, 'ROOT', tmp_path)
    def failure(args, **kwargs):
        raise RuntimeError('gcc: cannot find crt1.o')
    monkeypatch.setattr(runtime, 'run', failure)
    with pytest.raises(RuntimeError, match='gcc: cannot find crt1.o.*apt-get install --reinstall'):
        runtime.verify_toolchain()
    assert not list(tmp_path.glob('.compiler-check-*'))
