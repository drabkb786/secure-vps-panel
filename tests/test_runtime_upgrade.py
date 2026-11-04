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
        return SimpleNamespace(returncode=0, wait=lambda timeout: 0)
    monkeypatch.setattr(runtime.subprocess, 'Popen', execute)
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


def test_build_reports_progress_while_command_is_still_running(tmp_path, monkeypatch):
    import sys
    marker = tmp_path / 'done'
    observed = []
    def observe(message):
        observed.append((message, marker.exists()))
    monkeypatch.setattr(runtime, 'log', observe)
    monkeypatch.setattr(runtime, 'BUILD_PROGRESS_SECONDS', .03)
    command = [sys.executable, '-c', 'import time; from pathlib import Path; print("compiling real fixture", flush=True); time.sleep(.2); Path(' + repr(str(marker)) + ').touch()']
    runtime.build_run(command, tmp_path, tmp_path / 'build.log')
    assert marker.exists()
    assert any('Still running' in message and not done for message, done in observed)
    assert any('compiling real fixture' in message for message, _ in observed)
    assert observed[-1][0].startswith('Finished ')


def test_failed_build_includes_actual_error_in_terminal(tmp_path, monkeypatch):
    import sys
    monkeypatch.setattr(runtime, 'BUILD_PROGRESS_SECONDS', .05)
    with pytest.raises(RuntimeError, match='actual compiler failure'):
        runtime.build_run([sys.executable, '-c', 'import sys; print("actual compiler failure", file=sys.stderr); sys.exit(2)'], tmp_path, tmp_path / 'build.log')


def test_interrupt_stops_build_and_sigterm_ignoring_compiler_child(tmp_path, monkeypatch):
    import sys
    import time
    ready, completed = tmp_path / 'child-ready', tmp_path / 'child-completed'
    child = ('import signal,time; from pathlib import Path; '
             'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
             f'Path({str(ready)!r}).touch(); time.sleep(2); Path({str(completed)!r}).touch()')
    parent = f'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",{child!r}]); time.sleep(30)'
    def interrupt_when_ready(message):
        if message.startswith('Still running') and ready.exists():
            raise KeyboardInterrupt
    monkeypatch.setattr(runtime, 'log', interrupt_when_ready)
    monkeypatch.setattr(runtime, 'BUILD_PROGRESS_SECONDS', .03)
    with pytest.raises(KeyboardInterrupt):
        runtime.build_run([sys.executable, '-c', parent], tmp_path, tmp_path / 'build.log', timeout=5)
    assert ready.exists(), 'The child must really have started and ignored SIGTERM'
    time.sleep(2.2)
    assert not completed.exists(), 'The compiler descendant must be killed even after its make-like parent exits'


def test_build_timeout_cancels_child_before_it_can_finish(tmp_path, monkeypatch):
    import subprocess
    import sys
    import time
    marker = tmp_path / 'late-output'
    code = f'import time; from pathlib import Path; time.sleep(.5); Path({str(marker)!r}).touch()'
    monkeypatch.setattr(runtime, 'BUILD_PROGRESS_SECONDS', .03)
    with pytest.raises(subprocess.TimeoutExpired):
        runtime.build_run([sys.executable, '-c', code], tmp_path, tmp_path / 'build.log', timeout=.1)
    time.sleep(.6)
    assert not marker.exists()


def test_cli_ctrl_c_has_clear_message_and_conventional_exit_code():
    import subprocess
    import sys
    driver = ('import argparse,runpy; '
              'argparse.ArgumentParser.parse_args=lambda *args,**kwargs: (_ for _ in ()).throw(KeyboardInterrupt()); '
              f'runpy.run_path({str(ROOT / "scripts/upgrade-runtime.py")!r},run_name="__main__")')
    result = subprocess.run([sys.executable, '-c', driver], capture_output=True, text=True, timeout=5)
    assert result.returncode == 130
    assert 'cancelled (Ctrl+C)' in result.stderr
    assert 'Traceback' not in result.stderr


@pytest.mark.parametrize('name,code', [('SIGHUP', 129), ('SIGTERM', 143)])
def test_cli_disconnect_and_termination_use_the_cancellation_cleanup(name, code):
    import subprocess
    import sys
    driver = ('import argparse,os,signal,runpy; '
              f'argparse.ArgumentParser.parse_args=lambda *args,**kwargs: os.kill(os.getpid(),signal.{name}); '
              f'runpy.run_path({str(ROOT / "scripts/upgrade-runtime.py")!r},run_name="__main__")')
    result = subprocess.run([sys.executable, '-c', driver], capture_output=True, text=True, timeout=5)
    assert result.returncode == code
    assert f'cancelled ({name})' in result.stderr
    assert 'Traceback' not in result.stderr


@pytest.mark.parametrize('plugin', ['webroot', 'standalone', 'manual', '"webroot" # inline comment'])
def test_certbot_root_settings_and_nested_webroot_map_are_read_without_rewriting(tmp_path, plugin):
    path = tmp_path / 'vpn.example.com.conf'
    original = ('# Certbot-generated renewal format\nversion = 2.9.0\n'
                'archive_dir = /etc/letsencrypt/archive/vpn.example.com\n'
                'cert = /etc/letsencrypt/live/vpn.example.com/cert.pem\n'
                'privkey = /etc/letsencrypt/live/vpn.example.com/privkey.pem\n'
                'chain = /etc/letsencrypt/live/vpn.example.com/chain.pem\n'
                'fullchain = /etc/letsencrypt/live/vpn.example.com/fullchain.pem\n'
                f'[renewalparams]\nauthenticator = {plugin}\ninstaller = None\n'
                'webroot_path = /var/www/letsencrypt,\n'
                '[[webroot_map]]\nvpn.example.com = /var/www/letsencrypt\n')
    path.write_text(original)
    before = path.stat()
    runtime.check_renewal_plugins(tmp_path)
    after = path.stat()
    assert path.read_text() == original
    assert (before.st_mtime_ns, before.st_mode) == (after.st_mtime_ns, after.st_mode)


@pytest.mark.parametrize('plugin', ['"dns-cloudflare" # inline comment', 'nginx'])
def test_headerless_configobj_file_still_blocks_missing_renewal_plugins(tmp_path, plugin):
    (tmp_path / 'example.conf').write_text(f'version = 2.9.0\n[renewalparams]\nauthenticator = {plugin}\n[[webroot_map]]\nexample.com = /webroot\n')
    with pytest.raises(RuntimeError, match='Existing certificate needs'):
        runtime.check_renewal_plugins(tmp_path)


@pytest.mark.parametrize('plugin', ['webroot', 'dns-cloudflare'])
def test_configobj_plugin_interpolation_matches_certbot(tmp_path, plugin):
    (tmp_path / 'example.conf').write_text(f'plugin = {plugin}\nversion = 2.9.0\n[renewalparams]\nauthenticator = %(plugin)s\n')
    if plugin == 'webroot':
        runtime.check_renewal_plugins(tmp_path)
    else:
        with pytest.raises(RuntimeError, match='dns-cloudflare'):
            runtime.check_renewal_plugins(tmp_path)


@pytest.mark.parametrize('content', ['version = 2.9.0\n[broken', 'version = 2.9.0\n',
                                   'version = 2.9.0\n[renewalparams]\nauthenticator = webroot, nginx\n',
                                   'version = 2.9.0\n[renewalparams]\nauthenticator = %(missing)s\n'])
def test_invalid_renewal_files_fail_clearly_before_activation(tmp_path, content):
    (tmp_path / 'example.conf').write_text(content)
    with pytest.raises(RuntimeError, match='Certbot renewal file'):
        runtime.check_renewal_plugins(tmp_path)


@pytest.fixture
def completed_build(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip('Completed release validation requires root-owned build files')
    root = tmp_path / 'runtime'; root.mkdir()
    monkeypatch.setattr(runtime, 'ROOT', root)
    manifest = runtime.read_manifest(ROOT / 'RUNTIME_VERSIONS.json')
    release = root / 'releases/8118e9df56f5'; release.mkdir(parents=True)
    (release / 'READY').write_text(release.name + '\n')
    (release / 'manifest.json').write_text(json.dumps(manifest))
    checked = []
    monkeypatch.setattr(runtime, 'verify_versions', lambda *args: checked.append(args))
    return release, manifest, checked


def test_completed_release_is_version_checked_without_rebuilding(completed_build):
    release, manifest, checked = completed_build
    assert runtime.completed_release(release.name, manifest) == release
    assert checked == [(release, manifest)]


def test_completed_release_accepts_staged_fail2ban_python_binding(completed_build):
    release, manifest, checked = completed_build
    bindir = release / 'fail2ban/usr/bin'; bindir.mkdir(parents=True)
    # dpkg extracts this relative system-interpreter binding into a private
    # prefix. The managed wrappers already invoke /usr/bin/python3 explicitly.
    (bindir / 'fail2ban-python').symlink_to('python3')
    assert not (bindir / 'python3').exists()
    assert runtime.completed_release(release.name, manifest) == release
    assert os.readlink(bindir / 'fail2ban-python') == 'python3'
    assert checked == [(release, manifest)]


def test_completed_release_rejects_unexpected_dangling_links(completed_build):
    release, manifest, checked = completed_build
    (release / 'unexpected-python').symlink_to('python3')
    with pytest.raises(RuntimeError, match='link target'):
        runtime.completed_release(release.name, manifest)
    assert not checked


@pytest.mark.parametrize('target', ['../python3', 'missing-python'])
def test_staged_fail2ban_binding_exception_is_narrow(completed_build, target):
    release, manifest, checked = completed_build
    bindir = release / 'fail2ban/usr/bin'; bindir.mkdir(parents=True)
    (bindir / 'fail2ban-python').symlink_to(target)
    with pytest.raises(RuntimeError, match='link target'):
        runtime.completed_release(release.name, manifest)
    assert not checked


def test_staged_fail2ban_binding_cannot_hide_an_unsafe_local_interpreter(completed_build):
    release, manifest, checked = completed_build
    bindir = release / 'fail2ban/usr/bin'; bindir.mkdir(parents=True)
    (bindir / 'fail2ban-python').symlink_to('python3')
    interpreter = bindir / 'python3'; interpreter.write_text('untrusted'); interpreter.chmod(0o777)
    with pytest.raises(RuntimeError, match='Unsafe'):
        runtime.completed_release(release.name, manifest)
    assert not checked


def test_fresh_runtime_sealing_removes_inherited_write_access_before_reuse(completed_build):
    release, manifest, checked = completed_build
    venv = release / 'venv'; venv.mkdir(); venv.chmod(0o775)
    binary = venv / 'python'; binary.write_text('fixture'); binary.chmod(0o775)
    module = venv / 'module.py'; module.write_text('fixture'); module.chmod(0o664)
    runtime.seal_fresh_release(release)
    assert venv.stat().st_mode & 0o777 == 0o755
    assert binary.stat().st_mode & 0o777 == 0o755
    assert module.stat().st_mode & 0o777 == 0o644
    assert runtime.completed_release(release.name, manifest) == release
    assert checked == [(release, manifest)]


def test_fresh_runtime_sealing_rejects_special_files(completed_build):
    release, _, _ = completed_build
    os.mkfifo(release / 'unexpected-pipe')
    with pytest.raises(RuntimeError, match='file type'):
        runtime.seal_fresh_release(release)


@pytest.mark.parametrize('problem', ['missing_ready', 'wrong_receipt', 'wrong_versions', 'writable', 'symlink', 'foreign_owner'])
def test_incomplete_or_untrusted_releases_are_rejected(completed_build, problem):
    release, manifest, checked = completed_build
    if problem == 'missing_ready': (release / 'READY').unlink()
    elif problem == 'wrong_receipt': (release / 'READY').write_text('a' * 12)
    elif problem == 'wrong_versions': (release / 'manifest.json').write_text('{}')
    elif problem == 'writable': (release / 'READY').chmod(0o666)
    elif problem == 'foreign_owner':
        try:
            os.chown(release / 'READY', 65534, -1)
        except OSError as exc:
            if exc.errno in (1, 22) and os.environ.get('GITHUB_ACTIONS') != 'true':
                pytest.skip('Container does not map a foreign UID')
            raise
    else:
        moved = release.with_name('elsewhere'); release.rename(moved); release.symlink_to(moved, target_is_directory=True)
    with pytest.raises(RuntimeError):
        runtime.completed_release(release.name, manifest)
    assert not checked


@pytest.mark.parametrize('identifier', ['', '../8118e9df56f5', '/tmp/release', 'failed-build-8118e9df56f5', 'nothex'])
def test_activate_built_rejects_non_release_names(identifier):
    with pytest.raises(ValueError, match='Invalid completed build ID'):
        runtime.completed_release(identifier, {})


def test_activate_built_never_installs_downloads_or_compiles(completed_build, tmp_path, monkeypatch):
    release, manifest, _ = completed_build
    monkeypatch.setattr(runtime, 'STATE', tmp_path)
    monkeypatch.setattr(runtime, 'preflight', lambda: None)
    monkeypatch.setattr(runtime.sys, 'argv', ['upgrade-runtime.py', '--activate-built', release.name])
    def forbidden(*args, **kwargs): pytest.fail('No compiler, download or apt commands for completed activation')
    for name in ('build', 'run', 'download', 'verify_toolchain'):
        monkeypatch.setattr(runtime, name, forbidden)
    activated = []
    monkeypatch.setattr(runtime, 'activate', activated.append)
    monkeypatch.setattr(runtime, 'status', lambda _: None)
    runtime.main()
    assert activated == [release]


def test_completed_release_rejects_links_into_writable_directories(completed_build):
    release, manifest, checked = completed_build
    destination = release.parent / 'writable'; destination.mkdir(); destination.chmod(0o777)
    (release / 'unsafe-link').symlink_to(destination, target_is_directory=True)
    with pytest.raises(RuntimeError, match='link target'):
        runtime.completed_release(release.name, manifest)
    assert not checked


def test_empty_activate_built_argument_cannot_fall_back_to_a_full_build(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, 'STATE', tmp_path)
    monkeypatch.setattr(runtime, 'preflight', lambda: None)
    monkeypatch.setattr(runtime.sys, 'argv', ['upgrade-runtime.py', '--activate-built', ''])
    def forbidden(*args, **kwargs): pytest.fail('Invalid completed ID must not start apt or compilation')
    monkeypatch.setattr(runtime, 'run', forbidden)
    monkeypatch.setattr(runtime, 'build', forbidden)
    with pytest.raises(ValueError, match='Invalid completed build ID'):
        runtime.main()


def test_source_build_refuses_an_unprotected_release_parent_before_downloads(completed_build, monkeypatch):
    release, manifest, _ = completed_build
    release.parent.chmod(0o777)
    monkeypatch.setattr(runtime, 'download', lambda *a: pytest.fail('Do not build in a writable parent'))
    with pytest.raises(RuntimeError, match='Unsafe runtime release directory'):
        runtime.build(manifest, 2)
