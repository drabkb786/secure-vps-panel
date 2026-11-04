"""Regressions from the 4.2 throughput and concurrency audit."""
import asyncio
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
from types import SimpleNamespace

import pytest
import dropbear_sessions
import openssh_sessions
import paneld
import session_enforcer
import ssh_identity
import ssh_ws_client


@pytest.mark.parametrize('command', ['diagnostics', 'dashboard_status', 'web_revision', 'web_auth'])
def test_reader_authorization_does_not_wait_for_active_writer(monkeypatch, command):
    entered, release = threading.Event(), threading.Event()
    def writer(_):
        entered.set()
        assert release.wait(5)
        return {'written': True}
    monkeypatch.setattr(paneld, 'HANDLERS', {'xray_sync': writer, command: lambda _: {'read': True}})
    monkeypatch.setattr(paneld, 'peer_uid', lambda _: 0)
    monkeypatch.setattr(paneld, 'allowed_peer', lambda _: True)
    a, a_server = socket.socketpair(); b, b_server = socket.socketpair()
    threads = [threading.Thread(target=paneld.handle_connection, args=(peer,), daemon=True) for peer in (a_server, b_server)]
    try:
        threads[0].start(); a.sendall(b'{"command":"xray_sync"}\n')
        assert entered.wait(2)
        threads[1].start(); b.sendall((json.dumps({'command': command}) + '\n').encode()); b.settimeout(2)
        assert json.loads(b.recv(4096))['read'] is True
    finally:
        release.set()
        for thread in threads:
            if thread.is_alive(): thread.join(3)
        a.close(); b.close()


@pytest.mark.skipif(os.geteuid() != 0, reason='Executable trust requires root-owned fixture')
@pytest.mark.parametrize('backend', [openssh_sessions, dropbear_sessions])
def test_active_ssh_executable_survives_package_replacement(tmp_path, monkeypatch, backend):
    executable = tmp_path / 'sshd'
    shutil.copyfile('/bin/sleep', executable); executable.chmod(0o755)
    monkeypatch.setattr(backend, 'EXECUTABLES', (executable,))
    process = subprocess.Popen([str(executable), '30'])
    try:
        metadata = backend.metadata if backend is openssh_sessions else backend.process
        try:
            os.readlink('/proc/' + str(process.pid) + '/exe')
        except (PermissionError, FileNotFoundError):
            if os.environ.get("GITHUB_ACTIONS") == "true":
                raise
            pytest.skip('Container prevents reading child /proc executable')
        before = metadata(process.pid)
        assert before is not None
        executable.unlink()
        assert metadata(process.pid) == before
        # Replacing the pathname cannot alter the original running inode's trust.
        executable.write_text('replacement'); executable.chmod(0o777)
        assert metadata(process.pid) == before
    finally:
        process.terminate(); process.wait(timeout=3)


def test_unlimited_ip_accounts_skip_socket_scan(tmp_path, monkeypatch):
    (tmp_path / 'basit.json').write_text(json.dumps({'username': 'basit', 'expiry': '2099-12-31', 'max_ips': 0, 'max_sessions': 2}))
    monkeypatch.setattr(session_enforcer, 'USERS_DIR', tmp_path)
    monkeypatch.setattr(session_enforcer, 'dropbear_pids_by_uid', lambda: {1001: [123]})
    monkeypatch.setattr(session_enforcer.pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=1001))
    def unexpected(*_): raise AssertionError('Unnecessary socket/FD scan')
    monkeypatch.setattr(ssh_identity, 'session_ips', unexpected)
    session_enforcer.enforce_once()


def test_no_sessions_skip_kernel_socket_scan(monkeypatch):
    def unexpected(*_): raise AssertionError('Unnecessary kernel socket scan')
    monkeypatch.setattr(ssh_identity, 'tcp_sockets', unexpected)
    assert ssh_identity.session_ips({1001: []}) == {}


def test_pipe_sink_preserves_partial_writes():
    class Partial(io.BytesIO):
        def write(self, data): return super().write(bytes(data[:3]))
    async def run():
        output = Partial(); sink = ssh_ws_client.PipeSink(output)
        try:
            for _ in range(10): await sink.put(b'abcdefgh')
            await asyncio.wait_for(sink.drain(), 3)
            assert output.getvalue() == b'abcdefgh' * 10
        finally: sink.close()
    asyncio.run(run())


@pytest.mark.parametrize('flag', ['false', 1, None, []])
def test_backup_rejects_nonboolean_reality_flag(flag):
    import profile_backup
    from common import ValidationError
    with pytest.raises(ValidationError, match='REALITY'):
        profile_backup.validate({'schema': profile_backup.SCHEMA, 'network': {'enabled': False, 'reality_enabled': flag}, 'accounts': []}, lambda _: {})


def test_cdn_probes_run_concurrently_with_deterministic_report(monkeypatch):
    import cdn_manager
    barrier = threading.Barrier(5)
    def probe(host, path, websocket):
        barrier.wait(timeout=3)
        return {'ok': True, 'path': path}
    monkeypatch.setattr(cdn_manager, 'probe', probe)
    report = cdn_manager.probe_paths('cdn.example.com', cdn_manager.PATHS)
    assert list(report) == [name for name in cdn_manager.PATHS if name != 'xhttp']
    assert all(row['ok'] for row in report.values())
