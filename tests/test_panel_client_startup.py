"""Exercise startup races with real UNIX sockets, without replaying commands."""
import errno
import json
import os
import socket
import threading
import time

import pytest

import panel_client as client


@pytest.fixture
def rpc_peer(tmp_path, monkeypatch):
    path = tmp_path / 'panel.sock'
    monkeypatch.setattr(client, 'SOCKET_PATH', path)
    native_socket = socket.socket
    try:
        with native_socket(socket.AF_UNIX, socket.SOCK_STREAM):
            pass
    except PermissionError:
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            raise
        pytest.skip('This container prohibits creating AF_UNIX sockets; exercised on hosted CI')
    attempts = []
    first_failure = threading.Event()
    threads = []
    errors = []

    class ObservedSocket(native_socket):
        def connect(self, address):
            attempts.append(address)
            try:
                return super().connect(address)
            except OSError:
                first_failure.set()
                raise

    monkeypatch.setattr(client.socket, 'socket', ObservedSocket)

    def serve(*, after_failure=False, reply=b'{"ok":true,"revision":"r1"}\n', hold=0):
        ready = threading.Event()
        requests = []

        def run():
            try:
                if after_failure:
                    assert first_failure.wait(2), 'client did not attempt its connection'
                path.unlink(missing_ok=True)
                with native_socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    listener.bind(str(path))
                    listener.listen(1)
                    listener.settimeout(2)
                    ready.set()
                    peer, _ = listener.accept()
                    with peer:
                        peer.settimeout(2)
                        data = b''
                        while b'\n' not in data:
                            chunk = peer.recv(4096)
                            assert chunk, 'client closed before sending a request'
                            data += chunk
                        requests.append(json.loads(data.split(b'\n', 1)[0]))
                        if hold:
                            threading.Event().wait(hold)
                        if reply:
                            peer.sendall(reply)
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        threads.append(thread)
        thread.start()
        if not after_failure:
            assert ready.wait(2), errors
        return requests

    yield path, native_socket, attempts, serve
    for thread in threads:
        thread.join(3)
        assert not thread.is_alive(), 'RPC fixture did not finish'
    assert not errors


@pytest.mark.parametrize('stale_socket', [False, True], ids=['not-created', 'refused'])
def test_delayed_daemon_accepts_command_once(rpc_peer, stale_socket):
    path, native_socket, attempts, serve = rpc_peer
    if stale_socket:
        with native_socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
            stale.bind(str(path))
    requests = serve(after_failure=True)

    assert client.request('create_user', username='basit')['ok'] is True
    assert len(attempts) >= 2
    assert requests == [{'command': 'create_user', 'params': {'username': 'basit'}}]


def test_missing_daemon_has_bounded_clear_error(monkeypatch):
    sockets = []

    class MissingSocket:
        def __init__(self, *args):
            self.closed = False
            sockets.append(self)

        def settimeout(self, timeout):
            pass

        def connect(self, address):
            raise FileNotFoundError(errno.ENOENT, 'not ready')

        def close(self):
            self.closed = True

    monkeypatch.setattr(client.socket, 'socket', MissingSocket)
    monkeypatch.setattr(client, 'CONNECT_WAIT', .08)
    started = time.monotonic()
    with pytest.raises(client.PanelNotReady, match='journalctl -u abdulbasit-paneld'):
        client.request('diagnostics')
    assert time.monotonic() - started < .8
    assert len(sockets) >= 2
    assert all(peer.closed for peer in sockets)


@pytest.mark.parametrize('error', [errno.EACCES, errno.EINVAL, errno.EIO])
def test_other_connection_errors_are_not_retried(tmp_path, monkeypatch, error):
    sockets = []

    class FailingSocket:
        def __init__(self, *args):
            self.closed = False

        def settimeout(self, timeout):
            pass

        def connect(self, address):
            sockets.append(self)
            raise OSError(error, 'connection rejected')

        def close(self):
            self.closed = True

    monkeypatch.setattr(client, 'SOCKET_PATH', tmp_path / 'panel.sock')
    monkeypatch.setattr(client.socket, 'socket', FailingSocket)
    with pytest.raises(OSError) as caught:
        client.request('diagnostics')
    assert caught.value.errno == error
    assert len(sockets) == 1
    assert sockets[0].closed


def test_empty_reply_does_not_replay_an_accepted_change(rpc_peer):
    _, _, attempts, serve = rpc_peer
    requests = serve(reply=b'')
    with pytest.raises(client.PanelNotReady, match='command was not replayed'):
        client.request('delete_user', username='basit')
    assert len(attempts) == 1
    assert requests == [{'command': 'delete_user', 'params': {'username': 'basit'}}]


def test_response_timeout_does_not_replay_an_accepted_change(rpc_peer):
    _, _, attempts, serve = rpc_peer
    requests = serve(reply=b'', hold=.15)
    with pytest.raises(TimeoutError):
        client.exchange('renew_user', {'username': 'basit'}, response_timeout=.03, connect_wait=.5)
    assert len(attempts) == 1
    assert requests == [{'command': 'renew_user', 'params': {'username': 'basit'}}]


def test_daemon_error_is_reported_without_retry(rpc_peer):
    _, _, attempts, serve = rpc_peer
    serve(reply=b'{"ok":false,"error":"Rejected by daemon"}\n')
    with pytest.raises(RuntimeError, match='Rejected by daemon'):
        client.request('create_user', username='basit')
    assert len(attempts) == 1


def test_readiness_uses_a_read_only_rpc(rpc_peer):
    _, _, attempts, serve = rpc_peer
    requests = serve(after_failure=True)
    assert client.wait_ready(timeout=.5) is None
    assert requests == [{'command': 'web_revision', 'params': {}}]
    assert len(attempts) >= 2


@pytest.mark.parametrize('timeout', [0, -1])
def test_invalid_readiness_timeout_is_rejected(timeout):
    with pytest.raises(ValueError, match='must be positive'):
        client.wait_ready(timeout=timeout)


@pytest.mark.parametrize('reply', ['success', 'eof', 'timeout', 'send-error', 'daemon-error'])
def test_failed_connections_are_closed_and_payload_is_never_replayed(monkeypatch, reply):
    """Deterministic fault coverage also runs where AF_UNIX creation is denied."""
    faults = [errno.ENOENT, errno.ECONNREFUSED, None]
    sockets, payloads = [], []
    clock = [0.0]
    monkeypatch.setattr(client.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(client.time, 'sleep', lambda delay: clock.__setitem__(0, clock[0] + delay))

    class Peer:
        def __init__(self, *args):
            self.closed = False
            self.fault = faults.pop(0)
            sockets.append(self)

        def settimeout(self, timeout):
            pass

        def connect(self, address):
            if self.fault:
                raise OSError(self.fault, 'daemon is starting')

        def sendall(self, data):
            payloads.append(json.loads(data))
            if reply == 'send-error':
                raise BrokenPipeError('daemon closed during send')

        def recv(self, limit):
            if reply == 'timeout':
                raise TimeoutError('reply timed out')
            if reply == 'eof':
                return b''
            if reply == 'daemon-error':
                return b'{"ok":false,"error":"Denied"}\n'
            return b'{"ok":true}\n'

        def close(self):
            self.closed = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    monkeypatch.setattr(client.socket, 'socket', Peer)
    if reply == 'success':
        assert client.request('renew_user', username='basit') == {'ok': True}
    else:
        expected = {'eof': client.PanelNotReady, 'timeout': TimeoutError,
                    'send-error': BrokenPipeError, 'daemon-error': RuntimeError}[reply]
        with pytest.raises(expected):
            client.request('renew_user', username='basit')
    assert not faults
    assert len(sockets) == 3
    assert all(peer.closed for peer in sockets)
    assert payloads == [{'command': 'renew_user', 'params': {'username': 'basit'}}]
