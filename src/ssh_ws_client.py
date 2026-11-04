#!/usr/bin/env python3
"""OpenSSH ProxyCommand adapter with one asyncio TLS owner and bounded pipe I/O.

Dependency: python -m pip install wsproto==1.3.2 h11==0.16.0
Example: ssh -o 'ProxyCommand=python3 ssh-ws-client.py --host cdn.example.com' user@origin.example.com
stdout is exclusively the SSH byte stream. TLS and SSH host keys stay verified.
"""
import argparse
import asyncio
import contextlib
import ipaddress
import os
import queue
import socket
import ssl
import sys
import threading
import time
from wsproto import WSConnection, ConnectionType
from wsproto.connection import ConnectionState
from wsproto.events import Request, AcceptConnection, RejectConnection, BytesMessage, Ping, CloseConnection, TextMessage
from wsproto.utilities import LocalProtocolError

IO_CHUNK = 65536
MAX_PENDING = 4 * IO_CHUNK
MAX_MESSAGE = 8 * 1024 * 1024
PING_INTERVAL = 25
STALE_TIMEOUT = 90


def wake(loop, event):
    try:
        loop.call_soon_threadsafe(event.set)
    except RuntimeError:
        pass  # A blocked daemon pipe reader must not keep a closed client alive.


def descriptor(stream):
    try:
        return stream.fileno()
    except (OSError, AttributeError):
        return None


class PipeSource:
    """Pipe reads may block on Windows; only this daemon touches stdin's raw FD."""
    def __init__(self, stream):
        self.loop = asyncio.get_running_loop()
        self.ready = asyncio.Event()
        self.stopped = threading.Event()
        self.queue = queue.Queue(maxsize=MAX_PENDING // IO_CHUNK)
        fd = descriptor(stream)
        self.read = (lambda: os.read(fd, IO_CHUNK)) if fd is not None else (lambda: stream.read(IO_CHUNK))
        threading.Thread(target=self.worker, daemon=True).start()

    def put(self, data):
        while not self.stopped.is_set():
            try:
                self.queue.put(data, timeout=.1)
                wake(self.loop, self.ready)
                return
            except queue.Full:
                continue

    def worker(self):
        try:
            while not self.stopped.is_set():
                data = self.read()
                self.put(data or None)
                if not data:
                    return
        except (OSError, ValueError) as exc:
            self.put(exc)

    async def take(self):
        while True:
            self.ready.clear()
            try:
                item = self.queue.get_nowait()
            except queue.Empty:
                await self.ready.wait()
                continue
            if isinstance(item, Exception):
                raise OSError('SSH input closed unexpectedly') from item
            return item

    def close(self):
        self.stopped.set()


class PipeSink:
    """Bound stdout without ever holding a TLS/protocol lock during pipe writes."""
    def __init__(self, stream):
        self.loop = asyncio.get_running_loop()
        self.space = asyncio.Event()
        self.drained = asyncio.Event(); self.drained.set()
        self.failed = asyncio.Event()
        self.stopped = threading.Event()
        self.queue = queue.Queue(maxsize=MAX_PENDING // IO_CHUNK)
        self.pending = 0
        self.error = None
        self.stream = stream
        self.fd = descriptor(stream)
        threading.Thread(target=self.worker, daemon=True).start()

    def completed(self, error=None):
        self.pending -= 1
        self.space.set()
        if error is not None:
            self.error = error
            self.failed.set()
        if self.pending == 0 or self.error is not None:
            self.drained.set()

    def worker(self):
        while not self.stopped.is_set():
            try:
                data = self.queue.get(timeout=.1)
            except queue.Empty:
                continue
            error = None
            try:
                view = memoryview(data)
                while view:
                    count = os.write(self.fd, view) if self.fd is not None else self.stream.write(view)
                    if not isinstance(count, int) or count <= 0:
                        raise OSError('SSH output made no progress')
                    view = view[count:]
                if self.fd is None:
                    self.stream.flush()
            except (OSError, ValueError) as exc:
                error = exc
            try:
                self.loop.call_soon_threadsafe(self.completed, error)
            except RuntimeError:
                return
            if error is not None:
                return

    async def put(self, data):
        if not data:
            return
        while True:
            if self.error is not None:
                raise OSError('SSH output closed unexpectedly') from self.error
            self.space.clear()
            try:
                self.queue.put_nowait(bytes(data))
                self.pending += 1
                self.drained.clear()
                return
            except queue.Full:
                await self.space.wait()

    async def failure(self):
        await self.failed.wait()
        raise OSError('SSH output closed unexpectedly') from self.error

    async def drain(self):
        await self.drained.wait()
        if self.error is not None:
            raise OSError('SSH output closed unexpectedly') from self.error

    def close(self):
        self.stopped.set()


async def close_writer(writer):
    writer.close()
    with contextlib.suppress(OSError, asyncio.TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), 3)


async def connect(host, port, path, address=None):
    if any(ch in host + path for ch in '\r\n\x00') or not path.startswith('/'):
        raise ValueError('Invalid host/path')
    if not 1 <= port <= 65535:
        raise ValueError('Port must be 1-65535')
    if address:
        ipaddress.ip_address(address)
    context = ssl.create_default_context()
    context.set_alpn_protocols(['http/1.1'])
    reader, writer = await asyncio.wait_for(asyncio.open_connection(
        address or host, port, ssl=context, server_hostname=host,
        ssl_handshake_timeout=10, limit=MAX_PENDING), 10)
    try:
        peer = writer.get_extra_info('socket')
        peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        writer.transport.set_write_buffer_limits(high=MAX_PENDING, low=IO_CHUNK)
        ws = WSConnection(ConnectionType.CLIENT)
        writer.write(ws.send(Request(host=host, target=path)))
        await writer.drain()
        pending = []
        deadline = time.monotonic() + 15
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OSError('WebSocket handshake timed out')
            data = await asyncio.wait_for(reader.read(IO_CHUNK), remaining)
            if not data:
                raise OSError('CDN closed before the WebSocket handshake')
            ws.receive_data(data)
            accepted = False
            for event in ws.events():
                if isinstance(event, AcceptConnection):
                    accepted = True
                elif isinstance(event, RejectConnection):
                    raise OSError(f'WebSocket rejected: HTTP {event.status_code}')
                else:
                    pending.append(event)
            if accepted:
                return reader, writer, ws, pending
    except BaseException:
        await close_writer(writer)
        raise


async def pump(reader, writer, ws, pending=(), source=None, sink=None):
    """All SSL and wsproto operations run on this event loop, in both directions."""
    incoming = PipeSource(sys.stdin.buffer if source is None else source)
    outgoing = PipeSink(sys.stdout.buffer if sink is None else sink)
    last_received = time.monotonic()
    message_bytes = 0

    async def events(items):
        nonlocal message_bytes
        for event in items:
            if isinstance(event, BytesMessage):
                message_bytes += len(event.data)
                if message_bytes > MAX_MESSAGE:
                    raise OSError('WebSocket binary message exceeds 8 MiB')
                await outgoing.put(event.data)
                if event.message_finished:
                    message_bytes = 0
            elif isinstance(event, Ping) and ws.state == ConnectionState.OPEN:
                # Never wait for upload backpressure while draining downloads.
                writer.write(ws.send(event.response()))
                if writer.transport.get_write_buffer_size() > MAX_PENDING + IO_CHUNK:
                    raise OSError("WebSocket control traffic exceeded buffer limit")
            elif isinstance(event, TextMessage):
                raise OSError('SSH requires binary WebSocket messages')
            elif isinstance(event, CloseConnection):
                if event.code == 1006:
                    raise OSError('WebSocket connection ended abnormally')
                # A peer may close TCP immediately after its valid close frame.
                with contextlib.suppress(LocalProtocolError, OSError):
                    writer.write(ws.send(event.response()))
                    await writer.drain()
                return False
        return True

    async def download():
        nonlocal last_received
        if not await events(pending):
            return
        while True:
            data = await reader.read(IO_CHUNK)
            if not data:
                raise OSError("WebSocket connection ended without a close frame")
            last_received = time.monotonic()
            ws.receive_data(data)
            # Consume the event iterator before yielding to another coroutine.
            if not await events(list(ws.events())):
                return

    async def upload():
        while True:
            data = await incoming.take()
            if data is None:
                return
            if ws.state != ConnectionState.OPEN:
                return
            writer.write(ws.send(BytesMessage(data=data)))
            await writer.drain()

    async def heartbeat():
        while True:
            await asyncio.sleep(PING_INTERVAL)
            if time.monotonic() - last_received >= STALE_TIMEOUT:
                raise OSError('WebSocket peer stopped responding')
            # Control traffic is tiny; avoid waiting behind an upload's drain.
            if ws.state == ConnectionState.OPEN:
                writer.write(ws.send(Ping(payload=b'noway')))

    tasks = [asyncio.create_task(download()), asyncio.create_task(upload()),
             asyncio.create_task(heartbeat()), asyncio.create_task(outgoing.failure())]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        if tasks[1] in done and not tasks[0].done():
            tasks[2].cancel()
            if ws.state == ConnectionState.OPEN:
                writer.write(ws.send(CloseConnection(code=1000, reason='SSH input closed')))
                await asyncio.wait_for(writer.drain(), 3)
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(tasks[0], 3)
    finally:
        incoming.close()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            await asyncio.wait_for(outgoing.drain(), 3)
        finally:
            outgoing.close()
            await close_writer(writer)


async def run(args):
    await pump(*await connect(args.host, args.port, args.path, args.address))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, help='Hostname used for Host, SNI and TLS verification')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--path', default='/ssh/ws')
    parser.add_argument('--address', help='Optional edge IP; TLS still verifies the hostname')
    args = parser.parse_args()
    if os.name == 'nt':
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    try:
        asyncio.run(run(args))
    except Exception as exc:
        print(f'WSS adapter: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
