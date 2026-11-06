"""Bounded UDP dispatcher for two delegated DNSTT zones on one public port."""
from __future__ import annotations

import errno
import selectors
import socket
import struct
import subprocess
import time

MAX_PACKET = 4096
MAX_PEERS = 512
IDLE_SECONDS = 60
BACKEND_PORTS = (53530, 53531)


def question_zone(packet, zones):
    if len(packet) < 17 or len(packet) > MAX_PACKET:
        return None
    _, flags, questions, answers, authority, _ = struct.unpack_from('!6H', packet)
    if flags & 0xFA00 or questions != 1 or answers or authority:
        return None
    labels, offset = [], 12
    while offset < min(len(packet), 267):
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size > len(packet):
            return None
        label = packet[offset:offset + size]
        if any(c not in b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in label):
            return None
        labels.append(label.decode('ascii').lower())
        offset += size
    else:
        return None
    if offset - 12 > 255 or offset + 4 > len(packet):
        return None
    query_type, query_class = struct.unpack_from('!HH', packet, offset)
    # Recursive resolvers may probe the zone with NS/SOA/A/AAAA before TXT.
    # Let the official authoritative backend produce those responses too.
    if query_class != 1 or query_type not in (1, 2, 6, 16, 28):
        return None
    name = '.'.join(labels)
    return next((zone for zone in zones if name == zone or name.endswith('.' + zone)), None)


class Router:
    def __init__(self, address, routes):
        self.routes = routes
        self.selector = selectors.DefaultSelector()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.listener.bind(address)
            self.listener.setblocking(False)
            self.selector.register(self.listener, selectors.EVENT_READ, None)
        except BaseException:
            self.listener.close(); self.selector.close()
            raise
        self.peers = {}

    def close(self):
        for peer, _ in self.peers.values():
            peer.close()
        self.listener.close()
        self.selector.close()

    def step(self, timeout=1):
        current = time.monotonic()
        for identity, (peer, touched) in list(self.peers.items()):
            if current - touched > IDLE_SECONDS:
                self.selector.unregister(peer); peer.close()
                del self.peers[identity]
        for event, _ in self.selector.select(timeout):
            if event.fileobj is self.listener:
                packet, source = self.listener.recvfrom(MAX_PACKET + 1)
                zone = question_zone(packet, self.routes)
                if zone is None:
                    continue
                identity = (source, zone, packet[:2])
                if identity not in self.peers:
                    if len(self.peers) >= MAX_PEERS:
                        continue
                    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        peer.connect(self.routes[zone]); peer.setblocking(False)
                        self.selector.register(peer, selectors.EVENT_READ, identity)
                    except BaseException:
                        peer.close()
                        raise
                else:
                    peer = self.peers[identity][0]
                self.peers[identity] = (peer, current)
                try:
                    peer.send(packet)
                except OSError:
                    pass
            else:
                peer, identity = event.fileobj, event.data
                try:
                    packet = peer.recv(MAX_PACKET + 1)
                    if 12 <= len(packet) <= MAX_PACKET and packet[:2] == identity[2]:
                        self.listener.sendto(packet, identity[0])
                except OSError:
                    pass
                finally:
                    self.selector.unregister(peer); peer.close()
                    del self.peers[identity]


def serve(binary, key, config, *, upstreams=("127.0.0.1:109", "127.0.0.1:10006")):
    zones = (config['zone'], config['xray_zone'])
    routes = dict(zip(zones, [('127.0.0.1', port) for port in BACKEND_PORTS]))
    children, router = [], None
    try:
        for zone, port, upstream in zip(zones, BACKEND_PORTS, upstreams):
            # Fail before spawning if a private listener is already occupied.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(('127.0.0.1', port))
            child = subprocess.Popen([str(binary), '-udp', f'127.0.0.1:{port}', '-mtu', str(config['mtu']),
                                      '-privkey-file', str(key), zone, upstream])
            children.append(child)
            deadline = time.monotonic() + 8
            while True:
                if child.poll() is not None:
                    raise RuntimeError('A private DNSTT backend exited before readiness')
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                        probe.bind(('127.0.0.1', port))
                except OSError as exc:
                    if exc.errno != errno.EADDRINUSE:
                        raise
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('DNSTT backend did not open its private listener')
                time.sleep(.05)
        router = Router(('0.0.0.0', config['port']), routes)
        while all(child.poll() is None for child in children):
            router.step()
        raise RuntimeError('A DNSTT backend stopped; restarting both routes')
    finally:
        if router is not None:
            router.close()
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=3)
