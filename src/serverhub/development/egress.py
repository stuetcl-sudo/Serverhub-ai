"""Unprivileged per-command CONNECT gateway: public allowlisted HTTPS only.

Repository code stays in its private network namespace. It reaches this gateway
through one private Unix socket, never the worker's host TCP/network namespace.
DNS answers are checked and pinned before connect; no shell, firewall or root API.
"""
from contextlib import contextmanager
import ipaddress
import os
from pathlib import Path
import selectors
import socket
import socketserver
import struct
import threading
import time


class EgressDenied(ValueError):
    pass


def destination(authority, allowed_hosts, local_networks=()):
    host, separator, port = authority.rpartition(':')
    host = host.lower()
    if separator != ':' or port != '443' or host not in allowed_hosts:
        raise EgressDenied('HTTPS destination is outside the registered host allowlist')
    records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    addresses = []
    for family, kind, protocol, _, address in records:
        ip = ipaddress.ip_address(address[0])
        if (not ip.is_global or ip.is_multicast or ip.is_unspecified or getattr(ip, 'ipv4_mapped', None)
                or getattr(ip, 'sixtofour', None) or getattr(ip, 'teredo', None)
                or (ip.version == 6 and ip in ipaddress.ip_network('64:ff9b::/96'))
                or any(ip.version == network.version and ip in network for network in local_networks)):
            raise EgressDenied('Private, loopback, reserved and mixed DNS destinations are denied')
        # Restrict the gateway transport to IPv4. Public AAAA records are still
        # validated, but never dialed: custom NAT64/IPv4 transition prefixes must
        # not turn an apparently global IPv6 address into a private IPv4 target.
        if family == socket.AF_INET:
            addresses.append((family, kind, protocol, address))
    if not addresses:
        raise EgressDenied('Destination has no approved public IPv4 transport')
    return addresses


class Gateway(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, address)

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        try:
            _, uid, _ = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != self.server.uid:
                raise EgressDenied('Peer identity denied')
            self.request.settimeout(10)
            header = b''
            while b'\r\n\r\n' not in header and len(header) <= 16384:
                chunk = self.request.recv(1)
                if not chunk:
                    return
                header += chunk
            if len(header) > 16384:
                raise EgressDenied('Proxy header exceeds limit')
            method, authority, version = header.split(b'\r\n',1)[0].decode('ascii').split(' ')
            if method != 'CONNECT' or version not in {'HTTP/1.0','HTTP/1.1'}:
                raise EgressDenied('Only HTTPS CONNECT is supported')
            addresses = destination(authority, self.server.allowed_hosts, self.server.local_networks)
            for family, kind, protocol, address in addresses:
                if self.server.stopped.is_set() or time.monotonic() >= self.server.deadline:
                    break
                candidate = socket.socket(family, kind, protocol)
                candidate.settimeout(10)
                try:
                    candidate.connect(address)  # pin validated IP: never resolve again
                    upstream = candidate
                    break
                except OSError:
                    candidate.close()
            if upstream is None:
                raise EgressDenied('Public endpoint unavailable')
            self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            with selectors.DefaultSelector() as selector:
                for stream, other in ((self.request, upstream),(upstream,self.request)):
                    stream.settimeout(10)
                    selector.register(stream, selectors.EVENT_READ, other)
                while not self.server.stopped.is_set() and time.monotonic() < self.server.deadline:
                    for event, _ in selector.select(.5):
                        data = event.fileobj.recv(65536)
                        if not data:
                            return
                        with self.server.byte_lock:
                            self.server.remaining -= len(data)
                            if self.server.remaining < 0:
                                raise EgressDenied('Dependency transfer byte budget exceeded')
                        event.data.sendall(data)
        except (ValueError, OSError, UnicodeError):
            if upstream is None:
                try:
                    self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                except OSError:
                    pass
        finally:
            if upstream is not None:
                upstream.close()


@contextmanager
def gateway(directory: Path, project, timeout):
    path = directory / 'egress.sock'
    with Gateway(str(path), Handler) as server:
        os.chmod(path, 0o600)
        import psutil
        networks = []
        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                if address.family in {socket.AF_INET, socket.AF_INET6}:
                    ip = ipaddress.ip_address(address.address.split('%')[0])
                    mask = address.netmask
                    prefix = ip.max_prefixlen if not mask else bin(int(ipaddress.ip_address(mask.split('%')[0]))).count('1')
                    networks.append(ipaddress.ip_network(f'{ip}/{prefix}', strict=False))
        server.local_networks = networks
        server.uid = os.geteuid()
        server.allowed_hosts = set(project.dependency_hosts)
        server.remaining = project.max_dependency_bytes
        server.byte_lock = threading.Lock()
        server.slots = threading.BoundedSemaphore(8)
        server.stopped = threading.Event()
        server.deadline = time.monotonic() + timeout
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.1), daemon=True)
        thread.start()
        try:
            yield path
        finally:
            server.stopped.set()
            server.shutdown()
            thread.join(timeout=2)
