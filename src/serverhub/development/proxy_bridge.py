"""Executed inside bwrap using system Python only; no ServerHub imports/secrets."""
import os
import selectors
import socket
import socketserver
import subprocess
import sys
import threading


class Bridge(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
            try:
                upstream.connect('/run/serverhub-egress.sock')
                with selectors.DefaultSelector() as selector:
                    selector.register(self.request, selectors.EVENT_READ, upstream)
                    selector.register(upstream, selectors.EVENT_READ, self.request)
                    while True:
                        for event, _ in selector.select(1):
                            data = event.fileobj.recv(65536)
                            if not data:
                                return
                            event.data.sendall(data)
            except OSError:
                return


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 8


if __name__ == '__main__':
    with Server(('127.0.0.1', 0), Bridge) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        proxy = 'http://127.0.0.1:' + str(server.server_address[1])
        env = dict(os.environ)
        env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, ALL_PROXY=proxy,
                   http_proxy=proxy, https_proxy=proxy, all_proxy=proxy, NO_PROXY='', no_proxy='')
        try:
            result = subprocess.run(sys.argv[1:], env=env)
        finally:
            server.shutdown()
        sys.exit(result.returncode if result.returncode >= 0 else 128-result.returncode)
