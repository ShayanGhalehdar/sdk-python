"""Real loopback HTTP peers and a CONNECT proxy for the generated sync and async clients."""

from __future__ import annotations

import json
import select
import socket
import ssl
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Self


@dataclass
class Request:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    peer_port: int


@dataclass
class Reply:
    status: int = 200
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    split: int | None = None
    pause: float = 0
    chunk_size: int | None = None
    header_pause: float = 0
    first_pause: float = 0


class Server(AbstractContextManager["Server"]):
    def __init__(
        self, respond: Callable[[Request, int], Reply], tls: ssl.SSLContext | None = None
    ) -> None:
        self.requests: list[Request] = []
        self._lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                self.dispatch()

            def do_POST(self) -> None:
                self.dispatch()

            def dispatch(self) -> None:
                request = Request(
                    self.command,
                    self.path,
                    dict(self.headers),
                    self.rfile.read(int(self.headers.get("Content-Length", 0))),
                    self.client_address[1],
                )
                with owner._lock:
                    owner.requests.append(request)
                    index = len(owner.requests) - 1
                reply = respond(request, index)
                payload = (
                    reply.body if isinstance(reply.body, bytes) else json.dumps(reply.body).encode()
                )
                time.sleep(reply.header_pause)
                self.send_response(reply.status)
                if "Content-Type" not in reply.headers:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                for key, value in reply.headers.items():
                    self.send_header(key, value)
                self.end_headers()
                try:
                    time.sleep(reply.first_pause)
                    if reply.chunk_size:
                        for start in range(0, len(payload), reply.chunk_size):
                            self.wfile.write(payload[start : start + reply.chunk_size])
                            self.wfile.flush()
                            time.sleep(reply.pause)
                    else:
                        split = len(payload) if reply.split is None else reply.split
                        self.wfile.write(payload[:split])
                        self.wfile.flush()
                        time.sleep(reply.pause)
                        self.wfile.write(payload[split:])
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        if tls is not None:
            self._server.socket = tls.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        scheme = "http" if tls is None else "https"
        self.url = f"{scheme}://127.0.0.1:{self._server.server_port}"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


@dataclass
class ProxyRequest:
    method: str
    target: str
    headers: dict[str, str]


class TunnelProxy(AbstractContextManager["TunnelProxy"]):
    """A loopback CONNECT proxy that records each request head and pipes the tunnel.

    A status other than 200 refuses every request with that status, and
    answer=False reads the request and never replies. With tls, clients reach the
    proxy itself over TLS.
    """

    def __init__(
        self, status: int = 200, *, answer: bool = True, tls: ssl.SSLContext | None = None
    ) -> None:
        self.requests: list[ProxyRequest] = []
        self._status = status
        self._answer = answer
        self._tls = tls
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._peers: list[socket.socket] = []
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.01)
        self._thread = threading.Thread(target=self._accept, daemon=True)
        scheme = "http" if tls is None else "https"
        self.url = f"{scheme}://127.0.0.1:{self._listener.getsockname()[1]}"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._stopped.set()
        self._thread.join(timeout=2)
        self._listener.close()
        with self._lock:
            for peer in self._peers:
                peer.close()

    def _accept(self) -> None:
        while not self._stopped.is_set():
            try:
                peer, _ = self._listener.accept()
            except TimeoutError:
                continue
            peer.settimeout(None)
            threading.Thread(target=self._serve, args=(peer,), daemon=True).start()

    def _track(self, peer: socket.socket) -> socket.socket:
        with self._lock:
            self._peers.append(peer)
        return peer

    def _serve(self, peer: socket.socket) -> None:
        client = peer
        upstream: socket.socket | None = None
        try:
            if self._tls is not None:
                client = self._tls.wrap_socket(peer, server_side=True)
            self._track(client)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(65536)
                if not chunk:
                    return
                head += chunk
            head, rest = head.split(b"\r\n\r\n", 1)
            line, *fields = head.decode("latin-1").split("\r\n")
            method, target, _ = line.split(" ", 2)
            headers = dict(item.split(": ", 1) for item in fields)
            with self._lock:
                self.requests.append(ProxyRequest(method, target, headers))
            if not self._answer:
                self._stopped.wait()
                return
            status = self._status if method == "CONNECT" else 405
            if status != 200:
                reason = HTTPStatus(status).phrase
                client.sendall(
                    f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n"
                    f"Connection: close\r\n\r\n".encode()
                )
                return
            host, port = target.rsplit(":", 1)
            upstream = self._track(socket.create_connection((host, int(port)), timeout=2))
            upstream.settimeout(None)
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
            self._pipe(client, upstream)
        except OSError:
            pass
        finally:
            client.close()
            if upstream is not None:
                upstream.close()

    def _pipe(self, client: socket.socket, upstream: socket.socket) -> None:
        peers = {client: upstream, upstream: client}
        while not self._stopped.is_set():
            # TLS can hold decrypted bytes that select does not report.
            ready = [item for item in peers if isinstance(item, ssl.SSLSocket) and item.pending()]
            if not ready:
                ready, _, _ = select.select(list(peers), [], [], 0.05)
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                peers[source].sendall(data)
