"""Certificate trust and explicit proxies over real loopback HTTPS peers."""

from __future__ import annotations

import inspect
import ssl
import time
import traceback
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpcore
import httpx
import pytest
from pydantic import SecretStr

from proofline import AsyncProoflineClient, ProoflineClient, ProoflineError, _sync_http

from .fixtures import ORG, REPOSITORY, TOKEN
from .http_server import Reply, Request, Server, TunnelProxy

Client = ProoflineClient | AsyncProoflineClient
MODES = pytest.mark.parametrize("mode", ["sync", "async"])
TLS = Path(__file__).resolve().parent / "fixtures" / "tls"


def server_tls() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS / "server.pem", TLS / "server.key")
    return context


def private_ca() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=TLS / "ca.pem")


def repositories(request: Request, index: int) -> Reply:
    return Reply(body={"repositories": [{"id": str(REPOSITORY), "full_name": "repo/name"}]})


@asynccontextmanager
async def session(mode: str, url: str, **kwargs: Any) -> AsyncIterator[Client]:
    if mode == "sync":
        with ProoflineClient(SecretStr(TOKEN), base_url=url, **kwargs) as client:
            yield client
    else:
        async with AsyncProoflineClient(SecretStr(TOKEN), base_url=url, **kwargs) as async_client:
            yield async_client


async def call(client: Client, name: str, *args: Any, **kwargs: Any) -> Any:
    result = getattr(client, name)(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


@MODES
async def test_both_clients_share_the_default_certificate_trust(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    with Server(repositories, tls=server_tls()) as server:
        async with session(mode, server.url) as client:
            with pytest.raises(ProoflineError) as raised:
                await call(client, "list_repositories", ORG)
            assert raised.value.status == 0
            assert raised.value.type == "urn:proofline:sdk:transport-unavailable"
        # Stands in for a private CA in OpenSSL's default locations, for example one added
        # with update-ca-certificates. The async client used to trust certifi alone.
        monkeypatch.setattr(httpcore, "default_ssl_context", private_ca)
        async with session(mode, server.url) as client:
            result = await call(client, "list_repositories", ORG)
            assert [item.full_name for item in result.repositories] == ["repo/name"]
        assert len(server.requests) == 1
        assert server.requests[0].headers["Authorization"] == f"Bearer {TOKEN}"


def test_sync_transport_tunnels_https_and_maps_a_refused_connect() -> None:
    with Server(repositories, tls=server_tls()) as server, TunnelProxy() as proxy:
        port = server.url.rsplit(":", 1)[1]
        transport = _sync_http.Transport(proxy=httpx.Proxy(proxy.url), ssl_context=private_ca())
        with httpx.Client(transport=transport) as client:
            response = client.get(f"{server.url}/names", headers={"Authorization": "Bearer t"})
            assert response.json()["repositories"][0]["full_name"] == "repo/name"
        assert [(item.method, item.target) for item in proxy.requests] == [
            ("CONNECT", f"127.0.0.1:{port}")
        ]
        assert "Authorization" not in proxy.requests[0].headers
        assert server.requests[0].headers["Authorization"] == "Bearer t"
    with TunnelProxy(407) as proxy:
        with httpx.Client(transport=_sync_http.Transport(proxy=httpx.Proxy(proxy.url))) as client:
            with pytest.raises(httpx.ProxyError):
                client.get("https://127.0.0.1:9/names")
        assert [item.method for item in proxy.requests] == ["CONNECT"]


@MODES
async def test_both_clients_tunnel_to_a_private_ca_origin_through_an_explicit_proxy(
    mode: str,
) -> None:
    with Server(repositories, tls=server_tls()) as server, TunnelProxy() as proxy:
        port = server.url.rsplit(":", 1)[1]
        async with session(mode, server.url, proxy=proxy.url, ssl_context=private_ca()) as client:
            result = await call(client, "list_repositories", ORG)
            assert [item.full_name for item in result.repositories] == ["repo/name"]
        assert [(item.method, item.target) for item in proxy.requests] == [
            ("CONNECT", f"127.0.0.1:{port}")
        ]
        # The token travels inside TLS to the origin, never in the CONNECT request.
        assert "Authorization" not in proxy.requests[0].headers
        assert server.requests[0].headers["Authorization"] == f"Bearer {TOKEN}"
        async with session(mode, server.url, proxy=proxy.url) as client:
            with pytest.raises(ProoflineError) as raised:
                await call(client, "list_repositories", ORG)
            assert raised.value.status == 0
            assert raised.value.type == "urn:proofline:sdk:transport-unavailable"
        # The tunnel opened; the default trust refused the private CA inside it.
        assert len(proxy.requests) == 2
        assert len(server.requests) == 1


@MODES
async def test_an_https_proxy_is_verified_with_the_same_context(mode: str) -> None:
    with (
        Server(repositories, tls=server_tls()) as server,
        TunnelProxy(tls=server_tls()) as proxy,
    ):
        assert proxy.url.startswith("https://")
        async with session(mode, server.url, proxy=proxy.url, ssl_context=private_ca()) as client:
            result = await call(client, "list_repositories", ORG)
            assert [item.full_name for item in result.repositories] == ["repo/name"]
        assert [item.method for item in proxy.requests] == ["CONNECT"]
        async with session(mode, server.url, proxy=proxy.url) as client:
            with pytest.raises(ProoflineError) as raised:
                await call(client, "list_repositories", ORG)
            assert raised.value.type == "urn:proofline:sdk:transport-unavailable"
        assert len(proxy.requests) == 1
        assert len(server.requests) == 1


@MODES
async def test_proxy_variables_in_the_environment_are_ignored(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with Server(repositories, tls=server_tls()) as server, TunnelProxy() as proxy:
        for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
            monkeypatch.setenv(name, proxy.url)
            monkeypatch.setenv(name.lower(), proxy.url)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        async with session(mode, server.url, ssl_context=private_ca()) as client:
            await call(client, "list_repositories", ORG)
        assert proxy.requests == []
        assert len(server.requests) == 1


@MODES
async def test_proxy_credentials_reach_only_the_proxy_and_a_refusal_hides_them(
    mode: str,
) -> None:
    with Server(repositories, tls=server_tls()) as server, TunnelProxy() as proxy:
        credentialed = proxy.url.replace("http://", "http://user:secret@")
        async with session(
            mode, server.url, proxy=credentialed, ssl_context=private_ca()
        ) as client:
            await call(client, "list_repositories", ORG)
        assert proxy.requests[0].headers["Proxy-Authorization"] == "Basic dXNlcjpzZWNyZXQ="
        assert "Proxy-Authorization" not in server.requests[0].headers
    with TunnelProxy(407) as proxy:
        credentialed = proxy.url.replace("http://", "http://user:secret@")
        async with session(mode, "https://127.0.0.1:9", proxy=credentialed) as client:
            with pytest.raises(ProoflineError) as raised:
                await call(client, "list_repositories", ORG)
        error = raised.value
        assert error.status == 0
        assert error.type == "urn:proofline:sdk:transport-unavailable"
        shown = [str(error), repr(error), error.detail, "".join(traceback.format_exception(error))]
        assert not any("secret" in text for text in shown)
        assert len(proxy.requests) == 1


@MODES
async def test_a_silent_proxy_stops_at_the_request_deadline(mode: str) -> None:
    with TunnelProxy(answer=False) as proxy:
        async with session(mode, "https://127.0.0.1:9", proxy=proxy.url, timeout=0.5) as client:
            started = time.monotonic()
            with pytest.raises(ProoflineError) as raised:
                await call(client, "list_repositories", ORG)
            assert raised.value.type == "urn:proofline:sdk:timeout"
            assert time.monotonic() - started < 2
        assert [item.method for item in proxy.requests] == ["CONNECT"]


@MODES
async def test_retry_after_still_applies_through_a_proxy(mode: str) -> None:
    def respond(request: Request, index: int) -> Reply:
        if index == 0:
            return Reply(503, {"detail": "Provider unavailable."}, {"Retry-After": "0"})
        return repositories(request, index)

    with Server(respond, tls=server_tls()) as server, TunnelProxy() as proxy:
        async with session(mode, server.url, proxy=proxy.url, ssl_context=private_ca()) as client:
            result = await call(client, "list_repositories", ORG)
            assert [item.full_name for item in result.repositories] == ["repo/name"]
        assert len(server.requests) == 2
        assert {item.method for item in proxy.requests} == {"CONNECT"}


def test_proxy_and_ssl_context_values_are_checked_before_any_connection() -> None:
    for value in [
        "socks5://127.0.0.1:1080",
        "ftp://proxy.example:3128",
        "proxy.example:3128",
        "http://:3128",
        "http://proxy.example:3128/path",
        "http://proxy.example:3128?token=secret",
        "http://proxy.example:3128#secret",
        "http://proxy.example:99999",
        " http://proxy.example:3128",
        "http://user:secret@proxy.example:3128/path",
    ]:
        for client_type in (ProoflineClient, AsyncProoflineClient):
            with pytest.raises(ValueError) as raised:
                client_type(TOKEN, proxy=value)
            assert "secret" not in str(raised.value)
    with pytest.raises(ValueError):
        ProoflineClient(TOKEN, base_url="http://127.0.0.1:8080", proxy="http://proxy.example")
    with pytest.raises(TypeError):
        ProoflineClient(TOKEN, proxy=b"http://proxy.example:3128")  # type: ignore[arg-type]
    no_hostname = ssl.create_default_context()
    no_hostname.check_hostname = False
    no_verification = ssl.create_default_context()
    no_verification.check_hostname = False
    no_verification.verify_mode = ssl.CERT_NONE
    optional = ssl.create_default_context()
    optional.verify_mode = ssl.CERT_OPTIONAL
    for context in (no_hostname, no_verification, optional):
        for client_type in (ProoflineClient, AsyncProoflineClient):
            with pytest.raises(ValueError):
                client_type(TOKEN, ssl_context=context)
    with pytest.raises(TypeError):
        ProoflineClient(TOKEN, ssl_context="ca.pem")  # type: ignore[arg-type]
    for value in ["http://proxy.example:3128", "https://[::1]:3128/", "http://u:p%40ss@proxy"]:
        with ProoflineClient(TOKEN, proxy=value, ssl_context=private_ca()):
            pass
