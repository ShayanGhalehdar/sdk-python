"""Certificate trust and explicit proxies over real loopback HTTPS peers."""

from __future__ import annotations

import inspect
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpcore
import pytest
from pydantic import SecretStr

from proofline import AsyncProoflineClient, ProoflineClient, ProoflineError

from .fixtures import ORG, REPOSITORY, TOKEN
from .http_server import Reply, Request, Server

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
