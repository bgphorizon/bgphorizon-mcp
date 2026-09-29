"""Tests for the HTTP bearer-token gate (auth.py)."""

import asyncio
import json

import httpx
import pytest

from bgphorizon_mcp import auth
from bgphorizon_mcp.auth import BearerGate


async def _inner_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _call(gate, path="/mcp", method="POST", headers=None):
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "scheme": "http",
        "server": ("127.0.0.1", 8931),
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    asyncio.run(gate(scope, receive, send))
    start = sent[0]
    hdrs = {k.decode(): v.decode() for k, v in start["headers"]}
    return start["status"], hdrs, sent[1].get("body", b"")


@pytest.fixture
def tokeninfo(monkeypatch):
    """Route the gate's tokeninfo calls to a fake: bgps_good is live, all else 401."""
    calls = []

    def handler(request):
        calls.append(request)
        if request.headers.get("authorization") == "Bearer bgps_good":
            return httpx.Response(200, json={"active": True})
        return httpx.Response(401, json={"active": False})

    real = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(auth.httpx, "AsyncClient", fake_client)
    return calls


def test_missing_token_gets_challenge(tokeninfo):
    gate = BearerGate(_inner_app, api_url="http://api", public_url="https://bgphorizon.com")
    status, hdrs, body = _call(gate)
    assert status == 401
    assert hdrs["www-authenticate"] == (
        'Bearer resource_metadata="https://bgphorizon.com/.well-known/oauth-protected-resource/mcp"'
    )
    assert json.loads(body)["error"] == "unauthorized"
    assert tokeninfo == []  # no lookup without a token


def test_live_token_passes_and_is_cached(tokeninfo):
    gate = BearerGate(_inner_app, api_url="http://api", public_url="https://bgphorizon.com")
    for _ in range(3):
        status, _, body = _call(gate, headers={"Authorization": "Bearer bgps_good"})
        assert (status, body) == (200, b"ok")
    assert len(tokeninfo) == 1
    assert str(tokeninfo[0].url) == "http://api/oauth/tokeninfo"


def test_dead_token_gets_invalid_token(tokeninfo):
    gate = BearerGate(_inner_app, api_url="http://api", public_url="https://bgphorizon.com")
    status, hdrs, _ = _call(gate, headers={"Authorization": "Bearer bgps_expired"})
    assert status == 401
    assert 'error="invalid_token"' in hdrs["www-authenticate"]


def test_tokeninfo_unreachable_fails_open(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("down")

    real = httpx.AsyncClient
    monkeypatch.setattr(
        auth.httpx,
        "AsyncClient",
        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
    )
    gate = BearerGate(_inner_app, api_url="http://api")
    status, _, _ = _call(gate, headers={"Authorization": "Bearer bgps_any"})
    assert status == 200


def test_other_paths_and_preflight_pass_through(tokeninfo):
    gate = BearerGate(_inner_app, api_url="http://api")
    assert _call(gate, path="/health")[0] == 200
    assert _call(gate, path="/mcpx")[0] == 200  # prefix lookalike is not the MCP path
    assert _call(gate, method="OPTIONS")[0] == 200


def test_cache_is_bounded(tokeninfo, monkeypatch):
    monkeypatch.setattr(auth, "CACHE_MAX", 5)
    gate = BearerGate(_inner_app, api_url="http://api", public_url="https://bgphorizon.com")
    for i in range(20):
        _call(gate, headers={"Authorization": f"Bearer bgps_junk{i}"})
    assert len(gate._cache) <= 5


def test_origin_from_forwarded_headers(tokeninfo):
    gate = BearerGate(_inner_app, api_url="http://api")
    _, hdrs, _ = _call(gate, headers={"X-Forwarded-Proto": "https", "Host": "bgphorizon.com"})
    assert "https://bgphorizon.com/.well-known/oauth-protected-resource/mcp" in hdrs["www-authenticate"]
