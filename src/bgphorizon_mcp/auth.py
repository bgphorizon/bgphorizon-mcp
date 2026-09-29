"""Bearer-token gate for the hosted HTTP transport.

The hosted endpoint is an OAuth 2.1 protected resource (MCP authorization spec).
A request to the MCP path without a live token gets a plain HTTP 401 with a
``WWW-Authenticate`` header pointing at the protected-resource metadata. That
401 is what tells a client such as Claude Desktop or claude.ai to start the
sign-in flow, which BGPHorizon's web app runs as the authorization server.

Tokens are ordinary ``bgps_`` API keys, whether a user pasted one into a config
file or the OAuth flow issued it, so both kinds of client keep working. The gate
asks the web app whether a token is live (``/oauth/tokeninfo``) and caches the
answer briefly. If the web app cannot be reached it lets the request through:
the API checks the key again on every call, so failing open only changes where
the error appears, and an outage never pushes every user back through sign-in.

stdio is unaffected. The gate only wraps the HTTP app.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time

import httpx

log = logging.getLogger("bgphorizon-mcp.auth")

METADATA_PATH = "/.well-known/oauth-protected-resource"

# Upper bound on cached token answers, so a flood of junk tokens cannot grow
# memory without limit.
CACHE_MAX = 10_000


class BearerGate:
    """ASGI middleware that answers 401 for missing or dead bearer tokens."""

    def __init__(
        self,
        app,
        *,
        api_url: str,
        public_url: str | None = None,
        mcp_path: str = "/mcp",
        cache_seconds: float = 60.0,
        timeout: float = 5.0,
    ) -> None:
        self.app = app
        self.tokeninfo_url = api_url.rstrip("/") + "/oauth/tokeninfo"
        self.public_url = public_url.rstrip("/") if public_url else None
        self.mcp_path = mcp_path.rstrip("/") or "/"
        self.cache_seconds = cache_seconds
        self.timeout = timeout
        self._cache: dict[str, tuple[float, bool]] = {}

    async def __call__(self, scope, receive, send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") == "OPTIONS"
            or not _under(scope.get("path", ""), self.mcp_path)
        ):
            await self.app(scope, receive, send)
            return

        headers = _headers(scope)
        token = _bearer(headers.get("authorization", ""))
        if token is None:
            await self._challenge(scope, send, headers, error=None)
            return
        if not await self._is_live(token):
            await self._challenge(scope, send, headers, error="invalid_token")
            return
        await self.app(scope, receive, send)

    async def _is_live(self, token: str) -> bool:
        key = hashlib.sha256(token.encode()).hexdigest()
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit and hit[0] > now:
            return hit[1]

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    self.tokeninfo_url, headers={"Authorization": f"Bearer {token}"}
                )
        except httpx.HTTPError as exc:
            log.warning("tokeninfo unreachable, letting request through: %s", exc)
            return True

        if resp.status_code == 200:
            live = True
        elif resp.status_code == 401:
            live = False
        else:
            log.warning("tokeninfo returned %s, letting request through", resp.status_code)
            return True

        if len(self._cache) >= CACHE_MAX:
            self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
            if len(self._cache) >= CACHE_MAX:
                # Still full of unexpired entries: someone is sending many
                # distinct tokens. Start over rather than grow without bound;
                # the cost is one extra tokeninfo call per live token.
                self._cache.clear()
        self._cache[key] = (now + self.cache_seconds, live)
        return live

    def _metadata_url(self, scope, headers: dict[str, str]) -> str:
        base = self.public_url or _origin(scope, headers)
        return base + METADATA_PATH + self.mcp_path

    async def _challenge(self, scope, send, headers: dict[str, str], *, error: str | None) -> None:
        challenge = f'Bearer resource_metadata="{self._metadata_url(scope, headers)}"'
        if error:
            challenge += f', error="{error}"'
        message = (
            "Sign in to BGPHorizon to use this server, or send an API key as "
            "'Authorization: Bearer bgps_...'."
            if error is None
            else "The token is invalid, expired or revoked. Sign in again."
        )
        body = json.dumps({"error": error or "unauthorized", "error_description": message}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", challenge.encode()),
                    (b"access-control-expose-headers", b"WWW-Authenticate"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _headers(scope) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}


def _bearer(value: str) -> str | None:
    if value[:7].lower() != "bearer ":
        return None
    token = value[7:].strip()
    return token or None


def _origin(scope, headers: dict[str, str]) -> str:
    """Public origin of the request, as the client saw it (behind nginx)."""
    proto = headers.get("x-forwarded-proto") or scope.get("scheme", "http")
    host = headers.get("x-forwarded-host") or headers.get("host")
    if not host:
        server = scope.get("server") or ("localhost", 80)
        host = f"{server[0]}:{server[1]}"
    return f"{proto.split(',')[0].strip()}://{host.split(',')[0].strip()}"
