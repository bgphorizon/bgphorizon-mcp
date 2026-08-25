"""HTTP client for the BGPHorizon public ``/api/v1`` gateway.

The MCP server never talks to the internal ``bgp-api-go`` directly — it goes
through the same public, key-authenticated, metered, tier-gated surface that any
API user hits. That keeps the server thin and means quota/entitlement limits
surface here as structured errors the model can explain rather than retry blindly.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from .config import Settings


class APIError(RuntimeError):
    """A structured error from the API, phrased so an LLM can relay the cause."""

    def __init__(self, status: int, message: str, *, path: str = "") -> None:
        self.status = status
        self.message = message
        self.path = path
        super().__init__(self._render())

    def _render(self) -> str:
        if self.status == 401:
            return (
                "BGPHorizon API rejected the key (401). Set BGPHORIZON_API_KEY to a "
                "valid key from your account's API panel."
            )
        if self.status == 403:
            return f"Not permitted on your plan (403): {self.message}"
        if self.status == 429:
            return f"Rate limit reached (429): {self.message}"
        if self.status >= 500:
            return f"BGPHorizon API error ({self.status}) on {self.path}: {self.message}"
        return f"Request rejected ({self.status}) on {self.path}: {self.message}"


class BGPHorizonClient:
    """Thin, synchronous wrapper over ``/api/v1``.

    Methods mirror endpoints one-for-one; all analytical shaping (warnings,
    transitions, remediation, composition) lives in the tool layer, not here.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._http = httpx.Client(
            base_url=settings.api_base,
            headers={"Accept": "application/json", "User-Agent": "bgphorizon-mcp"},
            timeout=settings.timeout,
        )

    def _resolve_key(self) -> str | None:
        """The API key to use for this call.

        On the hosted HTTP transport each connecting user sends their own
        ``Authorization: Bearer bgps_...``; we read it per request so one shared
        server meters against the caller's key. On stdio there is no HTTP request,
        so we fall back to the ``BGPHORIZON_API_KEY`` the process was started with.
        """
        return incoming_bearer() or self._settings.api_key

    # -- low-level -----------------------------------------------------------

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "BGPHorizonClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _request(
        self, method: str, path: str, *, params: dict | None = None, json: Any = None
    ) -> Any:
        key = self._resolve_key()
        headers = {"Authorization": f"Bearer {key}"} if key else None
        try:
            resp = self._http.request(method, path, params=params, json=json, headers=headers)
        except httpx.RequestError as exc:  # network/DNS/timeout
            raise APIError(
                0,
                f"could not reach the API at {self._settings.api_base} ({exc})",
                path=path,
            ) from exc
        if resp.status_code >= 400:
            raise APIError(resp.status_code, _error_text(resp), path=path)
        if not resp.content:
            return {}
        return resp.json()

    def get(self, path: str, **params: Any) -> Any:
        return self._request("GET", path, params=_clean(params))

    def post(self, path: str, body: Any) -> Any:
        return self._request("POST", path, json=body)

    # -- endpoint helpers ----------------------------------------------------
    # ASN / prefix routing data

    def asn_overview(self, asn: int | str, **p: Any) -> Any:
        return self.get("/asn/overview", asn=asn, **p)

    def asn_prefixes(self, asn: int | str, **p: Any) -> Any:
        return self.get("/asn/prefixes", asn=asn, **p)

    def asn_events(self, asn: int | str, **p: Any) -> Any:
        return self.get("/asn/events", asn=asn, **p)

    def asn_relationships(self, asn: int | str, **p: Any) -> Any:
        return self.get("/asn/relationships", asn=asn, **p)

    def asn_propagation(self, asn: int | str, **p: Any) -> Any:
        return self.get("/asn/propagation", asn=asn, **p)

    def communities_translate(self, communities: str, **p: Any) -> Any:
        return self.get("/communities/translate", communities=communities, **p)

    def prefix_overview(self, prefix: str, **p: Any) -> Any:
        return self.get("/prefix/overview", prefix=prefix, **p)

    def prefix_events(self, prefix: str, **p: Any) -> Any:
        return self.get("/prefix/events", prefix=prefix, **p)

    def prefix_subprefixes(self, prefix: str, **p: Any) -> Any:
        return self.get("/prefix/subprefixes", prefix=prefix, **p)

    def prefix_hierarchy(self, prefix: str) -> Any:
        return self.get("/prefix/hierarchy", prefix=prefix)

    # Analytical primitives

    def timeseries(self, target: str, **p: Any) -> Any:
        return self.get("/timeseries", target=target, **p)

    def presence(self, **p: Any) -> Any:
        return self.get("/presence", **p)

    def reachability(self, prefix: str, **p: Any) -> Any:
        return self.get("/prefix/reachability", prefix=prefix, **p)

    def registry_bulk(self, body: dict) -> Any:
        return self.post("/registry/bulk", body)

    # Registry references

    def rpki_prefix(self, prefix: str, **p: Any) -> Any:
        return self.get("/rpki/prefix", prefix=prefix, **p)

    def rpki_asn(self, asn: int | str, **p: Any) -> Any:
        return self.get("/rpki/asn", asn=asn, **p)

    def irr_prefix(self, prefix: str, **p: Any) -> Any:
        return self.get("/irr/prefix", prefix=prefix, **p)

    def irr_asn(self, asn: int | str, **p: Any) -> Any:
        return self.get("/irr/asn", asn=asn, **p)

    def rdap_prefix(self, prefix: str) -> Any:
        return self.get("/rdap/prefix", prefix=prefix)

    def rdap_asn(self, asn: int | str) -> Any:
        return self.get("/rdap/asn", asn=asn)

    def peeringdb_asn(self, asn: int | str) -> Any:
        return self.get("/peeringdb/asn", asn=asn)

    # Detections

    def detections_search(self, **p: Any) -> Any:
        return self.get("/detections/search", **p)

    def detections_asn(self, asn: int | str, **p: Any) -> Any:
        return self.get("/detections/asn", asn=asn, **p)

    def detections_prefix(self, prefix: str, **p: Any) -> Any:
        return self.get("/detections/prefix", prefix=prefix, **p)

    # Composed

    def entity_profile(self, **p: Any) -> Any:
        return self.get("/entity/profile", **p)

    def ip_lookup(self, ips: list[str], days_back: int = 7) -> Any:
        return self.post("/ip/lookup", {"ips": ips, "days_back": days_back})

    def health(self) -> Any:
        # /health lives outside /api/v1's key group; hit it on the bare origin.
        url = self._settings.api_url.rstrip("/") + "/api/v1/health"
        resp = self._http.get(url)
        resp.raise_for_status()
        return resp.json() if resp.content else {}


def incoming_bearer() -> str | None:
    """Extract the caller's bearer token from the active MCP HTTP request, if any.

    On the streamable-HTTP transport the low-level server binds the current
    request into a contextvar around each tool call, and ``RequestContext.request``
    is the Starlette request. anyio copies the context into the tool threadpool, so
    this is visible from a synchronous tool. On stdio there is no request, so this
    returns None and the process-level env key is used instead.
    """
    try:
        from mcp.server.lowlevel.server import request_ctx

        rc = request_ctx.get()
    except (ImportError, LookupError):
        return None
    req = getattr(rc, "request", None)
    headers = getattr(req, "headers", None)
    if not headers:
        return None
    auth = headers.get("authorization") or headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _clean(params: dict) -> dict:
    """Drop None values so we don't send empty query params."""
    return {k: v for k, v in params.items() if v is not None}


def _error_text(resp: httpx.Response) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict) and "error" in data:
            return str(data["error"])
        return str(data)
    except Exception:
        return resp.text[:300] or resp.reason_phrase


def encode_prefix(prefix: str) -> str:
    """CIDR → path-safe (callers using query params don't need this; kept for
    any future path-style routes)."""
    return quote(prefix, safe="")
