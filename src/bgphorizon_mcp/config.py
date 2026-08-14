"""Configuration for the BGPHorizon MCP server.

Everything is driven by environment variables so the server drops cleanly into
any MCP client's ``env`` block:

- ``BGPHORIZON_API_KEY``  — required; forwarded as ``Authorization: Bearer`` to
  the public ``/api/v1`` gateway (inherits metering + tier entitlements).
- ``BGPHORIZON_API_URL``  — base URL of the BGPHorizon site (default production).
- ``BGPHORIZON_LOG_LEVEL`` — DEBUG | INFO | WARNING | ERROR (default INFO).
- ``BGPHORIZON_TIMEOUT``  — per-request timeout in seconds (default 30).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_API_URL = "https://bgphorizon.com"


@dataclass(frozen=True)
class Settings:
    api_key: str | None
    api_url: str
    timeout: float
    log_level: str

    @property
    def api_base(self) -> str:
        """Base URL of the versioned API surface, e.g. ``https://.../api/v1``."""
        return self.api_url.rstrip("/") + "/api/v1"


def load_settings(
    *,
    api_url: str | None = None,
    api_key: str | None = None,
) -> Settings:
    """Build settings from the environment, with optional explicit overrides
    (used by CLI flags such as ``--api-url``)."""
    resolved_url = (
        api_url
        or os.environ.get("BGPHORIZON_API_URL")
        or DEFAULT_API_URL
    )
    timeout_raw = os.environ.get("BGPHORIZON_TIMEOUT", "30")
    try:
        timeout = float(timeout_raw)
    except ValueError:
        timeout = 30.0
    return Settings(
        api_key=api_key or os.environ.get("BGPHORIZON_API_KEY"),
        api_url=resolved_url,
        timeout=timeout,
        log_level=os.environ.get("BGPHORIZON_LOG_LEVEL", "INFO").upper(),
    )
