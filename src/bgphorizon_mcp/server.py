"""Assemble the FastMCP server: register all tools, resources and prompts.

The server is intentionally thin. Each tool is an *analytical operation* (see
docs/mcp/SERVER-DESIGN.md), composing one or more ``/api/v1`` calls and annotating
the result with ``warnings`` so a connecting model cannot silently misread it.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .client import BGPHorizonClient
from .config import Settings
from .prompts import register_prompts
from .resources import register_resources
from .tools import register_tools

INSTRUCTIONS = """\
BGPHorizon exposes global BGP routing data: routing history, prefix/ASN \
analysis, RPKI/IRR/RDAP/PeeringDB, and routing-anomaly detections.

Two habits keep conclusions correct:
1. Persistence before narrative. A prefix seen on 2 of 60 days is transient, not a \
migration. Trust the server's `classification` and `origin_history`, never a bare \
`first_seen`.
2. Attribution before alarm. Check `concentration`/`single_vantage_point` warnings; \
a spike from one collector peer is a measurement artifact, not a routing event. Call \
`platform_baseline` before calling anything anomalous.

Every response includes `warnings[]` and `meta`. Read the warnings.

Writing anything up for a person: read `bgphorizon://reference/writing-guide` and \
`bgphorizon://reference/qa-checklist` BEFORE drafting, and follow them. They are \
short, and they are the difference between a report an operator trusts and one \
that reads as generated. For a full document use the `write_report` prompt, which \
carries the whole procedure and the report template.\
"""


def build_server(
    settings: Settings,
    *,
    host: str | None = None,
    port: int | None = None,
    stateless: bool = False,
) -> FastMCP:
    client = BGPHorizonClient(settings)

    mcp = FastMCP(
        name="bgphorizon",
        instructions=INSTRUCTIONS,
        host=host or "127.0.0.1",
        port=port or 8931,
        # Hosted HTTP is multi-tenant: each POST carries the caller's own bearer
        # key and is handled independently, so run stateless.
        stateless_http=stateless,
    )

    register_tools(mcp, client)
    register_resources(mcp, client)
    register_prompts(mcp)

    # Stash the client so the CLI can close it on shutdown / use it in selftest.
    mcp._bgphorizon_client = client  # type: ignore[attr-defined]
    return mcp


def run_http(mcp: FastMCP, settings: Settings) -> None:
    """Serve the streamable-HTTP transport behind the bearer-token gate.

    Same as ``mcp.run(transport="streamable-http")``, except that a request
    without a live token gets an HTTP 401 pointing at the OAuth metadata, which
    is how clients know to sign the user in. See ``auth.py``.
    """
    import uvicorn

    from .auth import BearerGate

    app = BearerGate(
        mcp.streamable_http_app(),
        api_url=settings.api_url,
        public_url=settings.public_url,
        mcp_path=mcp.settings.streamable_http_path,
    )
    uvicorn.run(
        app,
        host=mcp.settings.host,
        port=mcp.settings.port,
        log_level=mcp.settings.log_level.lower(),
    )
