"""Read-only reference resources (5).

Reference data belongs in resources, not in every model's system prompt — a
connecting model can pull these without spending a tool call. Content is bundled
as package data so the server stays self-contained when forked.
"""

from __future__ import annotations

from importlib import resources

from mcp.server.fastmcp import FastMCP

from .client import BGPHorizonClient

_PKG = "bgphorizon_mcp.reference"


def _read(name: str) -> str:
    return resources.files(_PKG).joinpath(name).read_text(encoding="utf-8")


def register_resources(mcp: FastMCP, client: BGPHorizonClient) -> None:

    @mcp.resource(
        "bgphorizon://reference/detection-types",
        name="Detection types",
        description="Every detection type, its severity split, and how to read actor_as vs baseline_asns.",
        mime_type="text/markdown",
    )
    def detection_types() -> str:
        return _read("detection_types.md")

    @mcp.resource(
        "bgphorizon://reference/collectors",
        name="Route collectors",
        description="RouteViews / RIPE RIS collector inventory and how to use concentration metadata.",
        mime_type="text/markdown",
    )
    def collectors() -> str:
        return _read("collectors.md")

    @mcp.resource(
        "bgphorizon://reference/glossary",
        name="BGP glossary",
        description="BGP terms in plain language, reusable directly in report output.",
        mime_type="text/markdown",
    )
    def glossary() -> str:
        return _read("glossary.md")

    @mcp.resource(
        "bgphorizon://reference/data-horizon",
        name="Data horizon & caveats",
        description="Retention floor, rollup vs raw_events, and the first_seen trap.",
        mime_type="text/markdown",
    )
    def data_horizon() -> str:
        return _read("data_horizon.md")

    @mcp.resource(
        "bgphorizon://reference/report-template",
        name="Report template",
        description="The house HTML report skeleton used by the write_report prompt.",
        mime_type="text/html",
    )
    def report_template() -> str:
        return _read("report_template.html")
