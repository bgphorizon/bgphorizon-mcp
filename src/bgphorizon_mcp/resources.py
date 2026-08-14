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
        description="The house HTML report skeleton, with the real house CSS already "
        "inlined — use it as-is, do not write substitute styles.",
        mime_type="text/html",
    )
    def report_template() -> str:
        # Inline the real stylesheet so a model using only this resource gets the
        # house look, instead of inventing CSS from the empty <style> block.
        html = _read("report_template.html")
        css = _read("report.css")
        return html.replace(
            "/* ---- inline the contents of template-assets/report.css here ---- */", css
        )

    @mcp.resource(
        "bgphorizon://reference/writing-guide",
        name="Report writing guide",
        description="House voice rules and the explicit 'avoid' table (em-dash density, "
        "'not X but Y', observation-vs-inference, correction blocks). Read before writing.",
        mime_type="text/markdown",
    )
    def writing_guide() -> str:
        return _read("writing_guide.md")

    @mcp.resource(
        "bgphorizon://reference/qa-checklist",
        name="Report QA checklist",
        description="The pre-publication pass every report must clear (claims trace to "
        "evidence, colour semantics, no unverified pattern-matching, live-badge accuracy).",
        mime_type="text/markdown",
    )
    def qa_checklist() -> str:
        return _read("qa_checklist.md")

    @mcp.resource(
        "bgphorizon://reference/methodology",
        name="Report methodology",
        description="The investigation procedure — evidence order and the checks that "
        "keep conclusions defensible.",
        mime_type="text/markdown",
    )
    def methodology() -> str:
        return _read("methodology.md")
