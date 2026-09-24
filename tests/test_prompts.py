"""The prompts are the product: they carry the method and the house style into
a model that has never seen BGP data. A silent edit that drops a rule is not
visible until a report comes out wrong, so the load-bearing parts are pinned."""

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP

from bgphorizon_mcp.prompts import register_prompts


def render(name: str, args: dict) -> str:
    mcp = FastMCP("test")
    register_prompts(mcp)
    result = asyncio.run(mcp.get_prompt(name, args))
    return result.messages[0].content.text


def test_write_report_asks_before_investigating():
    """The caller decides whether to review findings before the report is built.

    The question has to survive verbatim, has to land before any tool call, and
    has to tell the model to stop. A model that asks and then answers itself has
    defeated the point.
    """
    text = render("write_report", {"entity": "AS54994", "window": "60d"})

    assert "This tool wants me to ask you the following question:" in text
    assert (
        "Would you like me to run all of my findings by you for confirmation and"
        in text
    )
    assert "STOP and wait for a reply" in text
    assert "Do not answer it yourself" in text

    # The gate must precede the procedure, or the model reads the steps first
    # and starts working.
    assert text.index("STEP 0") < text.index("Procedure")
    # Silence or ambiguity must not be read as permission to skip the review.
    assert "Anything other than a clear no means yes" in text


def test_write_report_review_loop_is_a_real_stop():
    text = render("write_report", {"entity": "AS54994", "window": "60d"})
    # Findings go to the caller before any report text exists.
    assert "BEFORE writing a line of the report" in text
    # And a caller correction is recorded, not quietly folded in.
    assert "carries\n  the correction" in text


@pytest.mark.parametrize(
    "name,args",
    [
        ("write_report", {"entity": "AS54994"}),
        ("alert_report", {"window": "24h"}),
        ("explain_incident", {"prefix": "203.0.113.0/24"}),
        ("audit_my_network", {"asn": "64500"}),
    ],
)
def test_report_prompts_carry_the_style_rules(name, args):
    """Every prompt that produces prose for a human must carry the house style,
    or a report reads as generated no matter how good the evidence is."""
    text = render(name, args)
    assert "Never use an em-dash" in text
    assert 'Never write "not X but Y"' in text
    assert "vary the length" in text
    assert "Answer, never narrate" in text


def test_guardrails_reach_every_investigative_prompt():
    for name, args in [
        ("investigate_entity", {"entity": "AS54994"}),
        ("triage_incident", {"prefix": "203.0.113.0/24"}),
        ("write_report", {"entity": "AS54994"}),
    ]:
        text = render(name, args)
        assert "PERSISTENCE" in text, name
        assert "ATTRIBUTION" in text, name


def test_server_instructions_point_at_the_report_standards():
    """Prompts only fire when a user explicitly invokes them. Someone who just
    types "write me a report on AS54994" never sees write_report, so the server
    instructions are the only place the standards reach them: those are sent to
    every client on connect."""
    from bgphorizon_mcp.server import INSTRUCTIONS

    assert "bgphorizon://reference/writing-guide" in INSTRUCTIONS
    assert "bgphorizon://reference/qa-checklist" in INSTRUCTIONS
    assert "write_report" in INSTRUCTIONS


def test_every_report_standard_is_served_as_a_resource():
    """A hosted user cannot clone the repo, so anything the report procedure
    references has to be fetchable over MCP."""
    from importlib import resources

    import bgphorizon_mcp.reference as ref

    shipped = {p.name for p in resources.files(ref).iterdir()}
    for required in (
        "writing_guide.md",
        "qa_checklist.md",
        "methodology.md",
        "examples.md",
        "report_template.html",
        "report.css",
    ):
        assert required in shipped, f"{required} is repo-only; hosted users cannot reach it"
