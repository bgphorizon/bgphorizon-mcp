"""docs/TOOLS.md must document exactly the parameters each tool takes. Several
schemas drifted (from/to documented where tools take start/end, parameters that
never existed); this fails on the next drift instead of a user finding it."""

import asyncio
import pathlib
import re

from mcp.server.fastmcp import FastMCP

from bgphorizon_mcp.tools.alerts import register_alert_tools
from bgphorizon_mcp.tools.investigation import register_investigation_tools
from bgphorizon_mcp.tools.operator import register_operator_tools

DOC = pathlib.Path(__file__).resolve().parents[1] / "docs" / "TOOLS.md"
# Nested object parameters whose inner keys appear in the documented schema.
NESTED_KEYS = {"compare_windows": {"from", "to"}}


def _tools() -> dict[str, set[str]]:
    mcp = FastMCP("docs")
    for register in (register_operator_tools, register_investigation_tools, register_alert_tools):
        register(mcp, None)
    return {t.name: set((t.inputSchema.get("properties") or {}).keys()) for t in asyncio.run(mcp.list_tools())}


def test_every_tool_documented_with_its_real_parameters():
    doc = DOC.read_text()
    problems = []
    for name, params in sorted(_tools().items()):
        m = re.search(r'\{ "name": "' + name + r'",\s*"inputSchema": (\{.*?\n)```', doc, re.S)
        if not m:
            problems.append(f"{name}: no schema in TOOLS.md")
            continue
        documented = set(re.findall(r'"(\w+)":\s*\{', m.group(1))) - {"inputSchema", "properties", "items"}
        documented -= NESTED_KEYS.get(name, set())
        if documented != params:
            problems.append(f"{name}: doc-only={sorted(documented - params)} undocumented={sorted(params - documented)}")
    assert not problems, "\n".join(problems)
