"""Tool registration. Investigation (15) + operator (3) = 18 task-shaped tools."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import BGPHorizonClient
from .investigation import register_investigation_tools
from .operator import register_operator_tools


def register_tools(mcp: FastMCP, client: BGPHorizonClient) -> None:
    register_investigation_tools(mcp, client)
    register_operator_tools(mcp, client)
