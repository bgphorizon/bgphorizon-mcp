"""CLI entrypoint for ``bgphorizon-mcp``.

    bgphorizon-mcp                         # stdio (default) — for local clients
    bgphorizon-mcp --transport http --port 8931
    bgphorizon-mcp --selftest              # verify API reachability + surface counts
    bgphorizon-mcp --version
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import sys

from . import __version__
from .client import APIError
from .config import load_settings
from .server import build_server


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bgphorizon-mcp",
        description="MCP server for BGPHorizon BGP routing intelligence.",
    )
    p.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="stdio for local clients (default); http for hosted/streamable use.",
    )
    p.add_argument("--port", type=int, default=8931, help="Port for --transport http.")
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address for --transport http (e.g. 0.0.0.0 to accept a reverse proxy).",
    )
    p.add_argument(
        "--api-url",
        default=None,
        help="BGPHorizon base URL (default: $BGPHORIZON_API_URL or production).",
    )
    p.add_argument(
        "--require-auth",
        action="store_true",
        help="Refuse to start without BGPHORIZON_API_KEY set.",
    )
    p.add_argument(
        "--selftest",
        action="store_true",
        help="Check API reachability + key, print tool/resource/prompt counts, exit.",
    )
    p.add_argument("--version", action="store_true", help="Print version and exit.")
    return p


def _selftest(mcp, settings) -> int:
    client = mcp._bgphorizon_client
    ok = True

    def line(good: bool, label: str) -> None:
        nonlocal ok
        ok = ok and good
        print(f"{'✓' if good else '✗'} {label}")

    # API reachable?
    try:
        client.health()
        line(True, f"API reachable ({settings.api_url})")
    except Exception as exc:  # noqa: BLE001
        line(False, f"API unreachable ({settings.api_url}): {exc}")

    # Key valid? (a cheap authed call)
    if settings.api_key:
        try:
            client.rdap_asn(13335)
            line(True, "key valid")
        except APIError as exc:
            line(exc.status not in (401, 403), f"key check: {exc}")
        except Exception as exc:  # noqa: BLE001
            line(False, f"key check failed: {exc}")
    else:
        line(False, "no BGPHORIZON_API_KEY set")

    import asyncio

    tools = asyncio.run(mcp.list_tools())
    resources = asyncio.run(mcp.list_resources())
    prompts = asyncio.run(mcp.list_prompts())
    line(len(tools) == 15, f"{len(tools)} tools")
    line(len(resources) == 8, f"{len(resources)} resources")
    line(len(prompts) == 7, f"{len(prompts)} prompts")

    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.version:
        print(f"bgphorizon-mcp {__version__}")
        return 0

    settings = load_settings(api_url=args.api_url)
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.require_auth and not settings.api_key:
        print("error: BGPHORIZON_API_KEY is required (--require-auth)", file=sys.stderr)
        return 2

    # Hosted HTTP is multi-tenant: every request must carry the caller's own key,
    # which is what gets metered and billed. Drop any process-level env key so a
    # keyless request can never silently fall back to (and bill) the host's key.
    if args.transport == "http" and not args.selftest:
        if settings.api_key:
            logging.getLogger("bgphorizon-mcp").warning(
                "ignoring BGPHORIZON_API_KEY in http mode; keys come per-request from callers"
            )
        settings = dataclasses.replace(settings, api_key=None)

    mcp = build_server(
        settings, host=args.host, port=args.port, stateless=(args.transport == "http")
    )

    if args.selftest:
        return _selftest(mcp, settings)

    try:
        if args.transport == "http":
            mcp.run(transport="streamable-http")
        else:
            mcp.run(transport="stdio")
    finally:
        mcp._bgphorizon_client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
