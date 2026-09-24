# bgphorizon-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes **BGPHorizon**
BGP routing data to any MCP-capable LLM client (Claude Code,
Claude Desktop, Cursor, Gemini CLI, OpenAI Agents, …).

It is not a thin wrapper over the REST API. The surface is **22 task-shaped
tools** built around the operations investigators and operators perform,
each returning aggregates plus `warnings[]` so a model cannot silently misread the
data (persistence, single-vantage-point concentration, censored `first_seen`, …).

```
LLM client ──stdio│http──► bgphorizon-mcp ──► BGPHorizon /api/v1 ──► ClickHouse
                            (key auth, metering, tier entitlements inherited)
```

## Install & run

The server needs a BGPHorizon API key (create one in your account's **API**
panel), passed as `BGPHORIZON_API_KEY`.

**From source, with [uv](https://docs.astral.sh/uv/):**

```bash
git clone https://github.com/bgphorizon/bgphorizon-mcp.git && cd bgphorizon-mcp
uv sync
export BGPHORIZON_API_KEY=bgps_xxx
uv run bgphorizon-mcp --selftest   # ✓ API reachable ✓ key valid ✓ 22 tools ✓ 9 resources ✓ 8 prompts
```

The selftest prints a line per check, so a wrong key or an unreachable API shows
up before you wire the server into a client.

**Not on PyPI yet.** Once it is released there, `uvx bgphorizon-mcp` will run it
with nothing to install, and `uv tool install bgphorizon-mcp` or
`pipx install bgphorizon-mcp` will install it. Until then use the source install
above, or the hosted endpoint, which needs no install at all.

## Connect it

You can either use the **hosted** endpoint (nothing to install) or **self-host**
(this repo). Both authenticate with the same `bgps_` API key and go through the
same metered `/api/v1`.

### Hosted endpoint (no install)

```bash
claude mcp add --transport http bgphorizon https://bgphorizon.com/mcp \
  --header "Authorization: Bearer bgps_xxx"
```

```json
{
  "mcpServers": {
    "bgphorizon": {
      "url": "https://bgphorizon.com/mcp",
      "headers": { "Authorization": "Bearer bgps_xxx" }
    }
  }
}
```

### Self-hosted with Claude Code

```bash
claude mcp add bgphorizon --env BGPHORIZON_API_KEY=bgps_xxx \\
  -- uv run --directory /path/to/bgphorizon-mcp bgphorizon-mcp
```

### Claude Desktop / Cursor / Zed (`mcpServers` block)

```json
{
  "mcpServers": {
    "bgphorizon": {
      "command": "uvx",
      "args": ["bgphorizon-mcp"],
      "env": { "BGPHORIZON_API_KEY": "bgps_xxx" }
    }
  }
}
```

Point at a non-production API with `"BGPHORIZON_API_URL"` in the same `env` block.

### Hosted / HTTP transport

```bash
bgphorizon-mcp --transport http --port 8931 --require-auth
```

Put it behind TLS with `proxy_buffering off` for streaming. See
[`docs/SETUP.md`](docs/SETUP.md) for every client (Gemini CLI,
OpenAI Agents SDK, LangChain, n8n, VS Code) and reverse-proxy config.

## What's in the box

**Investigation tools (17):** `identify`, `inventory`, `timeline`,
`origin_history`, `reachability`, `global_reach`, `detections`, `paths`, `relationships`,
`path_diversity`, `translate_communities`, `compare_windows`, `locate`, `subprefixes`, `events_sample`,
`platform_baseline`, `notable_events`.

**Operator tools (3):** `health_check`, `validate_announcement`, `visibility`.

**Alert tools (2):** `my_alerts`, `my_monitors`. Your own monitoring rather than the
global table. `my_alerts(window="today")` returns every alert your monitors fired over a
window, with totals by detection type, severity and monitor, ready to write up.
`my_monitors` lists your watchlist with each monitor's alert volume for the same window,
so coverage and noise come back in one call.

**Resources (9):** `bgphorizon://reference/{detection-types, collectors, glossary,
data-horizon, report-template, writing-guide, qa-checklist, methodology,
report-examples}`: reference the model can pull without a tool call.
`report-template` ships with the house CSS already inlined, and the full report
standards are here, so a hosted client that never clones the repo still writes
house-style reports. Only the local enforcement scripts (`style-lint.py`,
`build-report.sh`) need the repo, and they check work the standards already
describe.

**Prompts (8):** `investigate_entity`, `write_report`, `alert_report`,
`triage_incident`, `locate_infrastructure`, `audit_my_network`,
`preflight_change`, `explain_incident`. The methodology lives here. In Claude
Code they surface as `/bgphorizon:audit_my_network`, etc. `write_report` asks
first whether you want to review its findings before it writes them up.

Full tool contracts, with a worked example per tool: [`docs/TOOLS.md`](docs/TOOLS.md).

## Writing investigative reports

The server ships a complete **report kit** and a `write_report` prompt so you can
generate BGP routing reports from any client: Claude
Code, Claude Desktop, OpenAI (Codex / Agents / ChatGPT), Gemini CLI, Cursor, and more.

Connect the server, then ask for a report. The `write_report` prompt carries the
whole procedure: it reads the standards, runs the investigation, asks whether you
want to review the findings before it writes, and fills the template. Nothing has
to be cloned for that. Cloning adds `build-report.sh`, which validates the HTML,
fails on a style violation, and renders a PDF and PNG.

The per-client, copy-paste guide is in
**[`reporting/README.md`](reporting/README.md)**.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `BGPHORIZON_API_KEY` | (none) | API key, forwarded as `Authorization: Bearer`. |
| `BGPHORIZON_API_URL` | `https://bgphorizon.com` | BGPHorizon base URL. |
| `BGPHORIZON_TIMEOUT` | `30` | Per-request timeout (seconds). |
| `BGPHORIZON_LOG_LEVEL` | `INFO` | DEBUG surfaces every upstream request. |

## Develop

```bash
uv sync --group dev
uv run pytest            # deterministic reshaping logic (transitions, direction, …)
uv run bgphorizon-mcp --selftest
npx @modelcontextprotocol/inspector uv run bgphorizon-mcp   # raw protocol inspection
```

Layout: `client.py` (one method per `/api/v1` endpoint) · `tools/` (analytical
operations + `_shape.py` pure helpers) · `resources.py` + `reference/` (bundled
docs) · `prompts.py` (methodology). Adding a tool = one function under `tools/`
with an `@mcp.tool()` decorator; the input schema comes from its type hints.

## License

MIT.
