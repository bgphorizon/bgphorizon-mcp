# Connecting an LLM to the BGPHorizon MCP Server

How to register `bgphorizon-mcp` with each major client. Pick your client, copy
the config, restart, verify.

**Prerequisite:** an API key from the BGPHorizon admin panel. Every example below
expects it in the environment as `BGPHORIZON_API_KEY`.

---

The server is a Python package (FastMCP). The easiest path uses
[uv](https://docs.astral.sh/uv/), which fetches and runs it on demand — no manual
install step, the Python equivalent of `npx`.

## Install

### uvx (recommended — zero install)
```bash
# one-time: install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

export BGPHORIZON_API_KEY=bgps_xxx
uvx bgphorizon-mcp --version        # fetches + runs; nothing installed globally
```

### As a persistent tool
```bash
uv tool install bgphorizon-mcp      # or: pipx install bgphorizon-mcp
bgphorizon-mcp --version
```

### From source
```bash
git clone https://github.com/bgphorizon/bgphorizon-mcp && cd bgphorizon-mcp
uv sync
uv run bgphorizon-mcp --version
```

### Docker
```bash
docker run -i --rm -e BGPHORIZON_API_KEY ghcr.io/bgphorizon/bgphorizon-mcp:latest
```

### Verify before wiring it to anything
```bash
export BGPHORIZON_API_KEY=bgps_xxx
uvx bgphorizon-mcp --selftest
# ✓ API reachable   ✓ key valid   ✓ 17 tools   ✓ 5 resources   ✓ 7 prompts
```

---

## Transport: which one do I need?

| Transport | Use for | Flag |
|---|---|---|
| **stdio** | Local clients — Claude Code, Claude Desktop, Gemini CLI, Cursor, Zed | default |
| **HTTP** | Hosted agents, OpenAI Agents SDK, shared team servers, n8n | `--transport http --port 8931` |

Start with stdio. Move to HTTP only when something remote needs to reach it.

---

## Claude Code

**One command:**

```bash
claude mcp add bgphorizon \
  --env BGPHORIZON_API_KEY=bgps_xxx \
  -- uvx bgphorizon-mcp
```

(Drop the `uvx` prefix — just `-- bgphorizon-mcp` — if you installed it with
`uv tool install` / `pipx`.)

Add `--scope project` to commit it to `.mcp.json` for the whole team, or
`--scope user` to make it available in every project.

**Or by hand** in `~/.claude/settings.json` (user) / `.mcp.json` (project):

```json
{
  "mcpServers": {
    "bgphorizon": {
      "command": "bgphorizon-mcp",
      "env": {
        "BGPHORIZON_API_KEY": "bgps_xxx",
        "BGPHORIZON_API_URL": "https://bgphorizon.com"
      }
    }
  }
}
```

**Verify:** run `/mcp` — `bgphorizon` should appear as connected with its tool
count. Then:

```
> Using bgphorizon, audit AS21799 and give me a remediation list
```

Prompts surface as slash commands: `/bgphorizon:audit_my_network`,
`/bgphorizon:write_report`.

---

## Claude Desktop

Edit `claude_desktop_config.json`:

- macOS — `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows — `%APPDATA%\Claude\claude_desktop_config.json`
- Linux — `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "bgphorizon": {
      "command": "bgphorizon-mcp",
      "env": { "BGPHORIZON_API_KEY": "bgps_xxx" }
    }
  }
}
```

Restart Claude Desktop fully (quit, don't just close the window). The tools appear
under the connector icon in the composer.

> Use an absolute path (`/usr/local/bin/bgphorizon-mcp`) if the binary isn't on
> the GUI app's `PATH` — the most common cause of a server that silently fails to
> start on macOS.

---

## Gemini CLI

`~/.gemini/settings.json`, or `.gemini/settings.json` for a single project:

```json
{
  "mcpServers": {
    "bgphorizon": {
      "command": "bgphorizon-mcp",
      "env": { "BGPHORIZON_API_KEY": "bgps_xxx" },
      "timeout": 30000,
      "trust": false
    }
  }
}
```

Verify with `/mcp list` inside the CLI. `trust: false` keeps per-call
confirmation; set it to `true` once you're comfortable.

HTTP transport instead:

```json
{ "mcpServers": { "bgphorizon": {
    "httpUrl": "http://localhost:8931/mcp",
    "headers": { "Authorization": "Bearer bgps_xxx" } } } }
```

---

## OpenAI

### Agents SDK (Python)

```python
import asyncio, os
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

async def main():
    async with MCPServerStdio(
        params={"command": "bgphorizon-mcp",
                "env": {"BGPHORIZON_API_KEY": os.environ["BGPHORIZON_API_KEY"]}},
        cache_tools_list=True,
    ) as server:
        agent = Agent(
            name="BGP Analyst",
            model="gpt-5",
            instructions=open("reporting/SYSTEM-PROMPT.md").read(),
            mcp_servers=[server],
        )
        result = await Runner.run(agent, "Audit AS21799 and list remediation by priority.")
        print(result.final_output)

asyncio.run(main())
```

### Agents SDK (TypeScript)

```ts
import { Agent, run, MCPServerStdio } from "@openai/agents";

const server = new MCPServerStdio({
  command: "bgphorizon-mcp",
  env: { BGPHORIZON_API_KEY: process.env.BGPHORIZON_API_KEY! },
});
await server.connect();

const agent = new Agent({
  name: "BGP Analyst",
  model: "gpt-5",
  mcpServers: [server],
});

console.log((await run(agent, "Audit AS21799.")).finalOutput);
await server.close();
```

### Responses API — hosted MCP

Requires the HTTP transport on a publicly reachable URL.

```python
from openai import OpenAI
client = OpenAI()

resp = client.responses.create(
    model="gpt-5",
    tools=[{
        "type": "mcp",
        "server_label": "bgphorizon",
        "server_url": "https://bgphorizon.com/mcp",
        "authorization": f"Bearer {API_KEY}",
        "require_approval": "never",
    }],
    input="Is AS54994 doing anything notable?",
)
print(resp.output_text)
```

> OpenAI's servers must reach `server_url`, so `localhost` will not work here.
> Deploy behind TLS and require the bearer token.

---

## Other clients

**Cursor** — `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global), same
`mcpServers` shape as Claude Desktop.

**Zed** — `settings.json` under `context_servers`:
```json
{ "context_servers": { "bgphorizon": {
    "command": { "path": "bgphorizon-mcp", "args": [] },
    "env": { "BGPHORIZON_API_KEY": "bgps_xxx" } } } }
```

**VS Code / Copilot** — `.vscode/mcp.json`:
```json
{ "servers": { "bgphorizon": { "type": "stdio", "command": "bgphorizon-mcp",
    "env": { "BGPHORIZON_API_KEY": "${input:bgph_key}" } } },
  "inputs": [{ "id": "bgph_key", "type": "promptString",
               "description": "BGPHorizon API key", "password": true }] }
```

**LangChain / LangGraph** — via `langchain-mcp-adapters`:
```python
from langchain_mcp_adapters.client import MultiServerMCPClient
client = MultiServerMCPClient({"bgphorizon": {
    "command": "bgphorizon-mcp", "transport": "stdio",
    "env": {"BGPHORIZON_API_KEY": key}}})
tools = await client.get_tools()
```

**n8n / Make / Zapier** — use HTTP transport and point the MCP Client node at
`https://…/mcp` with a bearer token.

---

## Self-hosting the HTTP transport

```bash
bgphorizon-mcp --transport http --port 8931 \
  --api-url https://bgphorizon.com \
  --require-auth
```

```nginx
location /mcp {
    proxy_pass http://127.0.0.1:8931;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_buffering off;              # required for streaming
    proxy_read_timeout 300s;
}
```

`proxy_buffering off` is not optional — with it on, streamed responses arrive only
after the request completes, which looks exactly like a hung server.

---

## Setting up a report-writing agent from scratch

The end-to-end path for someone with no prior context:

```bash
# 1. install uv + verify the server
curl -LsSf https://astral.sh/uv/install.sh | sh
export BGPHORIZON_API_KEY=bgps_xxx
uvx bgphorizon-mcp --selftest

# 2. register with Claude Code
claude mcp add bgphorizon --env BGPHORIZON_API_KEY=$BGPHORIZON_API_KEY -- uvx bgphorizon-mcp

# 3. give the model the methodology
mkdir -p .claude && cp reporting/SYSTEM-PROMPT.md .claude/CLAUDE.md

# 4. write one
claude "/bgphorizon:write_report AS54994 over the last 60 days"
```

Step 3 is the one people skip, and it is the one that determines output quality.
The tools supply data; the system prompt supplies the method — including the two
checks (persistence, and vantage-point attribution) that prevent the specific
errors documented in [`../reporting/METHODOLOGY.md`](../reporting/METHODOLOGY.md).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Server not listed after restart | Binary not on the GUI app's `PATH` | Use an absolute `command` path |
| `401` on every tool call | Key missing or not passed through | Confirm `env` block; test with `--selftest` |
| Tools appear, all calls time out | API unreachable from the server | Check `BGPHORIZON_API_URL`, test with `curl` |
| Model ignores the tools | No instruction to use them | Reference the server by name, or install the system prompt |
| Responses truncated mid-JSON | Client output cap | Narrow the window; `events_sample` caps at 500 by design |
| Quota errors mid-investigation | M11 entitlement limit | Check tier limits; errors are structured so the model can explain them |
| Streaming hangs behind a proxy | `proxy_buffering` on | Set `proxy_buffering off` |

Debug logging:
```bash
BGPHORIZON_LOG_LEVEL=debug bgphorizon-mcp 2>/tmp/mcp.log
```

Raw protocol inspection:
```bash
npx @modelcontextprotocol/inspector bgphorizon-mcp
```
