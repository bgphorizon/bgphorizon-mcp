# Connecting an LLM to the BGPHorizon MCP server

How to register `bgphorizon-mcp` with each major client. Pick your client, copy
the config, restart, verify.

**Prerequisite:** an API key from the BGPHorizon admin panel. Every example below
expects it in the environment as `BGPHORIZON_API_KEY`.

---

The server is a Python package (FastMCP). The easiest path uses
[uv](https://docs.astral.sh/uv/), which fetches and runs it on demand, with no manual
install step, the Python equivalent of `npx`.

## Install

Two ways to use it. The hosted endpoint needs no install at all and is covered
under [Hosted](#hosted-endpoint) below; this section is for running it yourself.

### From source
```bash
# one-time: install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

git clone https://github.com/bgphorizon/bgphorizon-mcp.git && cd bgphorizon-mcp
uv sync
uv run bgphorizon-mcp --version
```

### Verify before wiring it to anything
```bash
export BGPHORIZON_API_KEY=bgps_xxx
uv run bgphorizon-mcp --selftest
# ✓ API reachable   ✓ key valid   ✓ 25 tools   ✓ 9 resources   ✓ 8 prompts
```

One line per check, so a wrong key or an unreachable API shows up here rather
than as a silent failure inside a client.

### Package installs, once it is on PyPI
Not published yet. When it is, `uvx bgphorizon-mcp` will fetch and run it with
nothing installed globally, and `uv tool install bgphorizon-mcp` or
`pipx install bgphorizon-mcp` will install it as a command. Until then, use the
source install above or the hosted endpoint.

---

## Hosted endpoint

`https://bgphorizon.com/mcp` runs this server for you. Nothing to install.

### Sign in (OAuth)

Clients that support MCP sign-in only need the URL. The first time they
connect, the server answers 401 and the client opens a BGPHorizon page where you
sign in and click **Allow**.

- **Claude Desktop and claude.ai:** Settings → Connectors → Add custom
  connector, URL `https://bgphorizon.com/mcp`.
- **Claude Code:** `claude mcp add --transport http bgphorizon https://bgphorizon.com/mcp`,
  then `/mcp`, select `bgphorizon`, and choose **Authenticate**.
- **Cursor, VS Code and other clients with MCP sign-in:**
  `{ "mcpServers": { "bgphorizon": { "url": "https://bgphorizon.com/mcp" } } }`

Signing in issues an ordinary `bgps_` key, named after the client, that appears
in your API tab. It counts toward your daily API allowance, lasts 90 days, and
revoking it disconnects the client. When it expires the client asks you to sign
in again. Signing in again from the same client replaces its previous key. The
account needs API access; without it the consent page refuses.

### API key

Scripts, agents and clients without MCP sign-in send a key from the API tab as
`Authorization: Bearer bgps_...`:

```bash
claude mcp add --transport http bgphorizon https://bgphorizon.com/mcp \
  --header "Authorization: Bearer bgps_xxx"
```

---

## Choosing a transport

| Transport | Use for | Flag |
|---|---|---|
| **stdio** | Local clients: Claude Code, Claude Desktop, Gemini CLI, Cursor, Zed | default |
| **HTTP** | Hosted agents, OpenAI Agents SDK, shared team servers, n8n | `--transport http --port 8931` |

Start with stdio. Move to HTTP only when something remote needs to reach it.

---

## Claude Code

**One command:**

```bash
claude mcp add bgphorizon \
  --env BGPHORIZON_API_KEY=bgps_xxx \
  -- uv run --directory /path/to/bgphorizon-mcp bgphorizon-mcp
```

(Drop the `uvx` prefix, using just `-- bgphorizon-mcp`, if you installed it with
`uv tool install` / `pipx` once it is published.)

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

**Verify:** run `/mcp`. `bgphorizon` should appear as connected with its tool
count. Then:

```
> Using bgphorizon, audit AS21799 and give me a remediation list
```

Prompts surface as slash commands: `/bgphorizon:audit_my_network`,
`/bgphorizon:write_report`.

---

## Claude Desktop

### Hosted endpoint, with sign-in (recommended)

Settings → Connectors → Add custom connector, and enter
`https://bgphorizon.com/mcp`. A BGPHorizon page opens; sign in and click
**Allow**. This needs no Node.js, no config file and no key to copy. See
[Hosted endpoint](#hosted-endpoint).

The config-file setups below are for a fixed API key or a self-hosted server.
Claude Desktop's config file only starts local processes: it skips a remote
`url` + `headers` entry as "not a valid MCP server configuration", so both
options run something locally.

Open the config file from **Settings → Developer → Edit Config**. That opens the
right file on every install, including the Microsoft Store build on Windows,
which keeps it under `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\`
rather than `%APPDATA%\Claude\`. Add the `mcpServers` block alongside whatever is
already in the file.

### Hosted endpoint with an API key, via mcp-remote (needs Node.js)

[`mcp-remote`](https://www.npmjs.com/package/mcp-remote) bridges the local
process to `https://bgphorizon.com/mcp` and adds your key to each request.
Install [Node.js](https://nodejs.org) (LTS) first; `npx` comes with it.

```json
{
  "mcpServers": {
    "bgphorizon": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "https://bgphorizon.com/mcp",
        "--header", "Authorization:${BGPHORIZON_AUTH}"
      ],
      "env": { "BGPHORIZON_AUTH": "Bearer bgps_xxx" }
    }
  }
}
```

Keep the key in `env` and leave no space after `Authorization:`. Claude Desktop
on Windows mangles arguments that contain spaces, so
`"Authorization: Bearer bgps_xxx"` written directly into `args` fails.

### Self-hosted, via uv (needs uv)

Clone and `uv sync` as in [Install](#install), then:

```json
{
  "mcpServers": {
    "bgphorizon": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/bgphorizon-mcp", "bgphorizon-mcp"],
      "env": { "BGPHORIZON_API_KEY": "bgps_xxx" }
    }
  }
}
```

On Windows, write the directory with doubled backslashes:
`"C:\\Users\\you\\bgphorizon-mcp"`.

### Restart and verify

Quit Claude Desktop fully and reopen it. On Windows, quit from the system tray;
closing the window leaves it running. The tools appear under the connector icon
in the composer.

| Message | Cause | Fix |
|---|---|---|
| "not valid MCP server configurations and were skipped" | A `url` entry | Use the connector, or one of the two configs above |
| "couldn't start … command wasn't found" | Node.js or uv not installed, or not on the app's `PATH` | Install it, then restart the app. If it is installed, use the full path: `"C:\\Program Files\\nodejs\\npx.cmd"` on Windows, the output of `which npx` / `which uv` on macOS |
| Server starts, every tool call returns 401 | Key missing or mistyped | Check the `env` value, including the `Bearer ` prefix for mcp-remote |

Claude Desktop writes each server's output to `mcp-server-bgphorizon.log` in its
`logs` folder, next to the config file. Read that first when a server will not
connect.

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

### Responses API (hosted MCP)

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

**Cursor**: `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global), same
`mcpServers` shape as Claude Desktop.

**Zed**: `settings.json` under `context_servers`:
```json
{ "context_servers": { "bgphorizon": {
    "command": { "path": "bgphorizon-mcp", "args": [] },
    "env": { "BGPHORIZON_API_KEY": "bgps_xxx" } } } }
```

**VS Code / Copilot**: `.vscode/mcp.json`:
```json
{ "servers": { "bgphorizon": { "type": "stdio", "command": "bgphorizon-mcp",
    "env": { "BGPHORIZON_API_KEY": "${input:bgph_key}" } } },
  "inputs": [{ "id": "bgph_key", "type": "promptString",
               "description": "BGPHorizon API key", "password": true }] }
```

**LangChain / LangGraph**: via `langchain-mcp-adapters`:
```python
from langchain_mcp_adapters.client import MultiServerMCPClient
client = MultiServerMCPClient({"bgphorizon": {
    "command": "bgphorizon-mcp", "transport": "stdio",
    "env": {"BGPHORIZON_API_KEY": key}}})
tools = await client.get_tools()
```

**n8n / Make / Zapier**: use HTTP transport and point the MCP Client node at
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

`proxy_buffering off` is required. With it on, streamed responses arrive only
after the request completes, which looks exactly like a hung server.


Requests to `/mcp` without a live bearer token get an HTTP 401 with a
`WWW-Authenticate` header pointing at
`<public origin>/.well-known/oauth-protected-resource/mcp`. The server checks
tokens against `<BGPHORIZON_API_URL>/oauth/tokeninfo` and caches the answer for
60 seconds. Set `BGPHORIZON_PUBLIC_URL` to the origin clients use (for example
`https://mcp.example.com`) when the server sits behind a proxy; without it the
origin is taken from `X-Forwarded-Proto` and `Host`. Sign-in only works against
bgphorizon.com, which serves the OAuth metadata. A self-hosted HTTP server
pointed elsewhere still accepts API keys.

---

## Setting up a report-writing agent from scratch

The end-to-end path for someone with no prior context:

```bash
# 1. install uv + verify the server
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone https://github.com/bgphorizon/bgphorizon-mcp.git && cd bgphorizon-mcp
uv sync
export BGPHORIZON_API_KEY=bgps_xxx
uv run bgphorizon-mcp --selftest

# 2. register with Claude Code
claude mcp add bgphorizon --env BGPHORIZON_API_KEY=$BGPHORIZON_API_KEY \
  -- uv run --directory "$PWD" bgphorizon-mcp

# 3. give the model the methodology
mkdir -p .claude && cp reporting/SYSTEM-PROMPT.md .claude/CLAUDE.md

# 4. write one
claude "/bgphorizon:write_report AS54994 over the last 60 days"
```

Step 3 is the one people skip, and it is the one that determines output quality.
The tools supply data; the system prompt supplies the method, including the two
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
