# Writing BGP reports with any LLM client

The MCP server ships everything needed to produce a **defensible, house-style BGP
routing report** from *any* MCP-capable client — Claude Code, Claude Desktop,
OpenAI (Codex CLI / Agents SDK / ChatGPT), Gemini CLI, Cursor, and others.

It's the same three steps everywhere. Only step 1 (how you connect the server) and
*where* you paste the system prompt differ per client — both are spelled out below.

## Recommended workflow (what works best)

For the highest-quality output, **clone this repo and point the model at the on-disk
kit** — it includes the build/QA tooling the MCP itself can't run for you:

1. **Clone** — `git clone https://github.com/bgphorizon/bgphorizon-mcp`
2. **Register the MCP** with your client (hosted or self-hosted; see below).
3. **Ask for a report, and tell the model to use the `reporting/` directory** for the
   QA standards, template, and CSS — then run
   [`build-report.sh`](build-report.sh) to inline the CSS, validate the HTML, and
   render a PDF/PNG.

Why this matters: the MCP's `report-template` resource is self-contained, but the real
value of the on-disk kit is [`WRITING-GUIDE.md`](WRITING-GUIDE.md) (voice + the "avoid"
table), [`QA-CHECKLIST.md`](QA-CHECKLIST.md) (the pre-publication pass), and
`build-report.sh` (which catches undefined CSS vars, unreplaced placeholders, and
invalid nesting, and produces the PDF). A model that only reads the MCP resource can
produce a good report, but a model told to *follow the on-disk `reporting/` kit and run
`build-report.sh`* produces a **house-standard** one. When you invoke `write_report`,
explicitly say: *"use the `reporting/` directory for the writing guide, QA checklist,
template and CSS, and run build-report.sh at the end."*

**No clone?** The hosted/no-install path still works — the MCP serves the full standards
as resources (`writing-guide`, `qa-checklist`, `methodology`, and a `report-template`
with the house CSS already inlined). You just don't get the local build/render script.

## The workflow (three steps)

1. **Connect the MCP server** to your client (once). Full per-client config is in
   [`../docs/SETUP.md`](../docs/SETUP.md); the essentials are repeated below.
2. **Give the model the method** — set your agent's system prompt to
   [`SYSTEM-PROMPT.md`](SYSTEM-PROMPT.md). This is the step people skip, and it's the
   one that determines quality: it installs the two checks (persistence, and
   vantage-point attribution) that keep conclusions correct.
3. **Ask for the report.** The server exposes a `write_report` **prompt** that drives
   the whole flow — it reads the reference resources, runs the investigation tools to
   gather evidence, and fills the HTML template. Clients that surface MCP prompts let
   you invoke it directly; anywhere else, just say *"write a BGP report on AS13335 over
   the last 60 days."*

That's it. The model uses the 20 tools to gather evidence and the bundled
`report-template` resource to produce a single self-contained HTML file.

## Per-client setup

You need a BGPHorizon API key (`bgps_…`) from your account's API panel. Use the
**hosted** endpoint (`https://bgphorizon.com/mcp`, nothing to install) or self-host
with `uvx bgphorizon-mcp` — either works identically for reports.

### Claude Code
```bash
# 1. connect (hosted)
claude mcp add --transport http bgphorizon https://bgphorizon.com/mcp \
  --header "Authorization: Bearer bgps_your_key"

# 2. method: drop the system prompt into your project
mkdir -p .claude && cp path/to/reporting/SYSTEM-PROMPT.md .claude/CLAUDE.md

# 3. report — the prompt is a slash command:
#    /bgphorizon:write_report AS13335 over the last 60 days
```

### Claude Desktop
1. **Connect** — add to `claude_desktop_config.json`:
   ```json
   { "mcpServers": { "bgphorizon": {
       "url": "https://bgphorizon.com/mcp",
       "headers": { "Authorization": "Bearer bgps_your_key" } } } }
   ```
2. **Method** — paste `SYSTEM-PROMPT.md` into a Project's custom instructions (or the
   top of the chat).
3. **Report** — pick the **write_report** prompt from the connector's prompt menu, or
   ask *"write a BGP report on AS13335."*

### OpenAI
- **Codex CLI / Agents SDK** — register the server (stdio for self-host, HTTP for
  hosted; see [`../docs/SETUP.md`](../docs/SETUP.md)) and set the agent's
  `instructions`/system message to the contents of `SYSTEM-PROMPT.md`:
  ```python
  agent = Agent(name="BGP Analyst", model="gpt-5",
                instructions=open("reporting/SYSTEM-PROMPT.md").read(),
                mcp_servers=[server])
  ```
- **ChatGPT (hosted MCP connector)** — add the connector with
  `server_url=https://bgphorizon.com/mcp` and your bearer token, paste
  `SYSTEM-PROMPT.md` as a custom instruction, then ask for the report.

### Gemini CLI
1. **Connect** — `~/.gemini/settings.json`:
   ```json
   { "mcpServers": { "bgphorizon": {
       "httpUrl": "https://bgphorizon.com/mcp",
       "headers": { "Authorization": "Bearer bgps_your_key" } } } }
   ```
2. **Method** — put `SYSTEM-PROMPT.md` in your `GEMINI.md` / system prompt.
3. **Report** — invoke the `write_report` prompt (`/mcp` lists them) or ask in natural
   language.

### Cursor / Zed / VS Code / LangChain / n8n
Connect via each client's MCP config ([`../docs/SETUP.md`](../docs/SETUP.md) has all of
them), set `SYSTEM-PROMPT.md` as the system/rules prompt, and ask for the report. The
workflow is identical; only the config file differs.

## What's in this kit

| File | Purpose |
|---|---|
| `SYSTEM-PROMPT.md` | **Step 2.** Drop into your agent's system prompt so a cold model produces house-style output. |
| `METHODOLOGY.md` | The procedure — evidence order + the two checks (persistence, vantage-point attribution). |
| `WRITING-GUIDE.md` | House voice and structure for the write-up. |
| `TEMPLATE.html` | Self-contained HTML report skeleton (`{{PLACEHOLDER}}`s). |
| `template-assets/report.css` | Styles to inline into the template. |
| `build-report.sh` | Inlines the CSS and checks the output is standalone. |
| `QA-CHECKLIST.md` | Work through before publishing. |
| `EXAMPLES.md` | Worked examples. |

The `TEMPLATE.html` skeleton is also served by the server as the
`bgphorizon://reference/report-template` resource, so a connected model can pull it
without these files present — but keeping the kit handy lets you read, adapt, or run
the workflow by hand.

## What good output looks like

A model with this server + system prompt should answer *"is AS54994 doing anything
notable?"* in roughly five tool calls, and produce a report where **every claim traces
to a specific tool result**, persistence is stated before any migration/handover
language, and single-vantage-point signals are flagged rather than trusted. If the
evidence is thin, the report says so instead of reaching.
