# Writing BGP reports with any LLM client

The MCP server ships everything needed to produce a **defensible, house-style BGP
routing report** from any MCP-capable client: Claude Code, Claude Desktop,
OpenAI (Codex CLI / Agents SDK / ChatGPT), Gemini CLI, Cursor, and others.

It's the same three steps everywhere. Only step 1 (how you connect the server) and
*where* you paste the system prompt differ per client. Both are spelled out below.

## Hosted or cloned: what each one gives you

The server carries the standards, not just the data. Everything needed to write
a house-style report travels over MCP, so a hosted client that never clones
anything produces the same document.

| | Hosted (`https://bgphorizon.com/mcp`) | Clone of this repo |
|---|---|---|
| 22 investigation tools | yes | yes |
| `write_report` prompt (full procedure, asks whether to review findings first) | yes | yes |
| Writing guide, QA checklist, methodology, worked examples | yes, as resources | yes, on disk |
| Report template with the house CSS inlined | yes | yes |
| `style-lint.py`, an automated check for the banned list | no | yes |
| `build-report.sh`: validate HTML, run the lint, render PDF and PNG | no | yes |

So clone when you want the build to **fail** on a style violation and to get a
rendered PDF and PNG out the other end. Do not clone expecting better standards:
they are the same words either way, and the server tells the model to read them.

Hosted, the model fetches them itself:

```
bgphorizon://reference/writing-guide      style rules and the banned list
bgphorizon://reference/qa-checklist       the pre-publication pass
bgphorizon://reference/methodology        evidence order and the two checks
bgphorizon://reference/report-examples    published reports and what review caught
bgphorizon://reference/report-template    the skeleton, CSS already inlined
```

You do not need to name those resources yourself. The `write_report` prompt
reads them as step 1, and the server's own instructions tell any connected model
to read the guide and checklist before drafting anything for a person.

Cloned, point the model at `reporting/` instead and finish with
`./reporting/build-report.sh my-report.html`, which inlines the CSS, checks the
HTML for unclosed tags and undefined CSS variables, runs `style-lint.py`, and
renders the PDF and PNG.

## The workflow (three steps)

1. **Connect the MCP server** to your client (once). Full per-client config is in
   [`../docs/SETUP.md`](../docs/SETUP.md); the essentials are repeated below.
2. **Ask for the report.** The server exposes a `write_report` **prompt** that
   drives the whole flow: it reads the reference resources, runs the
   investigation tools, and fills the HTML template. Clients that surface MCP
   prompts let you invoke it directly, for example
   `/bgphorizon:write_report AS13335 over the last 60 days`. Anywhere else, say
   *"write a BGP report on AS13335 over the last 60 days"* and the server's own
   instructions still send the model to the writing guide and QA checklist first.
3. **Optional, for a cold agent**: set the system prompt to
   [`SYSTEM-PROMPT.md`](SYSTEM-PROMPT.md) (needs a clone). The two checks it
   installs, persistence and vantage-point attribution, already reach every
   connected client through the server's instructions, so this is reinforcement
   for a long-running agent rather than a missing piece.

The model uses the 22 tools to gather evidence and the bundled
`report-template` resource to produce a single self-contained HTML file.

Before it starts, `write_report` has the model ask whether you want to review
the findings first. Say yes and it gathers the evidence, then stops and walks
you through what it found, numbered, with the confidence behind each one and
what it could not determine. You can question any of it, ask for more lookups,
or correct it from what you know about the network before a line of the report
exists. Say no and it runs straight through. If your input changes a
conclusion, the report records the correction instead of quietly presenting the
corrected version.

## Per-client setup

You need a BGPHorizon API key (`bgps_…`) from your account's API panel. Use the
**hosted** endpoint (`https://bgphorizon.com/mcp`, nothing to install) or self-host
from a source checkout. Either works identically for reports.

### Claude Code
```bash
# 1. connect (hosted)
claude mcp add --transport http bgphorizon https://bgphorizon.com/mcp \
  --header "Authorization: Bearer bgps_your_key"

# 2. method: drop the system prompt into your project
mkdir -p .claude && cp path/to/reporting/SYSTEM-PROMPT.md .claude/CLAUDE.md

# 3. report: the prompt is a slash command:
#    /bgphorizon:write_report AS13335 over the last 60 days
```

### Claude Desktop
1. **Connect**: add to `claude_desktop_config.json`:
   ```json
   { "mcpServers": { "bgphorizon": {
       "url": "https://bgphorizon.com/mcp",
       "headers": { "Authorization": "Bearer bgps_your_key" } } } }
   ```
2. **Method**: paste `SYSTEM-PROMPT.md` into a Project's custom instructions (or the
   top of the chat).
3. **Report**: pick the **write_report** prompt from the connector's prompt menu, or
   ask *"write a BGP report on AS13335."*

### OpenAI
- **Codex CLI / Agents SDK**: register the server (stdio for self-host, HTTP for
  hosted; see [`../docs/SETUP.md`](../docs/SETUP.md)) and set the agent's
  `instructions`/system message to the contents of `SYSTEM-PROMPT.md`:
  ```python
  agent = Agent(name="BGP Analyst", model="gpt-5",
                instructions=open("reporting/SYSTEM-PROMPT.md").read(),
                mcp_servers=[server])
  ```
- **ChatGPT (hosted MCP connector)**: add the connector with
  `server_url=https://bgphorizon.com/mcp` and your bearer token, paste
  `SYSTEM-PROMPT.md` as a custom instruction, then ask for the report.

### Gemini CLI
1. **Connect**: `~/.gemini/settings.json`:
   ```json
   { "mcpServers": { "bgphorizon": {
       "httpUrl": "https://bgphorizon.com/mcp",
       "headers": { "Authorization": "Bearer bgps_your_key" } } } }
   ```
2. **Method**: put `SYSTEM-PROMPT.md` in your `GEMINI.md` or system prompt.
3. **Report**: invoke the `write_report` prompt (`/mcp` lists them) or ask in natural
   language.

### Cursor / Zed / VS Code / LangChain / n8n
Connect via each client's MCP config ([`../docs/SETUP.md`](../docs/SETUP.md) has all of
them), set `SYSTEM-PROMPT.md` as the system/rules prompt, and ask for the report. The
workflow is identical; only the config file differs.

## What's in this kit

| File | Purpose |
|---|---|
| `SYSTEM-PROMPT.md` | **Step 2.** Drop into your agent's system prompt so a cold model produces house-style output. |
| `METHODOLOGY.md` | The procedure: evidence order and the two checks (persistence, vantage-point attribution). |
| `WRITING-GUIDE.md` | Style rules, banned phrases, heading and title conventions. |
| `TEMPLATE.html` | Self-contained HTML report skeleton (`{{PLACEHOLDER}}`s). |
| `template-assets/report.css` | Styles to inline into the template. |
| `build-report.sh` | Inlines the CSS, validates structure, runs the style lint, renders PDF/PNG. |
| `style-lint.py` | Fails on em-dashes, "not X but Y" and banned words; warns on Title Case headings. Works on HTML or Markdown. |
| `QA-CHECKLIST.md` | Work through before publishing. |
| `EXAMPLES.md` | Worked examples. |

The `TEMPLATE.html` skeleton is also served by the server as the
`bgphorizon://reference/report-template` resource, so a connected model can pull it
without these files present. Keeping the kit lets you read, adapt, or run
the workflow by hand.

## What good output looks like

A model with this server + system prompt should answer *"is AS54994 doing anything
notable?"* in roughly five tool calls, and produce a report where **every claim traces
to a specific tool result**, persistence is stated before any migration/handover
language, and single-vantage-point signals are flagged rather than trusted. If the
evidence is thin, the report says so instead of reaching.
