"""Prompts (8). The methodology lives here.

Prompts embed the house procedure so a model that has never seen BGP data
produces correct, house-style output without the user pasting instructions. The
two guardrails (persistence, and vantage-point attribution) are the direct fix
for the specific errors documented in the reporting methodology.
"""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP

_GUARDRAILS = """\
Two checks are mandatory before any conclusion:
- PERSISTENCE: classify every prefix (persistent / intermittent / transient) with \
`inventory` or `origin_history` before calling anything a migration or handover. A \
prefix present on a handful of days is transient. Say so.
- ATTRIBUTION: read the `concentration` / `single_vantage_point` warnings; run \
`platform_baseline` before describing anything as anomalous. A spike from one \
collector peer is a measurement artifact.
- COUNTS: state a count only from a complete result. `detections` says `complete` and \
`total_matching`; when complete is false, narrow the window or filter by type until it \
is true. Give every number its denominator.
Read the `warnings[]` on every response and reflect them in the write-up."""

_STYLE = """\
Style. The write-up uses the platform's own plain register; the test is whether a \
network engineer would believe a colleague wrote it.
- One idea per sentence, but vary the length: a run of sentences all the same \
length reads as generated. Lead with the finding.
- Answer, never narrate. Do not restate the question before answering it, and do \
not announce what a section is about to do.
- Let confidence track the evidence: state a firm finding flatly and an unknown \
flatly. Hedging everything to the same degree is the giveaway.
- Never use an em-dash. Never write "not X but Y" or "it's not X, it's Y".
- No filler or editorial adverbs: "actually", "really", "simply", "notably", \
"importantly", "it's worth noting", "keep in mind".
- No "why this matters", "key takeaways" or "in summary" sections, and no section \
ends with a summary paragraph.
- Headings and titles in sentence case, literal and complete ("Reachability during \
the outage"). No puns, teasers, fragments or questions.
- No marketing or color words: "deep dive", "leverage", "robust", "comprehensive", \
"landscape", "classic", "textbook", "red flag", "smoking gun".
- Numbers carry a denominator. Observation and inference are marked as such."""


def register_prompts(mcp: FastMCP) -> None:

    # -- investigator --------------------------------------------------------

    @mcp.prompt(
        name="investigate_entity",
        title="Investigate an ASN or prefix",
        description="Full workup of an ASN or prefix. Findings only, no prose report.",
    )
    def investigate_entity(entity: str, window: str = "90d") -> str:
        return f"""Investigate {entity} over the last {window} and return findings only \
(not a formatted report).

Suggested path (adapt as evidence dictates):
1. `identify`: registry, RPKI, IRR, PeeringDB.
2. `detections` (use `summary_only=true` first on a busy entity): platform findings. \
Read the `direction` field to see whether the entity is the offending or the rightful \
party, and `complete` before quoting any count.
3. For any contested prefix, `origin_history`: day-by-day origins and classified \
transitions. This is where a handover is confirmed or a blip is dismissed.
4. If one network announced other networks' space in a short window (a suspected \
hijack or leak): `origin_episode(asn, start, end)` gives the whole event in one call \
(what was new, whose space, conflicts, carriers, first/last seen). Its \
`summary.peer_buckets` shows whether some prefixes spread widely and others barely; \
treat those as separate groups, and use each prefix's `conflicts` to say where the \
conflict total comes from. Then \
`origin_reach` on two or three of its prefixes for the propagation curve and its \
phases, `timeline(target="asn:...", granularity="10m")` for the prefix count over \
time, `paths(prefix, origin_as=...)` for the leaked routes' paths, and \
`bulk_registry(prefixes, origin_asn=..., as_of=<incident day>, summary_only=true)` for \
RPKI/IRR/holder on every prefix rather than a sample. `notable_events(asn=..., start=..., end=...)` shows how the platform \
ranked it.
5. `identify` any counterpart ASNs/prefixes that surface.
6. `timeline` / `paths` only if volume or transit structure is part of the finding.

{_GUARDRAILS}

Output a concise findings list: each finding with its evidence and a confidence note. \
Plain sentences, no em-dashes, no "not X but Y", no editorial adverbs."""

    @mcp.prompt(
        name="alert_report",
        title="Write up my alerts for a period",
        description="Pull your own monitoring alerts over a window and write them up.",
    )
    def alert_report(window: str = "today", focus: Optional[str] = None) -> str:
        scope = f" Focus the write-up on {focus}." if focus else ""
        return f"""Pull the alerts my monitors fired over: {window}, and write them up.{scope}

Path:
1. `my_alerts(window="{window}")`. This is the whole input. It returns the alerts \
plus totals by detection type, severity and monitor.
2. If the volume is dominated by one monitor or one detection type, call \
`my_monitors(window="{window}")` to say what was under watch and which watches are noisy.
3. Investigate only what the alerts justify: `detections` or `origin_history` on the \
specific prefixes that fired something anomalous. Do not sweep the platform; this is a \
report about MY monitoring, not global routing.

Rules for this write-up:
- Lead with the totals and the window, stated as absolute times from `meta.window`.
- Separate SECURITY findings (RPKI invalid, MOAS, new origin, path anomalies) from \
INFORMATIONAL churn (ROA/IRR changes, unregistered routes, new prefixes). A window that \
is all informational is a quiet period. Say so.
- Attribute volume before generalising: if one monitor produced most alerts, name it.
- If `warnings[]` says the result was truncated, say the per-alert detail is partial.
- If nothing fired, the report is one short paragraph saying so. That is a valid result.

{_GUARDRAILS}

{_STYLE}"""

    @mcp.prompt(
        name="write_report",
        title="Write a full HTML report",
        description="Complete HTML report following the house methodology and template.",
    )
    def write_report(entity: str, window: str = "60d") -> str:
        return f"""Write a complete BGP routing report on {entity} covering: {window}.
(If the window above is unclear or looks cut off, read the caller's message for the \
period they meant; for a named incident, cover the incident plus enough surrounding \
days to show what normal looks like.)

STEP 0. Before any tool call, ask the caller this and then STOP and wait for a \
reply. Do not answer it yourself, do not assume, and do not start the \
investigation until they have answered:

    This tool wants me to ask you the following question:

    Would you like me to run all of my findings by you for confirmation and
    research before I put the report together?

Their answer decides the shape of the work:

- YES: gather the evidence, then stop and walk them through what you found
  BEFORE writing a line of the report. Number the findings, give the evidence
  and your confidence for each, and name what you could not determine. Then wait
  again. Answer their questions, run the extra lookups they ask for, and correct
  anything they contradict. A person who knows the network usually knows why a
  prefix moved, and that is worth more than another query. Only write the report
  once they are done. If their input changed a conclusion, the report carries
  the correction rather than quietly presenting the corrected version.
- NO: run straight through to the finished report.

Anything other than a clear no means yes. The point of the checkpoint is that
the person whose name is on the report understands it before it goes out.

If a `reporting/` directory is available on disk (you cloned the repo, the
recommended setup), use it as the source of truth: read `reporting/WRITING-GUIDE.md`
and `reporting/QA-CHECKLIST.md`, build from `reporting/TEMPLATE.html` +
`reporting/template-assets/report.css`, and run `reporting/build-report.sh` to inline
the CSS, validate the HTML, and render the PDF/PNG. Otherwise, use the equivalent MCP
resources below. They carry the same content.

Procedure (step 0 above comes first and gates all of it):
1. Read the standards first: `bgphorizon://reference/writing-guide`,
   `bgphorizon://reference/qa-checklist`, `bgphorizon://reference/methodology`,
   `bgphorizon://reference/data-horizon`, `bgphorizon://reference/detection-types`,
   `bgphorizon://reference/glossary`.
2. Do the full `investigate_entity` workup to gather evidence. For an incident by one \
   network, build the report on `origin_episode` and take its timing and \
   phases from `origin_reach`; a third-party account (another monitor's post) is a claim to \
   check against them, with any difference in method stated.
2a. If they asked to review first: present the numbered findings and WAIT. Do not
   continue to step 3 until they have said they are done.
3. Fetch `bgphorizon://reference/report-template`. The CSS is **already inlined**,
   so use those styles as-is; do NOT write substitute CSS. Replace every
   {{{{PLACEHOLDER}}}}, delete unused component blocks, keep it valid self-contained HTML.
4. Before finishing, work the QA checklist end to end.

Rules for the write-up:
{_GUARDRAILS}
- Follow the writing guide's "Banned" table without exception. If `reporting/` is on
  disk, `reporting/build-report.sh` runs `style-lint.py` and fails the build on an
  em-dash, a "not X but Y" or a banned word; fix the text rather than the lint.
- Mark observation vs inference explicitly; if your analysis changed mid-investigation,
  record the reversal in a correction block rather than hiding it.
- Lead with the defensible conclusion, then the evidence chain. Every claim traces to a
  specific tool result. Never pattern-match off numerals without a lookup, and use
  complete per-type queries (not a capped page) for any count you state.
- Respect the template's color semantics. Use the glossary's plain-language level.

{_STYLE}"""

    @mcp.prompt(
        name="triage_incident",
        title="Triage a detection",
        description="Fast assessment: real event, measurement artifact, or nothing.",
    )
    def triage_incident(prefix: str, when: Optional[str] = None) -> str:
        window = f"around {when}" if when else "over the last 14 days"
        return f"""Triage {prefix} {window}. Decide: real routing event, measurement \
artifact, or nothing worth escalating.

1. `platform_baseline` first: is the platform unusually busy right now? If the day is \
ordinary, an apparent spike may be nothing.
2. `detections(prefix=...)`: what fired, what severity, anomalous or steady?
3. `origin_history`: did the origin change, or is this one collector's blip?
4. If a new origin appeared: `origin_reach(prefix, origin_as, ...)` shows how far and \
for how long its route propagated; `origin_episode(asn=<new origin>, start=<day>)` shows \
whether it announced other networks' space too.
5. `reachability` (tight window) only if impact is in question. Quantify how many \
peers lost the route and for how long.

{_GUARDRAILS}

End with a one-line verdict (real / artifact / nothing) and the single strongest piece \
of evidence for it."""

    @mcp.prompt(
        name="locate_infrastructure",
        title="Geolocate by routing",
        description="Routing-only geolocation workup with a confidence assessment.",
    )
    def locate_infrastructure(entity: str) -> str:
        return f"""Locate the infrastructure behind {entity} using routing evidence.

1. `locate`: facility/IX intersection across the upstreams' PeeringDB presence.
2. `paths`: confirm the upstream set and look for a single dominant transit that \
anchors the location.
3. `identify` the upstreams to sanity-check they are regional, not global anycast \
transit.

Prefer routing evidence over GeoIP (the `geoip_unavailable` warning explains why). \
State a most-probable location with an explicit confidence level and the basis for it; \
if the upstreams share no common city, say the location is indeterminate rather than \
guessing."""

    # -- operator ------------------------------------------------------------

    @mcp.prompt(
        name="audit_my_network",
        title="Audit my network",
        description="Hygiene report for your ASN with a prioritized remediation list.",
    )
    def audit_my_network(asn: str, window: str = "30d") -> str:
        return f"""Audit AS{asn.lstrip('AS').lstrip('as')} over the last {window} and produce a \
prioritized remediation list a network engineer can act on.

1. `health_check(asn=...)`. This is the audit: RPKI/IRR coverage, MOAS, ROA \
max-length exposure, transit diversity, visibility, unrouted space.
2. `path_diversity(asn=...)`: is transit redundant, or does most of the \
internet reach this network through a single upstream? A dominant branch near 100% \
is a single-point-of-failure worth flagging even when two upstreams are configured. \
Scope to a critical prefix with `prefix=...` to check that route specifically.
3. For any high-severity finding, drill in: `visibility` for filtered prefixes, \
`validate_announcement` to confirm what a fix would need.

Present findings ordered by severity (high → low). For each: what is wrong, which \
prefixes, the operational consequence, and the exact remediation. No BGP jargon \
without a plain-language gloss; the reader may not be a routing specialist. End with \
the top three actions in priority order.

{_STYLE}"""

    @mcp.prompt(
        name="preflight_change",
        title="Pre-flight an announcement",
        description="Go / no-go assessment for an announcement or renumbering.",
    )
    def preflight_change(prefix: str, origin_asn: str) -> str:
        return f"""Pre-flight announcing {prefix} from AS{origin_asn.lstrip('AS').lstrip('as')}.

1. `validate_announcement(prefix=..., origin_asn=...)`: RPKI validity and max-length, \
IRR route objects, which origins announced it in the last 7 days, and whether the \
space was recently transferred (old ROAs linger).
2. If blocked or warned, explain precisely what must change first (create a ROA, \
register a route object, wait for the previous holder's ROA to be withdrawn).

Give a clear go / no-go verdict (clear / warn / blocked), the blockers if any, and the \
ordered list of prerequisites to make the announcement clean."""

    @mcp.prompt(
        name="explain_incident",
        title="Explain an incident to a stakeholder",
        description="Plain-language incident summary for a non-technical audience.",
    )
    def explain_incident(prefix: str, when: Optional[str] = None) -> str:
        window = f"around {when}" if when else "recently"
        return f"""Explain what happened to {prefix} {window} for a non-technical \
stakeholder (management, a customer, a comms team).

Gather the facts first: `detections`, `origin_history`, and `reachability` (tight \
window) to quantify impact. If another network announced the prefix, `origin_reach` \
says how much of the internet took that route and for how long.

Then write 3–5 short paragraphs, no jargon:
- What happened, in one sentence.
- Impact framing: roughly how much of the internet lost reachability, and for how \
long (use the reachability outage windows; "2,289 withdrawals" is not impact).
- Whether anyone else was affected, and whether it looks deliberate or accidental, \
only if the evidence supports it.
- What is being done / what the reader should do.

Do not speculate beyond the evidence. If impact was negligible, say so plainly.

{_STYLE}"""
