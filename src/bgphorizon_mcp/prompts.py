"""Prompts (7) — where methodology lives.

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
prefix present on a handful of days is transient — say so.
- ATTRIBUTION: read the `concentration` / `single_vantage_point` warnings; run \
`platform_baseline` before describing anything as anomalous. A spike from one \
collector peer is a measurement artifact.
Read the `warnings[]` on every response and reflect them in the write-up."""


def register_prompts(mcp: FastMCP) -> None:

    # -- investigator --------------------------------------------------------

    @mcp.prompt(
        name="investigate_entity",
        title="Investigate an ASN or prefix",
        description="Full workup of an ASN or prefix — findings only, no prose report.",
    )
    def investigate_entity(entity: str, window: str = "90d") -> str:
        return f"""Investigate {entity} over the last {window} and return findings only \
(not a formatted report).

Suggested path (adapt as evidence dictates):
1. `identify` — who is this? Registry, RPKI, IRR, PeeringDB.
2. `detections` — platform findings, read the `direction` field to see whether the \
entity is the offending or the rightful party.
3. For any contested prefix, `origin_history` — day-by-day origins and classified \
transitions. This is where a handover is confirmed or a blip is dismissed.
4. `identify` any counterpart ASNs/prefixes that surface.
5. `timeline` / `paths` only if volume or transit structure is part of the story.

{_GUARDRAILS}

Output a concise findings list: each finding with its evidence and a confidence note."""

    @mcp.prompt(
        name="write_report",
        title="Write a full HTML report",
        description="Complete HTML report following the house methodology and template.",
    )
    def write_report(entity: str, window: str = "60d") -> str:
        return f"""Write a complete BGP routing report on {entity} covering the last {window}.

If a `reporting/` directory is available on disk (you cloned the repo — the
recommended setup), use it as the source of truth: read `reporting/WRITING-GUIDE.md`
and `reporting/QA-CHECKLIST.md`, build from `reporting/TEMPLATE.html` +
`reporting/template-assets/report.css`, and run `reporting/build-report.sh` to inline
the CSS, validate the HTML, and render the PDF/PNG. Otherwise, use the equivalent MCP
resources below — they carry the same content.

Procedure:
1. Read the standards first: `bgphorizon://reference/writing-guide`,
   `bgphorizon://reference/qa-checklist`, `bgphorizon://reference/methodology`,
   `bgphorizon://reference/data-horizon`, `bgphorizon://reference/detection-types`,
   `bgphorizon://reference/glossary`.
2. Do the full `investigate_entity` workup to gather evidence.
3. Fetch `bgphorizon://reference/report-template` — the house CSS is **already inlined**,
   so use those styles as-is; do NOT write substitute CSS. Replace every
   {{{{PLACEHOLDER}}}}, delete unused component blocks, keep it valid self-contained HTML.
4. Before finishing, work the QA checklist end to end.

Rules for the write-up:
{_GUARDRAILS}
- Follow the writing guide's voice rules — especially the "avoid" table (watch em-dash
  density and "not X but Y"; both read as generated prose).
- Mark observation vs inference explicitly; if your analysis changed mid-investigation,
  record the reversal in a correction block rather than hiding it.
- Lead with the defensible conclusion, then the evidence chain. Every claim traces to a
  specific tool result — never pattern-match off numerals without a lookup, and use
  complete per-type queries (not a capped page) for any count you state.
- Respect the template's colour semantics. Use the glossary's plain-language level."""

    @mcp.prompt(
        name="triage_incident",
        title="Triage a detection",
        description="Fast assessment: real event, measurement artifact, or nothing.",
    )
    def triage_incident(prefix: str, when: Optional[str] = None) -> str:
        window = f"around {when}" if when else "over the last 14 days"
        return f"""Triage {prefix} {window}. Decide: real routing event, measurement \
artifact, or nothing worth escalating.

1. `platform_baseline` first — is the platform unusually busy right now? If the day is \
ordinary, an apparent spike may be nothing.
2. `detections(prefix=...)` — what fired, what severity, is it anomalous or steady?
3. `origin_history` — did the origin actually change, or is this one collector's blip?
4. `reachability` (tight window) only if impact is in question — quantify how many \
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

1. `locate` — facility/IX intersection across the upstreams' PeeringDB presence.
2. `paths` — confirm the upstream set and look for a single dominant transit that \
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
        description="Hygiene report for your ASN with a prioritised remediation list.",
    )
    def audit_my_network(asn: str, window: str = "30d") -> str:
        return f"""Audit AS{asn.lstrip('AS').lstrip('as')} over the last {window} and produce a \
prioritised remediation list a network engineer can act on.

1. `health_check(asn=...)` — this is the audit: RPKI/IRR coverage, MOAS, ROA \
max-length exposure, transit diversity, visibility, unrouted space.
2. `path_diversity(asn=...)` — is transit actually redundant, or does most of the \
internet reach this network through a single upstream? A dominant branch near 100% \
is a single-point-of-failure worth flagging even when two upstreams are configured. \
Scope to a critical prefix with `prefix=...` to check that route specifically.
3. For any high-severity finding, drill in: `visibility` for filtered prefixes, \
`validate_announcement` to confirm what a fix would need.

Present findings ordered by severity (high → low). For each: what is wrong, which \
prefixes, why it matters operationally, and the exact remediation. No BGP jargon \
without a plain-language gloss — the reader may not be a routing specialist. End with \
the top three actions in priority order."""

    @mcp.prompt(
        name="preflight_change",
        title="Pre-flight an announcement",
        description="Go / no-go assessment for an announcement or renumbering.",
    )
    def preflight_change(prefix: str, origin_asn: str) -> str:
        return f"""Pre-flight announcing {prefix} from AS{origin_asn.lstrip('AS').lstrip('as')}.

1. `validate_announcement(prefix=..., origin_asn=...)` — RPKI validity and max-length, \
IRR route objects, who announces it today, and whether the space was recently \
transferred (old ROAs linger).
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
window) to quantify impact.

Then write 3–5 short paragraphs, no jargon:
- What happened, in one sentence.
- Impact framing: roughly how much of the internet lost reachability, and for how \
long (use the reachability outage windows — "2,289 withdrawals" is NOT impact).
- Whether anyone else was affected, and whether it looks deliberate or accidental — \
only if the evidence supports it.
- What is being done / what the reader should do.

Do not speculate beyond the evidence. If impact was negligible, say so plainly."""
