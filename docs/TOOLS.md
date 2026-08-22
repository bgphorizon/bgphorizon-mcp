# MCP Tool Schemas

Seventeen tools across two personas:

- **Investigation** (14) — analysing a network you do not run
- **Operator** (3) — watching one you do

Each maps to an analytical operation, not an endpoint.

Common conventions:
- Dates are `YYYY-MM-DD`; datetimes are RFC3339 UTC.
- Every response includes `warnings[]` (may be empty) and `meta` with
  `source` (`rollup` | `raw_events` | `registry`) and `computed_at`.
- Prefixes are plain CIDR — the server handles encoding.

---

## `identify`

Who is this? Registry, RPKI, IRR and PeeringDB in one call.

```jsonc
{ "name": "identify",
  "inputSchema": { "type": "object", "properties": {
    "asn":    { "type": "integer" },
    "prefix": { "type": "string", "description": "CIDR, e.g. 153.43.253.0/24" },
    "include": { "type": "array", "items": { "enum": ["rdap","rpki","irr","peeringdb","whois"] },
                 "default": ["rdap","rpki","irr"] } },
    "anyOf": [{ "required": ["asn"] }, { "required": ["prefix"] }] } }
```

```jsonc
{ "asn": 54994, "name": "ML-1432-54994", "registrant": "Meteverse Limited.",
  "registered": "2023-04-13", "abuse": "abuse@meteversecloud.com",
  "prefix_counts": { "v4": 1272, "v6": 182 },
  "rpki": { "roa_count": 292, "authorized_origins": [54994] },
  "irr":  { "objects": [{ "origin_as": 54994, "source": "ARIN" },
                        { "origin_as": 5693, "source": "RADB", "stale": true }] },
  "peeringdb": { "facilities": [{ "name": "Telehouse - Frankfurt", "city": "Frankfurt", "country": "DE" }],
                 "ix_count": 8 },
  "warnings": [{ "code": "irr_origin_mismatch",
                 "message": "IRR object names AS5693, which was not observed announcing this prefix." }] }
```

Set `include: ["whois"]` for RIPE/ARIN whois fields absent from RDAP —
`org-type`, `address`, `phone`, `mnt-routes`, POC validation status. Those fields
identified a shell entity in one report.

---

## `inventory`

What does this ASN announce, and does it stick?

```jsonc
{ "name": "inventory",
  "inputSchema": { "type": "object", "required": ["asn"], "properties": {
    "asn": { "type": "integer" },
    "from": { "type": "string" }, "to": { "type": "string" },
    "classify": { "type": "boolean", "default": true },
    "min_prefix_len": { "type": "integer", "description": "Filter out host routes, e.g. 24" } } } }
```

```jsonc
{ "asn": 54994, "totals": { "v4": 1272, "v6": 182, "addresses_v4": 291472 },
  "length_distribution": { "22": 2, "23": 4, "24": 1122, "32": 144 },
  "prefixes": [ { "prefix": "153.43.254.0/24", "classification": "persistent",
                  "days_present": 61, "days_in_window": 61, "origins": [54994] } ],
  "warnings": [{ "code": "host_routes_present",
                 "message": "144 IPv4 /32 routes. Widely filtered; exclude from volume baselines." }] }
```

`classification` is server-computed (`persistent` | `transient` | `intermittent`).
**Models must not infer this from `first_seen`.**

---

## `timeline`

Counts over time. Replaces bulk event downloads.

```jsonc
{ "name": "timeline",
  "inputSchema": { "type": "object", "required": ["target","from","to"], "properties": {
    "target": { "type": "string", "description": "asn:54994 or prefix:153.43.254.0/24" },
    "from": { "type": "string" }, "to": { "type": "string" },
    "granularity": { "enum": ["hour","day","week"], "default": "day" },
    "group_by": { "enum": ["none","origin","collector","peer","event_type"], "default": "none" } } } }
```

```jsonc
{ "points": [{ "t": "2026-07-09", "announcements": 2378, "withdrawals": 41,
               "groups": { "33015": 574, "54994": 1804 } }],
  "summary": { "peak": 4997, "peak_at": "2026-07-31", "median": 573, "total": 181885 },
  "concentration": { "top_collector": "route-views.hkix", "top_collector_share": 0.87 },
  "warnings": [{ "code": "single_vantage_point",
                 "message": "87% of the increase after 2026-07-28 comes from one collector peer." }] }
```

`group_by: "origin"` at daily granularity is the handover chart.

---

## `origin_history`

Day-by-day origins for a prefix. **The persistence check.**

```jsonc
{ "name": "origin_history",
  "inputSchema": { "type": "object", "required": ["prefix","from","to"], "properties": {
    "prefix": { "type": "string" }, "from": { "type": "string" }, "to": { "type": "string" } } } }
```

```jsonc
{ "prefix": "153.43.254.0/24",
  "days": [ { "d": "2026-07-08", "origins": { "33015": 47 } },
            { "d": "2026-07-09", "origins": { "33015": 574, "54994": 1804 }, "moas": true },
            { "d": "2026-07-10", "origins": { "54994": 411 } } ],
  "transitions": [ { "from_asn": 33015, "to_asn": 54994, "date": "2026-07-09",
                     "overlap_days": 3, "gap_days": 0, "type": "handover" } ],
  "summary": { "distinct_origins": [33015, 54994], "moas_days": 3 } }
```

`transitions[].type` is `handover` (persistent change), `episode` (reverts), or
`intermittent`. Server-computed. This is the direct fix for the error described in
[`../README.md`](../README.md#why-the-mcp-server-should-not-mirror-the-rest-api).

---

## `reachability`

Who could not reach it, and when.

```jsonc
{ "name": "reachability",
  "inputSchema": { "type": "object", "required": ["prefixes","from","to"], "properties": {
    "prefixes": { "type": "array", "items": { "type": "string" } },
    "from": { "type": "string" }, "to": { "type": "string" },
    "interval": { "enum": ["10s","1m","5m"], "default": "1m" } } } }
```

```jsonc
{ "series": [{ "t": "2026-06-27T05:52:00Z", "peers_tracked": 1323,
               "peers_without_route": 977, "pct_without": 73.8 }],
  "windows": [{ "start": "2026-06-27T05:52:00Z", "end": "2026-06-27T06:11:00Z",
                "duration_seconds": 1140, "peak_pct": 73.8 },
              { "start": "2026-06-27T07:25:00Z", "end": "2026-06-27T07:48:00Z",
                "duration_seconds": 1380, "peak_pct": 74.0 }],
  "warnings": [{ "code": "interval_too_coarse",
                 "message": "Median restore time is 19s; use interval=10s." }] }
```

Accepts multiple prefixes so multi-prefix events resolve in one call.

---

## `detections`

Platform findings, with direction made explicit.

```jsonc
{ "name": "detections",
  "inputSchema": { "type": "object", "properties": {
    "asn": { "type": "integer" }, "prefix": { "type": "string" },
    "from": { "type": "string" }, "to": { "type": "string" },
    "detection_type": { "type": "string" }, "anomalous_only": { "type": "boolean", "default": true } },
    "anyOf": [{ "required": ["asn"] }, { "required": ["prefix"] }] } }
```

```jsonc
{ "incidents": [{ "detection_type": "rpki_invalid_asn", "severity": "high",
                  "prefix": "153.43.253.0/24",
                  "actor_as": 33015, "baseline_asns": [54994],
                  "direction": "queried_entity_is_invalid_party",
                  "peer_count": 164, "state": "resolved",
                  "first_seen": "2026-07-10T00:44:50Z" }],
  "counts_by_type": { "rpki_invalid_asn": 6, "moas_conflict": 12 } }
```

`direction` is the important field. Values:
`queried_entity_is_invalid_party` | `queried_entity_is_baseline` | `third_party`.

Reading `actor_as` against `baseline_asns` incorrectly inverts a report's
conclusion — a court appeared to be a hijack victim when its own announcements
were the invalid ones.

---

## `paths`

Transit structure with prepending resolved.

```jsonc
{ "name": "paths",
  "inputSchema": { "type": "object", "required": ["prefix"], "properties": {
    "prefix": { "type": "string" }, "from": { "type": "string" }, "to": { "type": "string" },
    "group_by_origin": { "type": "boolean", "default": true } } } }
```

```jsonc
{ "upstreams": [{ "asn": 48927, "name": "ESEVEN DevOps GmbH", "share": 0.575 },
                { "asn": 212895, "name": "ROUTE64.ORG", "share": 0.263 }],
  "paths": [{ "path_string": "3491 3356 21799", "count": 10390,
              "origin_as": 21799, "upstream_as": 3356,
              "prepend_count": 0, "collapsed_path": [3491, 3356, 21799] }],
  "observations": [{ "code": "prepending_detected",
                     "message": "AS1600 prepended 3×, indicating a deliberately de-preferred backup path." }] }
```

---

## `relationships`

An ASN's transit hierarchy over a date window: **upstreams** (its providers) and
**downstreams** (its customers), plus observed neighbours of unknown type. Inferred
provider→customer, Tier-1-anchored (~94% agreement with CAIDA). Peering is **not**
inferred — `other_connections` are observed adjacencies, not confirmed peers.

```jsonc
{ "name": "relationships",
  "inputSchema": { "type": "object", "required": ["asn"], "properties": {
    "asn": { "type": "integer" }, "start": { "type": "string" }, "end": { "type": "string" } } } }
```

```jsonc
{ "asn": 15169,
  "window": { "from": "2026-07-19", "to": "2026-08-17" },
  "upstreams":   [{ "asn": 6453, "name": "TATA", "confidence": 0.98, "vantage_count": 310, "days_present": 30 }],
  "downstreams": [{ "asn": 396982, "name": "Google Cloud", "confidence": 0.9, "vantage_count": 42, "days_present": 30 }],
  "other_connections": [{ "asn": 13335, "name": "Cloudflare", "vantage_count": 180, "days_present": 30 }],
  "counts": { "upstreams": 6, "downstreams": 22, "other_connections": 410, "neighbors": 438 },
  "warnings": [{ "code": "peering_not_inferred",
                 "message": "other_connections are observed adjacencies of unknown type, not confirmed peers." }] }
```

---

## `path_diversity`

How an origin's announcements **fan out through its upstreams toward our collectors** — the
observed propagation tree, weighted by how many vantage points take each branch. Built only
from real AS paths (no inference). Each level-1 `share` is the fraction of vantage points
(that see the origin at all) whose path leaves via that upstream: a single branch near `1.0`
= effectively single-threaded through that provider; balanced branches = redundant transit.
`is_tier1` marks where a branch reaches the Tier-1 core. Pass `prefix` (a CIDR the ASN
originates) to scope the tree — and the %s — to one route (e.g. a MOAS prefix). This is the
control-plane route spread, **not a traceroute**: peering and IXP handoffs are invisible to
collectors. `diverse=false` (read `reason`) means single-threaded or too thinly observed.
Default window 14 days.

```jsonc
{ "name": "path_diversity",
  "inputSchema": { "type": "object", "required": ["asn"], "properties": {
    "asn": { "type": "integer" }, "prefix": { "type": "string" },
    "start": { "type": "string" }, "end": { "type": "string" } } } }
```

```jsonc
{ "asn": 44620, "prefix": null, "window": { "from": "2026-08-07", "to": "2026-08-21" },
  "diverse": true, "reason": null, "total_vantage_points": 363,
  "upstreams": [{ "asn": 208972, "name": "…", "share": 0.62, "vantage_points": 225, "is_tier1": false },
                { "asn": 3223, "name": "…", "share": 0.30, "vantage_points": 110, "is_tier1": false }],
  "tree": { "nodes": [{ "asn": 44620, "level": 0, "is_tier1": false, "feeds": 363 }],
            "edges": [{ "inner": 44620, "outer": 208972, "level": 1, "feeds": 225, "share": 0.62 }],
            "max_level": 3 },
  "warnings": [{ "code": "observed_not_traceroute",
                 "message": "Control-plane route spread across upstreams, not a data-plane path." }] }
```

---

## `compare_windows`

Baseline versus event.

```jsonc
{ "name": "compare_windows",
  "inputSchema": { "type": "object", "required": ["target","window_a","window_b"], "properties": {
    "target": { "type": "string" },
    "window_a": { "type": "object", "properties": { "from": {"type":"string"}, "to": {"type":"string"} } },
    "window_b": { "type": "object", "properties": { "from": {"type":"string"}, "to": {"type":"string"} } },
    "dimension": { "enum": ["origin","upstream","collector","volume","paths"], "default": "volume" } } } }
```

---

## `locate`

Facility intersection across upstreams — routing-only geolocation.

```jsonc
{ "name": "locate",
  "inputSchema": { "type": "object", "properties": {
    "asn": { "type": "integer" }, "prefix": { "type": "string" },
    "include_geoip": { "type": "boolean", "default": true } } } }
```

```jsonc
{ "upstreams": [48927, 212895, 34872],
  "facility_intersection": { "all_three": [{ "city": "Frankfurt", "country": "DE",
      "facilities": ["Telehouse - Frankfurt", "NewTelco Frankfurt", "iNTERWERK Rechenzentrum"] }],
    "pairwise": { "48927∩212895": ["Amsterdam NL", "Frankfurt DE", "Singapore SG"] } },
  "geoip": { "ipinfo": "Rotterdam, NL", "ip-api": "London, GB", "db-ip": "London, GB",
             "rdap_country": "EU", "agreement": false },
  "assessment": { "most_probable": "Frankfurt, DE", "confidence": "moderate",
                  "basis": "only city common to all three upstreams" },
  "warnings": [{ "code": "geoip_disagreement",
                 "message": "Geolocation sources disagree across three countries — characteristic of leased space with no stable anchor. Prefer routing evidence." }] }
```

---

## `subprefixes`

```jsonc
{ "name": "subprefixes",
  "inputSchema": { "type": "object", "required": ["prefix"], "properties": {
    "prefix": { "type": "string" }, "from": { "type": "string" }, "to": { "type": "string" } } } }
```

Returns announced more-specifics plus `unrouted_addresses` — allocated space never
seen in the table, which is the easiest kind to announce unnoticed.

---

## `events_sample`

Bounded raw events. **Last resort.**

```jsonc
{ "name": "events_sample",
  "inputSchema": { "type": "object", "required": ["prefix","from","to"], "properties": {
    "prefix": { "type": "string" },
    "from": { "type": "string", "description": "RFC3339; window must be under 24h" },
    "to": { "type": "string" },
    "limit": { "type": "integer", "default": 200, "maximum": 500 },
    "filters": { "type": "object", "properties": {
      "origin_as": {"type":"integer"}, "peer_asn": {"type":"integer"},
      "collector_id": {"type":"string"}, "event_type": {"enum":["announcement","withdrawal"]} } } } } }
```

Rejects windows over 24 hours. Sets `truncated: true` and suggests a narrower
window rather than silently truncating.

---

## `platform_baseline`

Is this unusual, platform-wide?

```jsonc
{ "name": "platform_baseline",
  "inputSchema": { "type": "object", "properties": {
    "window": { "type": "string", "default": "14d" },
    "by": { "enum": ["type","severity"], "default": "type" } } } }
```

Call this **before** describing anything as anomalous. One investigation was
correctly abandoned when platform trends showed the day was entirely normal — the
apparent spike was the platform's ordinary volume.

---
---

# Operator tools

For networks you own or operate. These answer "is my stuff correct and healthy?"
rather than "what is that network doing?". Backed by the same API; see
[`https://bgphorizon.com/docs/mcp`](https://bgphorizon.com/docs/mcp) for the underlying
endpoint sequences.

---

## `health_check`

Full hygiene and exposure audit for an ASN you control. The single most valuable
operator call — it is workflows §1–§4 in one.

```jsonc
{ "name": "health_check",
  "inputSchema": { "type": "object", "required": ["asn"], "properties": {
    "asn": { "type": "integer" },
    "window": { "type": "string", "default": "30d" },
    "checks": { "type": "array",
                "items": { "enum": ["rpki","irr","moas","visibility","transit","unrouted","maxlength"] },
                "default": ["rpki","irr","moas","visibility","transit","unrouted","maxlength"] } } } }
```

```jsonc
{ "asn": 21799, "prefixes_checked": 7,
  "findings": [
    { "check": "rpki", "severity": "high", "affected": ["144.166.53.0/24", "…"],
      "count": 7,
      "detail": "No ROA on any announced prefix. Announcements cannot be validated or rejected.",
      "remediation": "Create ROAs authorising AS21799 with max_length equal to the announced length." },
    { "check": "unrouted", "severity": "high", "affected": ["144.166.0.0/16"],
      "detail": "63,744 of 65,536 allocated addresses are never announced.",
      "remediation": "Publish a covering ROA permitting only the intended more-specifics." },
    { "check": "transit", "severity": "medium", "affected": ["144.166.53.0/24","144.166.176.0/24","144.166.178.0/24"],
      "detail": "Single upstream (AS3356) while four sibling prefixes have two.",
      "remediation": "Extend the second provider to these prefixes." },
    { "check": "moas", "severity": "none", "detail": "No competing origins observed." }
  ],
  "score": { "rpki_coverage": 0.0, "irr_coverage": 0.0, "prefixes_with_moas": 0,
             "single_homed_prefixes": 3 } }
```

Every finding carries `remediation` in operator terms. A model relaying this to a
network engineer should be able to hand over an action list, not a data dump.

`maxlength` deserves emphasis: a ROA on a `/24` with `max_length: 32` authorises
any more-specific under that origin, which is a hijack surface rather than
protection.

---

## `validate_announcement`

Pre-flight check before announcing space, renumbering, or accepting a customer
prefix.

```jsonc
{ "name": "validate_announcement",
  "inputSchema": { "type": "object", "required": ["prefix","origin_asn"], "properties": {
    "prefix": { "type": "string" },
    "origin_asn": { "type": "integer" },
    "check_holder": { "type": "boolean", "default": true } } } }
```

```jsonc
{ "prefix": "198.51.100.0/24", "origin_asn": 64500,
  "rpki": { "status": "invalid", "reason": "ROA exists for AS64501, max_length 24",
            "would_be_rejected_by": "any network performing origin validation" },
  "irr":  { "status": "missing", "detail": "No route object. Providers building filters from IRR have nothing to match." },
  "currently_announced_by": [64501],
  "holder": { "registrant": "Example Corp", "last_changed": "2026-07-02",
              "recently_transferred": true },
  "verdict": "blocked",
  "blockers": [
    "An existing ROA authorises AS64501; announcing from AS64500 will be RPKI-invalid.",
    "Space changed registered holder 40 days ago — the previous holder's ROA is still published."
  ] }
```

`verdict` is `clear` | `warn` | `blocked`. The `recently_transferred` flag exists
because of the ten-month invalid tail observed in the AS54994 report — freshly
transferred space routinely still carries the old holder's ROAs.

---

## `visibility`

Where can the internet see this prefix, and where can it not?

```jsonc
{ "name": "visibility",
  "inputSchema": { "type": "object", "required": ["prefix"], "properties": {
    "prefix": { "type": "string" },
    "compare_to": { "type": "array", "items": { "type": "string" },
                    "description": "Sibling prefixes to baseline against" },
    "window": { "type": "string", "default": "7d" } } } }
```

```jsonc
{ "prefix": "144.166.53.0/24",
  "peers_seeing": 327, "collectors_seeing": 24,
  "peer_baseline": { "median_across_siblings": 330, "ratio": 0.99 },
  "missing_regions": [],
  "upstreams": [{ "asn": 3356, "share": 1.0 }],
  "warnings": [{ "code": "single_upstream",
                 "message": "Reachable through one provider only; siblings 144.166.55.0/24 and 144.166.174.0/24 have two." }] }
```

`compare_to` is the useful part. Absolute peer counts mean little; a prefix seen
by 40 peers when its siblings are seen by 330 is being filtered, and that ratio is
what surfaces it.

---

## Operator prompts

| Prompt | Produces |
|---|---|
| `audit_my_network` | Hygiene report for your ASN with a prioritised remediation list |
| `preflight_change` | Go/no-go assessment for an announcement or renumbering |
| `explain_incident` | Plain-language incident summary for a non-network stakeholder |

`explain_incident` matters more than it sounds. Operators routinely need to tell
management what happened, and "2,289 withdrawals" is not that. The prompt enforces
impact framing: how much of the internet, for how long, and whether anyone else
was affected.
