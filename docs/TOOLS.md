# MCP Tool Schemas

Twenty-five tools across three personas:

- **Investigation** (20): analyzing a network you do not run
- **Operator** (3): watching one you do
- **Alerts** (2): reading your own monitoring, for reports

Each maps to an analytical operation, not an endpoint.

Common conventions:
- Dates are `YYYY-MM-DD`; datetimes are RFC3339 UTC.
- Every response includes `warnings[]` (may be empty) and `meta` with
  `source` (`rollup` | `raw_events` | `registry`) and `computed_at`.
- `warnings[]` includes every warning the API returned during the call, so partial
  results (`partial_result`), windows that reach before the data
  (`window_before_data`), raw data older than 90 days (`reduced_vantage_points`) and a
  shortened history (`history_limited`) are always visible. See the data-horizon
  resource.
- A section that could not be read is reported as unavailable (`unavailable`,
  `not_checked`, `sections_unavailable`), never as empty. Do not read it as "none".
- Prefixes are plain CIDR. The server handles encoding.

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

Set `include: ["whois"]` for RIPE/ARIN whois fields absent from RDAP;
`org-type`, `address`, `phone`, `mnt-routes`, POC validation status. Those fields
identified a shell entity in one report.


The result also carries `country` (the registry record's country code) and `rir` (the
registry that answered). IRR objects carry `last_seen` and `current`; an object no longer
in the registry raises `irr_object_deleted`.

A `sections_unavailable` warning names parts of the profile that could not be loaded
(for example RPKI); `rpki.has_rpki` is then null rather than false. `authorized_origins`
for a prefix counts only ROAs whose `max_length` reaches the prefix, so an AS0 or
too-short ROA is never listed as authorizing it.

---

## `inventory`

What does this ASN announce, and does it stick?

```jsonc
{ "name": "inventory",
  "inputSchema": { "type": "object", "required": ["asn"], "properties": {
    "asn": { "type": "integer" },
    "start": { "type": "string" }, "end": { "type": "string" },
    "classify": { "type": "boolean", "default": true },
    "min_prefix_len": { "type": "integer", "description": "Filter out host routes, e.g. 24" },
    "only": { "enum": ["persistent","intermittent","transient"] },
    "summary_only": { "type": "boolean", "default": false } } } }
```

```jsonc
{ "asn": 54994, "window": { "from": "2026-06-12", "to": "2026-08-11" },
  "totals": { "v4": 1272, "v6": 182, "addresses_v4": 291472, "listed": 1454 },
  "by_classification": { "persistent": 1180, "intermittent": 88, "transient": 186 },
  "length_distribution": { "22": 2, "23": 4, "24": 1122, "32": 144 },
  "prefixes": [ { "prefix": "153.43.254.0/24", "classification": "persistent",
                  "days_present": 61, "days_in_window": 61,
                  "first_seen": "2026-06-12", "last_seen": "2026-08-11" } ],
  "warnings": [{ "code": "host_routes_present",
                 "message": "144 IPv4 /32 routes. Widely filtered; exclude from volume baselines." }] }
```

`totals` always describe everything the ASN originated in the window, whatever `only`
or `min_prefix_len` keep in the list (`listed` counts the rows returned).
`addresses_v4` is the union of the IPv4 prefixes, so an aggregate and its
more-specifics are not counted twice.

`classification` is server-computed (`persistent` | `transient` | `intermittent`).
**Models must not infer this from `first_seen`.** Every row is originated by `asn`.
For "what did it announce during an incident, compared with normal", use
`origin_episode` rather than diffing two inventories.
---

## `timeline`

Counts over time. Replaces bulk event downloads.

```jsonc
{ "name": "timeline",
  "inputSchema": { "type": "object", "required": ["target"], "properties": {
    "target": { "type": "string", "description": "asn:54994 or prefix:153.43.254.0/24" },
    "start": { "type": "string", "description": "date, or RFC3339 for sub-day" },
    "end": { "type": "string" },
    "granularity": { "enum": ["day","week","hour","10m","1m"], "default": "day" },
    "group_by": { "enum": ["none","origin","collector"], "default": "none" } } } }
```

```jsonc
{ "points": [{ "t": "2026-07-09", "announcements": 2378, "withdrawals": 41,
               "groups": { "33015": 574, "54994": 1804 } }],
  "summary": { "peak": 4997, "peak_at": "2026-07-31", "median": 573, "total": 181885 },
  "concentration": { "top_collector": "route-views.hkix", "top_collector_share": 0.87 },
  "warnings": [{ "code": "single_vantage_point",
                 "message": "87% of observations come from one collector (route-views.hkix)." }] }
```

`group_by: "origin"` at daily granularity is the handover chart. `hour`, `10m` and
`1m` read raw events over at most 72 hours; for an ASN target each point then
carries `prefixes`, the distinct prefixes it originated in the bucket:

```jsonc
// timeline(target="asn:197207", granularity="10m", start="2026-09-20T09:30:00Z", end="2026-09-20T11:00:00Z")
{ "points": [ { "t": "2026-09-20T09:50:00Z", "prefixes": 133, "withdrawals": null },
              { "t": "2026-09-20T10:00:00Z", "prefixes": 514, "withdrawals": null } ],
  "warnings": [{ "code": "withdrawals_unattributable" }] }
```

Withdrawals carry no AS path, so for ASN targets `withdrawals` is `null`, never 0.
---

## `origin_history`

Day-by-day origins for a prefix. **The persistence check.**

```jsonc
{ "name": "origin_history",
  "inputSchema": { "type": "object", "required": ["prefix"], "properties": {
    "prefix": {"type": "string"},
    "start": {"type": "string"},
    "end": {"type": "string"} } } }
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
  "inputSchema": { "type": "object", "required": ["prefixes"], "properties": {
    "prefixes": {"type": "array", "items": {"type": "string"}},
    "start": {"type": "string"},
    "end": {"type": "string"} } } }
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

Accepts multiple prefixes so multi-prefix events resolve in one call: one prefix
returns its fields at the top level, several return a `results` list. When no ROA
authorizes the prefix at its length for any origin (only AS0 ROAs, or `max_length` too
short), `rpki: "invalid_for_every_origin"` and an `rpki_invalid_prefix` warning say
that routeless peers are mostly networks filtering it, not an outage.

---

## `global_reach`

How widely a prefix is seen, over 30 days.

```jsonc
{ "name": "global_reach",
  "inputSchema": { "type": "object", "required": ["prefix"], "properties": {
    "prefix": { "type": "string" } } } }
```

```jsonc
{ "prefix": "8.8.8.0/24", "reach_pct": 87, "class": "global",
  "seen_feeds": 222, "total_feeds": 253, "window_days": 30,
  "regions": [{ "region": "Europe", "seen": 121, "feeds": 136, "baseline": 128, "pct": 94 },
              { "region": "North America", "seen": 36, "feeds": 46, "baseline": 44, "pct": 81 }] }
```

Only full-table feeds count, so `seen_feeds` never exceeds `total_feeds`. Each feed belongs
to one collector region, and the regions add up to the totals. A region's `pct` is `seen`
over `baseline`, the number of that region's feeds a widely routed prefix typically
reaches, so 100% means as visible there as a typical global route. Region is where the
collector sits, not where the announcing network is.

---

## `detections`

Platform findings, with direction made explicit, paged to completion.

```jsonc
{ "name": "detections",
  "inputSchema": { "type": "object", "properties": {
    "asn": { "type": "integer" }, "prefix": { "type": "string" },
    "start": { "type": "string" }, "end": { "type": "string" },
    "detection_type": { "type": "string" }, "anomalous_only": { "type": "boolean", "default": true },
    "prefix_status": { "type": "string" }, "role": { "enum": ["actor","baseline"] },
    "state": { "enum": ["active","resolved"] },
    "max_incidents": { "type": "integer", "default": 1000, "maximum": 5000 },
    "offset": { "type": "integer", "default": 0 },
    "summary_only": { "type": "boolean", "default": false },
    "format": { "enum": ["auto","full","compact"], "default": "auto" } },
    "anyOf": [{ "required": ["asn"] }, { "required": ["prefix"] }] } }
```

```jsonc
{ "total_matching": 450, "offset": 0, "returned": 450, "next_offset": null, "complete": true,
  "counts_by_type": { "origin_mismatch_new": 450 },
  "summary": { "by_type_and_direction": { "origin_mismatch_new":
                 { "queried_entity_is_invalid_party": 428, "queried_entity_is_baseline": 22 } },
               "opened_by_hour": { "2026-09-20T09": 13, "2026-09-20T10": 415 },
               "distinct_prefixes": 450, "distinct_baseline_asns": 61,
               "peer_count": { "min": 1, "median": 32, "max": 208 } },
  "incidents": [{ "detection_type": "rpki_invalid_asn", "severity": "high",
                  "prefix": "153.43.253.0", "prefix_len": 24,
                  "actor_as": 33015, "baseline_asns": [54994],
                  "direction": "queried_entity_is_invalid_party",
                  "details": { "origin": 33015, "covering_vrps": [ ... ] } }] }
```

`format` controls the incident list. `full` lists each incident with `details`.
`compact` returns `incidents_compact`: a `columns` list (detection_type, prefix,
actor_as, baseline_asns, direction, severity, state, first_seen, last_seen,
peer_count) and one row per incident, without details, about a quarter of the size.
`auto` is full up to 200 incidents and compact above that, with a
`compact_incidents` warning. Counts and `summary` are the same in every format.

`direction` is the important field. Values:
`queried_entity_is_invalid_party` | `queried_entity_is_baseline` |
`queried_entity_announced_own_space` | `third_party`. The own-space value is a network
announcing inside space it already holds (for example a new, smaller prefix of its
own block); it is neither the victim nor the offender.

Reading `actor_as` against `baseline_asns` incorrectly inverts a report's
conclusion: a court appeared to be a hijack victim when its own announcements
were the invalid ones.

`complete: false` means `max_incidents` was reached before every match was read.
`next_offset` is then set: call again with the same arguments and
`offset: next_offset` to read the next batch, until `next_offset` is `null`. Counts
and `summary` describe only the incidents in one call, so add batches up or narrow
the window or `detection_type` before stating a total. `max_incidents` counts
incidents returned, and some API positions can hold incidents your plan does not
include, so `next_offset` can be larger than `offset + returned`.
---

## `paths`

Transit structure with prepending resolved.

```jsonc
{ "name": "paths",
  "inputSchema": { "type": "object", "required": ["prefix"], "properties": {
    "prefix": {"type": "string"},
    "start": {"type": "string"},
    "end": {"type": "string"},
    "origin_as": {"type": "integer"} } } }
```

```jsonc
{ "upstreams": [{ "asn": 48927, "origin_as": 21799, "sessions": 196, "share": 0.575 },
                { "asn": 212895, "origin_as": 21799, "sessions": 90, "share": 0.263 }],
  "direct_share": 0.0,
  "paths": [{ "path_string": "3491 3356 21799", "count": 10390,
              "origin_as": 21799, "upstream_as": 3356,
              "prepend_count": 0, "collapsed_path": [3491, 3356, 21799] }],
  "observations": [{ "code": "prepending_detected",
                     "message": "AS1600 prepended 3×, indicating a deliberately de-preferred backup path." }] }
```

`upstreams` count collector sessions: each session once, through the upstream in its
latest announcement in the window (the last 31 days of it at most; a longer window adds
`upstreams_window_cut`). Each row names the origin it carried; on a contested prefix pass
`origin_as` for one origin's mix, since without it a session contributes only its latest
route. A path that is the origin alone (its own session with a route collector) is not an
upstream: it counts toward `direct_share` and has `upstream_as: null` in `paths`. When
every session is like that the response warns `direct_session_only`: nothing but the origin
itself was seen carrying the route.

Path `count` is update volume, which one noisy peer can dominate: use `paths` for which
routes exist, and `upstreams` for how common they are. If the session count is unavailable,
`upstreams` falls back to update shares with an `upstreams_by_updates` warning.

---

## `relationships`

An ASN's inferred transit hierarchy over a window: **upstreams** (its providers) and
**downstreams** (its customers), plus **other_connections**, observed adjacencies whose
type is unknown. Provider→customer is inferred Tier-1-anchored (~94% agreement with CAIDA);
peering is **not** inferred, so `other_connections` are never presented as confirmed peers.
Each row carries `confidence`, `vantage_count` (distinct collector+peer feeds), and
`days_present`. Results reflect the window; relationships change over time.

```jsonc
{ "name": "relationships",
  "inputSchema": { "type": "object", "required": ["asn"], "properties": {
    "asn": {"type": "integer"},
    "start": {"type": "string"},
    "end": {"type": "string"},
    "max_per_group": {"type": "integer", "default": 50, "minimum": 1, "maximum": 5000} } } }
```

```jsonc
{ "asn": 15169, "window": { "from": "2026-07-22", "to": "2026-08-21" },
  "upstreams": [{ "asn": 174, "name": "Cogent", "confidence": 0.98, "vantage_count": 220, "days_present": 30 }],
  "downstreams": [{ "asn": 396982, "name": "Google Cloud", "confidence": 0.98, "vantage_count": 180, "days_present": 30 }],
  "other_connections": [{ "asn": 3356, "name": "Level 3", "vantage_count": 140, "days_present": 30 }],
  "counts": { "upstreams": 6, "downstreams": 22, "other_connections": 394, "neighbors": 422 },
  "warnings": [{ "code": "peering_not_inferred",
                 "message": "other_connections are observed adjacencies of unknown type, not confirmed peers." }] }
```


Each list is strongest first and capped at `max_per_group` (default 50; a
`lists_truncated` warning says when); `counts` always cover everything.

`data_through` is the newest day the relationship data covers. When the window
ends later the response carries `relationships_stale`; when it lies entirely past
the data, `served_window` says which days were used.

---

## `path_diversity`

How an origin's announcements **fan out through its upstreams toward our collectors**: the
observed propagation tree, weighted by how many vantage points take each branch. Built only
from real AS paths (no inference). Each level-1 `share` is the fraction of vantage points
(that see the origin at all) whose path leaves via that upstream: a single branch near `1.0`
= effectively single-threaded through that provider; balanced branches = redundant transit.
`is_tier1` marks where a branch reaches the Tier-1 core. Pass `prefix` (a CIDR the ASN
originates) to scope the tree, and the percentages, to one route (e.g. a MOAS prefix). This is the
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

## `translate_communities`

Decode raw BGP community strings into meaning, from a dictionary harvested from operators'
own IRR objects + NLNOG (ISC) + the IANA/RFC well-knowns. `known:false` = no published
definition (don't guess); the owner AS (left side) is still named, which is useful on its own.
`inferred:true` marks a near-universal convention (e.g. any `:666`/`:9999` = blackhole), not
something the owner published. `matched_by` is the wildcard pattern that matched, if any.

```jsonc
{ "name": "translate_communities",
  "inputSchema": { "type": "object", "required": ["communities"], "properties": {
    "communities": { "type": "array", "items": { "type": "string" },
                     "description": "e.g. [\"3356:2065\", \"1299:2731\", \"30844:666\"]" } } } }
```

```jsonc
{ "results": [
    { "community": "3356:2065", "known": true, "owner_asn": 3356, "owner_name": "Lumen",
      "category": "informational", "subtype": "geo", "description": "FRF1 - Frankfurt",
      "geo": "Frankfurt", "source": "nlnog" },
    { "community": "30844:666", "known": true, "owner_asn": 30844, "owner_name": "Liquid Telecom",
      "category": "action", "subtype": "blackhole",
      "description": "Blackhole (RTBH): discard traffic to this prefix. Inferred from the common :666 convention…",
      "inferred": true, "source": "convention" },
    { "community": "64500:12", "known": false, "owner_asn": 64500, "owner_name": null } ],
  "warnings": [{ "code": "unknown_communities_not_guessed",
                 "message": "Communities with known=false have no published definition; the owner AS is still named." }] }
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

Where is a network or prefix physically reached? Routing-only geolocation, strongest
evidence first: geo-ingress communities (where upstreams tag the routes as received,
weighted by observations over 30 days), the origin's own PeeringDB facilities, then
cities common to 2+ upstreams' IX presence.

```jsonc
{ "name": "locate",
  "inputSchema": { "type": "object", "properties": {
    "asn": {"type": "integer"},
    "prefix": {"type": "string"} } } }
```

```jsonc
// locate(asn=21799)
{ "target": "AS21799", "origin_as": 21799,
  "assessment": { "classification": "regional", "most_probable": "Los Angeles",
                  "alternatives": ["San Jose"], "confidence": "moderate",
                  "basis": "leading geo-ingress locations" },
  "ingress": [{ "city": "Los Angeles", "country": null, "observations": 39838, "share": 0.486,
                "carriers": [3356, 3491, 6453] },
              { "city": "San Jose", "country": null, "observations": 28423, "share": 0.347,
                "carriers": [1299, 3356, 3491, 6453] }],
  "own_facilities": [], "own_facility_count": 0,
  "upstreams": [], "upstream_common_cities": [],
  "warnings": [{ "code": "routing_evidence", "message": "Ingress shows where upstreams receive the routes ..." }] }
```

`assessment.classification` is `concentrated` (one place carries at least half of the
evidence), `regional` (a few leading places), `distributed` (many places with no
dominant one: anycast or a multi-site network, so `most_probable` is null) or
`insufficient_evidence`. A place is never chosen without evidence for it; with a single
upstream the upstream intersection carries no information and says so
(`single_upstream`). Ingress is where upstreams receive the routes, usually the
network's interconnection point rather than where its hosts are.

---

## `subprefixes`

```jsonc
{ "name": "subprefixes",
  "inputSchema": { "type": "object", "required": ["prefix"], "properties": {
    "prefix": {"type": "string"},
    "start": {"type": "string"},
    "end": {"type": "string"},
    "max_listed": {"type": "integer", "default": 200, "minimum": 1, "maximum": 1000} } } }
```

Returns announced more-specifics plus `unrouted_addresses_estimate`: addresses in the
block that no announcement covers, which are the easiest kind to announce unnoticed.
The estimate is the block minus the union of announced more-specifics. When the block
itself or a less-specific prefix is announced, every address is routed, the estimate
is 0 and `covered_by` names that route. `unrouted_examples` lists up to 10 gap CIDRs.

```jsonc
{ "prefix": "104.27.16.0/20", "subprefixes": [], "count": 0,
  "covered_by": ["104.27.16.0/20"], "unrouted_addresses_estimate": 0,
  "unrouted_examples": [], "warnings": [] }
```

The listing is capped at `max_listed` (default 200, most announced first;
`subprefixes_listed_partially` says when); `count` and the estimate use every fetched
more-specific. A `subprefixes_truncated` warning means more more-specifics exist than were fetched
(1,000), so the estimate may overstate the gap.

---

## `events_sample`

Bounded raw events, newest first. **Last resort.**

```jsonc
{ "name": "events_sample",
  "inputSchema": { "type": "object", "required": ["prefix","start","end"], "properties": {
    "prefix": { "type": "string" },
    "start": { "type": "string", "description": "date or RFC3339; window must be under 24h" },
    "end": { "type": "string" },
    "limit": { "type": "integer", "default": 200, "maximum": 500 },
    "origin_as": {"type":"integer"}, "peer_asn": {"type":"integer"},
    "collector_id": {"type":"string"}, "event_type": {"enum":["announcement","withdrawal"]} } } }
```

Filters are applied by the server, so `origin_as=197207` on a prefix with 30,000
other messages still returns the matching ones. Rejects windows over 24 hours.
Sets `truncated: true` and gives `matching` (the total) rather than silently
truncating.
---

## `platform_baseline`

Is this unusual, platform-wide?

```jsonc
{ "name": "platform_baseline",
  "inputSchema": { "type": "object", "properties": {
    "window": { "type": "string", "default": "14d" },
    "by": { "enum": ["type","severity"], "default": "type" },
    "day": { "type": "string", "description": "YYYY-MM-DD; default the latest full day" } } } }
```

```jsonc
{ "day": "2026-09-23",
  "series": { "origin_mismatch_new": { "day_count": 6213, "median": 4136, "ratio_to_median": 1.5 } } }
```

Exact daily counts, not a sample. Call this **before** describing anything as
anomalous. One investigation was correctly abandoned when platform trends showed
the day was entirely normal; the apparent spike was the platform's ordinary volume.

---

## `notable_events`

A scored feed of possible hijacks and leaks across the internet: one network
announcing address space another network normally originates. **Leads, not verdicts.**

```jsonc
{ "name": "notable_events",
  "inputSchema": { "type": "object", "properties": {
    "hours": { "type": "integer", "default": 24, "minimum": 1, "maximum": 168 },
    "limit": { "type": "integer", "default": 25, "minimum": 1, "maximum": 100 },
    "asn": { "type": "integer" },
    "start": { "type": "string" }, "end": { "type": "string" } } } }
```

```jsonc
{ "window_hours": 24, "count": 1,
  "events": [{ "announcing_as": 197207, "usual_origin_as": 25306, "prefix_count": 450,
               "sample_prefix": "185.192.8.0/22", "signals": ["origin_mismatch_new", "moas_conflict"],
               "possible_leak": false, "announcing_as_allocated": true,
               "severity": "high", "score": 87.5,
               "first_seen": "…", "last_seen": "…", "family": "ipv4" }],
  "warnings": [{ "code": "leads_not_verdicts", "message": "…" }] }
```

The live feed covers the last `hours`. For a past incident pass `start`/`end` (dates or
RFC3339, within the last 90 days, at most 31 days wide) and/or `asn` (as announcer or
usual origin). A more prominent victim, more corroborating detectors and more affected
prefixes raise the score; likely leaks (`possible_leak`: the two networks are related)
and shared or leased space lower it. `announcing_as_allocated` is false when no RIR
allocates the announcer (null when unknown). Such an announcer is a forged or corrupted
origin, not a network; these events rank lower and add an `unallocated_announcer`
warning. `usual_origin_as` skips unallocated ASNs in the baseline. Before describing an event as a
hijack, `identify` both ASNs, run `origin_episode` for the announcer, and pull the
prefix's history.

---

## `origin_episode`

What did one network originate during a short window that it does not normally
originate, and whose space was it? Start here for a hijack or leak report.

```jsonc
{ "name": "origin_episode",
  "inputSchema": { "type": "object", "required": ["asn", "start"], "properties": {
    "asn": {"type": "integer"},
    "start": {"type": "string", "description": "First episode day, YYYY-MM-DD"},
    "end": {"type": "string"},
    "baseline_days": {"type": "integer", "default": 28, "minimum": 7, "maximum": 60},
    "after_days": {"type": "integer", "default": 3, "minimum": 0, "maximum": 14},
    "list_prefixes": {"type": "boolean", "default": true},
    "min_peers": {"type": "integer", "default": 0, "minimum": 0},
    "max_prefixes": {"type": "integer", "default": 100, "minimum": 1, "maximum": 5000},
    "min_baseline_days": {"type": "integer", "default": 3, "minimum": 1, "maximum": 28} } } }
```

```jsonc
// origin_episode(asn=197207, start="2026-09-20")
{ "summary": { "prefixes_in_window": 1264, "new_in_window": 447,
               "new_own_space": 28, "new_other_space": 419,
               "first_seen": "2026-09-20T09:56:25.000Z", "last_seen": "2026-09-20T10:26:33.000Z",
               "max_peers": 323, "reference_peers": 83,
               "exact_conflicts": 78, "conflicts": 10179, "conflict_asns": 1483,
               "peer_buckets": [{ "peers": "1-9", "prefixes": 334 }, { "peers": "10-49", "prefixes": 10 },
                                { "peers": "50-99", "prefixes": 35 }, { "peers": "100-199", "prefixes": 0 },
                                { "peers": "200+", "prefixes": 40 }] },
  "carriers": [{ "asn": 49666, "prefixes": 419, "is_inferred_provider": true }],
  "holders":  [{ "asn": 25306, "relation": "exact", "prefixes": 42 }],
  "prefixes_available": 447,
  "prefixes": [{ "prefix": "151.234.128.0/17", "space": "other", "peers": 323,
                 "first_seen": "2026-09-20T10:03:12.000Z", "conflicts": 35, "conflict_asns": 1 }] }
```

`conflicts` counts prefix/origin pairs by other networks equal to or inside the
other-space prefixes during the episode, which is how public monitors count a
hijack's reach. Each other-space prefix also carries its own `conflicts` and
`conflict_asns` (nested prefixes each count what is under them, so these do not add
up to the total). Covering holders need 2+ baseline days; default routes and blocks
shorter than /8 (v4) or /16 (v6) never count.

A prefix counts as normal only if the ASN originated it on at least
`min_baseline_days` (default 3) comparison days, and only such blocks make "own
space". A prefix seen on fewer days is still listed, with `baseline_days` giving the
count, so a network that re-announces someone else's space every few weeks is not
hidden by its earlier occurrence. `start`/`end` are dates; an RFC3339 time is accepted
and its date used. A `window_before_data` warning means the baseline reaches before
the per-ASN data (2026-01-04), which would make old prefixes look new.

`peer_buckets` counts other-space prefixes by how many peers saw them, which shows a
split between widely and narrowly propagated routes at a glance. The listing puts
other-space prefixes first, most widely seen first, and stops at `max_prefixes`
(`prefixes_available` is the full count, and a `prefixes_truncated` warning says when
it was cut). `min_peers` lists only prefixes seen by at least that many peers.

---

## `origin_reach`

Propagation curve for one prefix and one origin.

```jsonc
{ "name": "origin_reach",
  "inputSchema": { "type": "object", "required": ["prefix","origin_as","start","end"], "properties": {
    "prefix": { "type": "string" }, "origin_as": { "type": "integer" },
    "start": { "type": "string" }, "end": { "type": "string" },
    "interval_seconds": { "type": "integer", "default": 60 } } } }
```

```jsonc
{ "full_table_feeds": 254,
  "summary": { "peak_pct": 88, "peak_at": "2026-09-20T10:18:00Z",
               "first_held": "2026-09-20T10:03:12Z", "last_held": "2026-09-20T10:26:42Z" },
  "phases": [ { "from": "2026-09-20T10:04:00Z", "to": "2026-09-20T10:10:00Z", "peak_pct": 45 },
              { "from": "2026-09-20T10:17:00Z", "to": "2026-09-20T10:26:00Z", "peak_pct": 88 } ],
  "warnings": [{ "code": "multiple_phases" }] }
```

`pct` uses the same full-table-feed denominator as `global_reach`. At most 48 hours.
`summary.propagated_sessions` counts the sessions that saw the route through another
network; when it is 0 the route was only on the origin's own collector sessions and the
response warns `direct_session_only`.
Built for new routes: a long-established route is undercounted (sessions that carried
it throughout without an update are not seen) and the response warns
`route_predates_window`.

---

## `bulk_registry`

RPKI, IRR and RDAP for many prefixes and ASNs, with an RPKI verdict per prefix.

```jsonc
{ "name": "bulk_registry",
  "inputSchema": { "type": "object", "properties": {
    "prefixes": { "type": "array", "items": { "type": "string" } },
    "origin_asn": { "type": "integer" },
    "asns": { "type": "array", "items": { "type": "integer" } },
    "as_of": { "type": "string", "description": "YYYY-MM-DD" },
    "summary_only": { "type": "boolean", "default": false } } } }
```

```jsonc
{ "rpki_summary": { "origin_asn": 197207, "valid": 0, "invalid": 0, "not_found": 3, "checked": 3 },
  "prefixes": [{ "prefix": "185.192.8.0/22", "rpki": "not_found", "irr_origins": [42990],
                 "irr_matches_origin": false,
                 "rdap": { "name": "IR-BANKSADERAT-20170227", "country": "IR", "rir": "RIPE NCC",
                           "name_source": "rdap" } }] }
```

RDAP comes from the platform's cache, or is looked up at the registry live when the cache
has no exact, current record. Live lookups count against the account's daily allowance of
registration lookups (shared by all its keys; cached answers are free). Past it, entries
carry `rdap_lookup: limit_reached` and the response an `rdap_live_limit` warning, and the
name comes from stored data instead. When nothing is
cached, `rdap.name` is a stored name instead and `name_source` says where it came
from: `irr` (a route object's descr for the prefix or a covering one), or for ASNs
`peeringdb`, `irr` or `delegated`. `approximate: true` means the RDAP record is the
registration containing the prefix, not a lookup of the prefix itself, so a more
specific reassignment may exist.

`rpki` is `valid`, `invalid`, `not_found`, or `unavailable` when the RPKI data could
not be read for that prefix (the entry's `error` says which sections failed; its
`irr_origins` is null when IRR could not be read). Never read `unavailable` as
not_found.

IRR origins list only objects still in the registry; deleted ones appear under
`irr_deleted_origins`. For a past incident pass `as_of`: holders often publish ROAs
soon after an incident, and today's ROAs would then call the incident's routes
RPKI-invalid when at the time they were not found.

`summary` counts the whole set: `prefixes`, `with_roas`, `with_irr_objects`,
`irr_matches_origin`, `by_rir` and `by_country` (top 15). With `summary_only=true`
the per-prefix list is replaced by `notable_prefixes`, the ones with a ROA, an IRR
object naming `origin_asn`, or an error (at most 200).
Each 200 items is one API request.
---
---

# Operator tools

For networks you own or operate. These answer "is my stuff correct and healthy?"
rather than "what is that network doing?". Backed by the same API; see
the operator workflows in the BGPHorizon API docs for the underlying
endpoint sequences.

---

## `health_check`

Full hygiene and exposure audit for an ASN you control. The single most valuable
operator call. It is workflows §1–§4 in one.

```jsonc
{ "name": "health_check",
  "inputSchema": { "type": "object", "required": ["asn"], "properties": {
    "asn": { "type": "integer" },
    "window": { "type": "string", "default": "30d" },
    "checks": { "type": "array",
                "items": { "enum": ["rpki","irr","moas","visibility","transit","unrouted","maxlength"] },
                "default": ["rpki","irr","moas","visibility","transit","unrouted","maxlength"] },
    "detail": { "enum": ["summary","full"], "default": "summary" } } } }
```

```jsonc
{ "asn": 21799, "prefixes_checked": 7,
  "findings": [
    { "check": "rpki_invalid", "severity": "high", "count": 1,
      "affected": ["144.166.60.0/24"],
      "prefixes": [{ "prefix": "144.166.60.0/24", "persistence": "persistent", "days_present": 31,
                     "holder": "Example University", "holder_is_asn": true, "basis": "registrant_handle",
                     "holder_source": "rdap", "state": "invalid", "reason": "as0",
                     "covering_roas": [{ "cidr": "144.166.60.0/23", "origin_asn": 0, "max_length": 23 }] }],
      "breakdown": { "reason": { "as0": 1 }, "persistence": { "persistent": 1 }, "holder_is_asn": { "true": 1 } },
      "detail": "1 announced prefixes are RPKI-invalid: a ROA covers them but none authorizes AS21799 at that length …",
      "remediation": "1 are covered only by AS0 ROAs, the holder's 'do not route' marker. Either the holder replaces …" },
    { "check": "rpki", "severity": "medium", "count": 6, "affected": ["144.166.53.0/24", "…"],
      "prefixes": [{ "prefix": "144.166.53.0/24", "persistence": "persistent", "days_present": 31,
                     "holder": "Example University", "holder_is_asn": true, "basis": "registrant_handle",
                     "holder_source": "rdap", "state": "not_found" },
                   { "prefix": "198.51.100.0/24", "persistence": "transient", "days_present": 1,
                     "holder": "Customer Corp", "holder_is_asn": false, "basis": "registrant_handle",
                     "holder_source": "rdap", "state": "not_found" }],
      "breakdown": { "persistence": { "persistent": 5, "transient": 1 },
                     "holder_is_asn": { "true": 4, "false": 1, "unknown": 1 } },
      "detail": "6 of 7 announced prefixes have no ROA covering them (RPKI NotFound) …",
      "remediation": "Create ROAs authorizing AS21799 … for the 4 steadily announced prefixes in your own or unconfirmed space. 1 prefixes are registered to other organizations (e.g. Customer Corp) … 1 were announced on only part of the window …" },
    { "check": "irr", "severity": "low", "count": 3,
      "prefixes": [{ "prefix": "144.166.53.0/24", "state": "covered_by_less_specific",
                     "covering_object": "144.166.0.0/16", "persistence": "persistent", "days_present": 31 }],
      "breakdown": { "state": { "covered_by_less_specific": 3 }, "…": "…" } },
    { "check": "maxlength", "severity": "medium", "count": 1,
      "prefixes": [{ "prefix": "144.166.0.0/16", "max_length": 32, "announced_inside": 3,
                     "suggested_max_length": 24, "holder": "Example University", "holder_is_asn": true }] },
    { "check": "unrouted", "severity": "low", "affected": ["144.166.0.0/16"],
      "gaps": [{ "allocation": "144.166.0.0/16", "unrouted_addresses": 63744,
                 "gaps": ["144.166.0.0/19", "…"], "truncated": false }] },
    { "check": "moas", "severity": "high", "count": 1, "source": "detections",
      "prefixes": [{ "prefix": "144.166.53.0/24", "other_origins": [64500],
                     "baseline_origins": [21799], "anomalous_origins": [64500], "relations": {},
                     "other_origin_names": { "64500": "Example Transit" }, "same_org_origins": [],
                     "classification": "anomalous", "active": false,
                     "first_seen": "…", "last_seen": "…", "incidents": 2 }],
      "breakdown": { "classification": { "anomalous": 1 } } },
    { "check": "transit", "severity": "high", "count": 7,
      "prefixes": [{ "prefix": "144.166.53.0/24", "kind": "single_homed", "neighbor": 3356,
                     "neighbor_name": "LEVEL3", "relationship": "provider", "unique_peers": 290,
                     "persistence": "persistent", "days_present": 31 }],
      "breakdown": { "kind": { "single_homed": 7 }, "relationship": {}, "persistence": { "persistent": 7 },
                     "top_lone_neighbors": {} } },
    { "check": "visibility", "severity": "medium", "count": 1,
      "prefixes": [{ "prefix": "144.166.60.0/24", "unique_peers": 40, "family_median": 300,
                     "ratio": 0.13, "persistence": "persistent", "likely_reasons": ["rpki_invalid"] }],
      "family_median_peers": { "v4": 300, "v6": null } }
  ],
  "score": { "rpki_coverage": 0.143, "irr_coverage": 0.571, "prefixes_with_moas": 1,
             "single_homed_prefixes": 3 },
  "warnings": [] }
```

Every finding carries `remediation` in operator terms, phrased per group, so a model
relaying this to a network engineer can hand over an action list, not a data dump.

**Nothing is filtered out; rows are annotated instead.** Every affected prefix is
counted in `count` and `breakdown`. With `detail: "summary"` (the default) each
finding lists in `prefixes` the rows that need action, and summarizes the rest with
`other_examples` (up to 10) and a `note` saying how many were summarized: rows in
another organization's space (only it can act), IRR rows already covered by a
less-specific object, selective transit, thin visibility explained by short-lived or
single-neighbor announcements, and steady MOAS (only baseline origins, such as a sibling
ASN). `detail: "full"` lists up to 250 rows
per finding. For a large network this is the difference between about 55 KB and
over 200 KB. The `rpki`, `rpki_invalid`, `irr` and `maxlength` rows carry:

- `persistence` and `days_present` for the window (`persistent`, `intermittent`,
  `transient`). A one-day announcement stays in the list, labelled, because it may be
  a leak or misconfiguration worth investigating; the remediation asks to confirm it
  was intended rather than to register it.
- `holder`: who is registered for the space, and `holder_is_asn`: `true` (your own
  space), `false` (another organization's; only it can publish ROAs, so the
  remediation says to ask it), or `null` (unknown). `basis` says how that was decided:
  `registrant_handle` (the prefix and the ASN share an RDAP registrant, same RIR) or
  `name` (the organization's first name word appears in the prefix's record). A name
  that does not match gives `null`, never `false`. `holder_source` is `rdap`, or `irr`
  / `peeringdb` when no RDAP record is cached yet and a stored name was used.
  `holder_approximate` means the RDAP record is the registration containing the prefix
  rather than a lookup of the prefix itself.

**`rpki_invalid`** (high) is separate from **`rpki`** (NotFound, medium). An invalid
route is dropped by networks performing origin validation; NotFound is only
unprotected. `reason` is `as0` (covered only by AS0 ROAs, the holder's "do not route"
marker), `max_length` (a ROA names your ASN but not at this length), or
`other_origin`. `covering_roas` lists the ROAs responsible.

**`irr`** rows carry a `state`: `missing` (no route object with your origin),
`covered_by_less_specific` (a less-specific object for your ASN covers it, with
`covering_object`; filters that accept more-specifics pass it, exact-match filters do
not), or `other_origin_only` (objects exist, for `object_origins` only). Severity is
`low` when every row is covered by a less-specific object.

**`maxlength`** rows give `announced_inside` (how many prefixes you originate inside
the ROA) and `suggested_max_length` (the longest of them). `announced_inside: 0` is a
ROA authorizing you for space you do not announce at all.

**`transit`** covers every prefix (no sampling), from each prefix's first-hop neighbors
as seen by the route collectors. A neighbor counts only with at least 1% of the
prefix's announcements, so a stray path is not a second provider. Rows are prefixes
with at most one such neighbor, labelled by `kind`: `single_homed` (the whole network
has one neighbor: a real single point of failure, severity high), `selective` (the
network has others but this prefix uses one, usually a deliberate regional or
traffic-engineered announcement, severity low), or `direct_sessions_only` (seen only
on direct sessions with collectors). `relationship` is how the lone neighbor relates to
you from inferred AS relationships (`provider`, `customer`, `other`); a prefix seen only
through a customer raises severity to medium. `top_lone_neighbors` groups the
selective rows by neighbor.

Neighbor shares are weighted by update volume, and older data did not record the
neighbor on paths where the origin prepended (`prepended_share` in the API), so a backup
provider can be hidden. Up to 30 rows are therefore re-checked against collector sessions:
first those with prepended paths (marked `neighbors_uncertain`, since the prepends may go
through a backup or through the same provider), then those that carry a recommendation
(`single_homed`, `direct_sessions_only`, customer-only). A row whose sessions show a second
neighbor at 1% or more is dropped and counted in the detail; the rest are marked
`verified_by_sessions`. A neighbor found this way counts toward the network-wide total, so
`single_homed` becomes `selective` when the network turns out to have two. Uncertain rows
beyond the limit keep their mark and are counted in the detail.

**`visibility`** compares each prefix's collector peers with the median of your
persistent prefixes in the same address family (IPv4 and IPv6 separately, needing at
least 5), flagging prefixes under 60% of it. `likely_reasons` lists what the audit
already knows: `rpki_invalid` (validating networks drop it), `short_lived`,
`single_neighbor`, `no_irr_object`. An empty list on a persistent prefix is the case to
investigate (upstream filters, or not announced to every provider).

**MOAS** comes from the detector's `moas_conflict` incidents: another ASN originated
the prefix within the detector's 4-hour window. Handovers are not MOAS; they appear as
`origin_mismatch_new` in `detections`. `baseline_origins` is the prefix's 30-day
baseline origin set from the incident details (the incidents' `baseline_asns` column
also lists every counterparty, so it is not the baseline). Each prefix is labelled:
`anomalous` (an origin outside the baseline with no known relation to it, or only an
observed adjacency, which is how leaks look; severity high), `related` (the new origin
is a baseline origin's provider or customer; medium), `same_organization` (registered
to the baseline origin's organization, such as a sibling ASN; low), or `steady` (only
baseline origins, such as a customer announcing its own space or an anycast partner).
`relations` holds the detector's evidence per flagged origin (`asn`, `relation`);
`other_origin_names` names each other origin; `anomalous_origins` keeps the detector's
flags, which can include your ASN. Related and same-organization conflicts still alert:
they may be an arrangement the operator did not know about. If one is routine, add the
ASNs to the monitor's trust set. Up to 5,000 incidents are
read; beyond that the finding's `note` gives the `detections` call and `offset` to
continue. Two warnings qualify a "none": `detector_gap` lists days with no detections
recorded anywhere on the platform (the detector was not running), and
`detector_coverage_unverified` means coverage could not be checked, for example for
windows older than 90 days. If the MOAS detection type is not part of your plan, the
`moas` finding is left out rather than reported as none.

**Unrouted** is measured against the registered allocation (RDAP `network_cidrs`)
that contains each sampled aggregate (up to 32, not counting transient ones), not
against the announced prefix itself. Space
under a prefix you announce is routed. `gaps` lists the unannounced CIDRs per
allocation. Up to 10 aggregates whose registration is not cached are looked up live
(each counts against the account's daily allowance of registration lookups); the rest
use cached registrations, and an `unrouted_unchecked` warning names any left without one.

Holder names for affected prefixes come from cached records and stored names only, so a
health check does not use the account's daily allowance on them. An
`annotation_partial` warning means some affected prefixes
could not be checked; their rows show `state: not_checked` or no holder. Independent
reads run concurrently; a large network (about 5,600 prefixes) takes 5 to 8 seconds.

---

## `validate_announcement`

Pre-flight check before announcing space, renumbering, or accepting a customer
prefix. With `as_of`, the same check against a past day's ROAs and IRR objects.

```jsonc
{ "name": "validate_announcement",
  "inputSchema": { "type": "object", "required": ["prefix","origin_asn"], "properties": {
    "prefix": { "type": "string" },
    "origin_asn": { "type": "integer" },
    "check_holder": { "type": "boolean", "default": true },
    "as_of": { "type": "string", "description": "YYYY-MM-DD" } } } }
```

```jsonc
{ "prefix": "198.51.100.0/24", "origin_asn": 64500,
  "rpki": { "status": "invalid",
            "covering_roas": [{ "cidr": "198.51.100.0/24", "origin_asn": 64501, "max_length": 24 }],
            "reason": "RPKI-invalid: no covering ROA authorizes AS64500 (covering: 198.51.100.0/24 AS64501 max /24).",
            "would_be_rejected_by": "any network performing origin validation" },
  "irr":  { "status": "missing", "detail": "No route object; IRR-based filters have nothing to match." },
  "announced_by": { "window": { "from": "2026-08-04", "to": "2026-08-11" }, "origins": [64501] },
  "registry_as_of": { "from": "2026-08-10", "to": "2026-08-11" },
  "holder": { "registrant": "Example Corp", "last_changed": "2026-07-02",
              "recently_transferred": true },
  "verdict": "blocked",
  "blockers": [ "RPKI-invalid: no covering ROA authorizes AS64500 (covering: 198.51.100.0/24 AS64501 max /24)." ],
  "warnings": [ { "code": "validation", "message": "Space changed registered holder within 90 days. ..." } ] }
```

`verdict` is `clear` | `warn` | `blocked`. `covering_roas` lists every ROA whose
prefix contains the announcement, including ones whose `max_length` is too short and
AS0 ROAs (the holder's "do not route" marker). Either kind makes the announcement
invalid, and `reason` says which applies. `announced_by` is the origins seen in
the last 7 days (or on `as_of`), not a live table. The `recently_transferred`
flag exists because of the ten-month invalid tail observed in the AS54994
report: freshly transferred space routinely still carries the old holder's ROAs.
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
  "upstreams": [{ "asn": 3356, "origin_as": 64500, "sessions": 318, "share": 0.994 }],
  "direct_share": 0.0,
  "concentration": { "top_collector": "rrc00", "top_collector_share": 0.08, "…": "…" },
  "warnings": [{ "code": "single_upstream",
                 "message": "Every collector session that heard it (apart from strays under 1%) did so through AS3356: …" }] }
```

`upstreams` are collector sessions per upstream, as in `paths` (at most the last 31 days
of the window). `compare_to` is the useful part. Absolute peer counts mean little; a prefix seen
by 40 peers when its siblings are seen by 330 is being filtered, and that ratio is
what surfaces it.

---

## `my_alerts`

Alerts your own monitors fired over a window: the input to an incident report or a
daily/weekly summary. Returns the alerts plus totals by detection type, severity and
monitor, so one call is enough to draft from. Scoped to your account (and anything your
organization shares with you); it is not a platform-wide search.

```jsonc
{ "name": "my_alerts",
  "inputSchema": { "type": "object", "properties": {
    "window": {"type": "string", "default": "today", "description": "Window to pull: \"today\", a relative span like \"24h\"/\"7d\"/\"30d\", or a date. Ignored when from/to are given."},
    "start": {"type": "string", "description": "Explicit window start (YYYY-MM-DD or RFC3339). Overrides `window`."},
    "end": {"type": "string", "description": "Explicit window end (YYYY-MM-DD or RFC3339)."},
    "detection_type": {"type": "string", "description": "Restrict to one detection type, e.g. rpki_invalid_asn."},
    "severity": {"type": "string", "description": "Restrict to one severity: info, low, medium, high, critical."},
    "prefix_status": {"type": "string", "description": "Restrict to one prefix novelty label the detector stamped at incident open: established, new, new_more_specific, returned. `new_more_specific` is the sub-prefix hijack shape (a more-specific of known space from a new origin) and is the one to pull first."},
    "monitor_id": {"type": "string", "description": "Restrict to a single monitor."},
    "include_dismissed": {"type": "boolean", "default": true, "description": "Include alerts already dismissed from the feed. True for a complete record of what fired."},
    "limit": {"type": "integer", "default": 200, "minimum": 1, "maximum": 1000, "description": "Maximum alerts to return (max 1000)."} } } }
```

Warnings: `no_alerts_in_window`, `truncated`, `mostly_informational`,
`single_monitor_dominates`.

---

## `my_monitors`

Your watchlist with each monitor's alert volume over a window: what you cover, and
which watches are noisy.

```jsonc
{ "name": "my_monitors",
  "inputSchema": { "type": "object", "properties": {
    "window":         { "type": "string", "default": "7d" },
    "start":          { "type": "string" },
    "end":            { "type": "string" },
    "scope":          { "type": "string", "enum": ["mine","org"], "default": "mine" },
    "resource":       { "type": "string", "enum": ["prefix","asn"] },
    "status":         { "type": "string", "enum": ["enabled","paused"] },
    "detection_type": { "type": "string" },
    "q":              { "type": "string" },
    "limit":          { "type": "integer", "default": 500, "maximum": 2000 } } } }
```

Warnings: `paused_monitors`, `no_activity`, `all_types_subscribed`.

---

## Operator prompts

| Prompt | Produces |
|---|---|
| `audit_my_network` | Hygiene report for your ASN with a prioritized remediation list |
| `preflight_change` | Go/no-go assessment for an announcement or renumbering |
| `explain_incident` | Plain-language incident summary for a non-network stakeholder |

`explain_incident` matters more than it sounds. Operators routinely need to tell
management what happened, and "2,289 withdrawals" is not that. The prompt enforces
impact framing: how much of the internet, for how long, and whether anyone else
was affected.
