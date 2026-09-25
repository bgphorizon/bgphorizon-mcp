# MCP Tool Schemas

Twenty-two tools across three personas:

- **Investigation** (20): analyzing a network you do not run
- **Operator** (3): watching one you do
- **Alerts** (2): reading your own monitoring, for reports

Each maps to an analytical operation, not an endpoint.

Common conventions:
- Dates are `YYYY-MM-DD`; datetimes are RFC3339 UTC.
- Every response includes `warnings[]` (may be empty) and `meta` with
  `source` (`rollup` | `raw_events` | `registry`) and `computed_at`.
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
    "summary_only": { "type": "boolean", "default": false } },
    "anyOf": [{ "required": ["asn"] }, { "required": ["prefix"] }] } }
```

```jsonc
{ "total_matching": 450, "returned": 450, "complete": true,
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

`direction` is the important field. Values:
`queried_entity_is_invalid_party` | `queried_entity_is_baseline` | `third_party`.

Reading `actor_as` against `baseline_asns` incorrectly inverts a report's
conclusion: a court appeared to be a hijack victim when its own announcements
were the invalid ones.

`complete: false` means the page limit was hit before every match was read.
Do not state a count from it; narrow the window or filter by type.
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

An ASN's inferred transit hierarchy over a window: **upstreams** (its providers) and
**downstreams** (its customers), plus **other_connections**, observed adjacencies whose
type is unknown. Provider→customer is inferred Tier-1-anchored (~94% agreement with CAIDA);
peering is **not** inferred, so `other_connections` are never presented as confirmed peers.
Each row carries `confidence`, `vantage_count` (distinct collector+peer feeds), and
`days_present`. Results reflect the window; relationships change over time.

```jsonc
{ "name": "relationships",
  "inputSchema": { "type": "object", "required": ["asn"], "properties": {
    "asn": { "type": "integer" }, "start": { "type": "string" }, "end": { "type": "string" } } } }
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

Facility intersection across upstreams: routing-only geolocation.

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
                 "message": "Geolocation sources disagree across three countries, which is characteristic of leased space with no stable anchor. Prefer routing evidence." }] }
```

---

## `subprefixes`

```jsonc
{ "name": "subprefixes",
  "inputSchema": { "type": "object", "required": ["prefix"], "properties": {
    "prefix": { "type": "string" }, "from": { "type": "string" }, "to": { "type": "string" } } } }
```

Returns announced more-specifics plus `unrouted_addresses`: allocated space never
seen in the table, which is the easiest kind to announce unnoticed.

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

## `origin_episode`

What did one network originate during a short window that it does not normally
originate, and whose space was it? Start here for a hijack or leak report.

```jsonc
{ "name": "origin_episode",
  "inputSchema": { "type": "object", "required": ["asn","start"], "properties": {
    "asn": { "type": "integer" }, "start": { "type": "string" }, "end": { "type": "string" },
    "baseline_days": { "type": "integer", "default": 28 },
    "after_days": { "type": "integer", "default": 3 },
    "list_prefixes": { "type": "boolean", "default": true } } } }
```

```jsonc
// origin_episode(asn=197207, start="2026-09-20")
{ "summary": { "prefixes_in_window": 1264, "new_in_window": 447,
               "new_own_space": 28, "new_other_space": 419,
               "first_seen": "2026-09-20T09:56:25.000Z", "last_seen": "2026-09-20T10:26:33.000Z",
               "max_peers": 323, "reference_peers": 83,
               "exact_conflicts": 78, "conflicts": 10179, "conflict_asns": 1483 },
  "carriers": [{ "asn": 49666, "prefixes": 419, "is_inferred_provider": true }],
  "holders":  [{ "asn": 25306, "relation": "exact", "prefixes": 42 }],
  "prefixes": [{ "prefix": "81.28.32.0/23", "space": "other", "exact_origins": [25306],
                 "first_seen": "2026-09-20T10:03:12.000Z", "peers": 323 }] }
```

`conflicts` counts prefix/origin pairs by other networks equal to or inside the
other-space prefixes during the episode, which is how public monitors count a
hijack's reach. Covering holders need 2+ baseline days; default routes and blocks
shorter than /8 (v4) or /16 (v6) never count.

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
    "as_of": { "type": "string", "description": "YYYY-MM-DD" } } } }
```

```jsonc
{ "rpki_summary": { "origin_asn": 197207, "valid": 0, "invalid": 0, "not_found": 3, "checked": 3 },
  "prefixes": [{ "prefix": "185.192.8.0/22", "rpki": "not_found", "irr_origins": [42990],
                 "irr_matches_origin": false,
                 "rdap": { "name": "IR-BANKSADERAT-20170227", "country": "IR", "rir": "RIPE NCC" } }] }
```

IRR origins list only objects still in the registry; deleted ones appear under
`irr_deleted_origins`. For a past incident pass `as_of`: four prefixes leaked on
2026-09-20 gained ROAs the next morning and would otherwise read as RPKI-invalid.
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
                "default": ["rpki","irr","moas","visibility","transit","unrouted","maxlength"] } } } }
```

```jsonc
{ "asn": 21799, "prefixes_checked": 7,
  "findings": [
    { "check": "rpki", "severity": "high", "affected": ["144.166.53.0/24", "…"],
      "count": 7,
      "detail": "No ROA on any announced prefix. Announcements cannot be validated or rejected.",
      "remediation": "Create ROAs authorizing AS21799 with max_length equal to the announced length." },
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

`maxlength` deserves emphasis: a ROA on a `/24` with `max_length: 32` authorizes
any more-specific under that origin, which is a hijack surface rather than
protection.

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
  "rpki": { "status": "invalid", "reason": "ROA(s) authorize [64501], max_length 24; announcing from AS64500 would be RPKI-invalid.",
            "would_be_rejected_by": "any network performing origin validation" },
  "irr":  { "status": "missing", "detail": "No route object; IRR-based filters have nothing to match." },
  "announced_by": { "window": { "from": "2026-08-04", "to": "2026-08-11" }, "origins": [64501] },
  "registry_as_of": { "from": "2026-08-10", "to": "2026-08-11" },
  "holder": { "registrant": "Example Corp", "last_changed": "2026-07-02",
              "recently_transferred": true },
  "verdict": "blocked",
  "blockers": [ "ROA(s) authorize [64501], max_length 24; announcing from AS64500 would be RPKI-invalid." ],
  "warnings": [ { "code": "validation", "message": "Space changed registered holder within 90 days. ..." } ] }
```

`verdict` is `clear` | `warn` | `blocked`. `announced_by` is the origins seen in
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
  "missing_regions": [],
  "upstreams": [{ "asn": 3356, "share": 1.0 }],
  "warnings": [{ "code": "single_upstream",
                 "message": "Reachable through one provider only; siblings 144.166.55.0/24 and 144.166.174.0/24 have two." }] }
```

`compare_to` is the useful part. Absolute peer counts mean little; a prefix seen
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
    "window":            { "type": "string", "default": "today",
                           "description": "\"today\", a relative span (24h/7d/30d), or a date" },
    "start":             { "type": "string", "description": "Explicit window start; overrides window" },
    "end":               { "type": "string", "description": "Explicit window end" },
    "detection_type":    { "type": "string" },
    "severity":          { "type": "string", "enum": ["info","low","medium","high","critical"] },
    "monitor_id":        { "type": "string", "format": "uuid" },
    "include_dismissed": { "type": "boolean", "default": true },
    "limit":             { "type": "integer", "default": 200, "maximum": 1000 } } } }
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
