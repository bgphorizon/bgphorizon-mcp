# Data horizon and known caveats

Read this before reasoning about *when* something started.

## How far back the data goes

The sources do not reach back evenly (checked 2026-09-30):

| Source | Starts | Used by |
|---|---|---|
| Per-ASN daily rollup | 2026-01-04 | `inventory`, `origin_history` for an ASN, `origin_episode`, `health_check`, `timeline` for an ASN |
| Per-prefix daily rollup | 2025-05-27 | `origin_history` for a prefix, `paths` (path list), `visibility` (reach), `timeline` for a prefix, `subprefixes` |
| Raw events, IPv4 | 2025-05-27 | `reachability`, `origin_reach`, `events_sample`, `path_diversity`, sub-day `timeline`, the `upstreams` of `paths`, `visibility` and `locate` (last 31 days of the window) |
| Raw events, IPv6 | 2026-04-01 | the same, for IPv6 |

**Raw events are kept for 90 days from all ~25 collectors, and only from 5 collectors
(route-views2, rrc00, rrc11, rrc21, rrc23) beyond that.** Peer counts, reach and
propagation shares for anything older than 90 days are therefore understated.

The API says so, and every tool passes it on:

- `window_before_data`: the window starts before the source has data; results cover
  the period from the date it names, and anything first seen on that date may be
  older.
- `reduced_vantage_points`: part of the window is older than 90 days, so those raw-event
  figures come from 5 collectors.
- `window_start_censored`: a prefix was first seen on the window's first day; its
  `first_seen` is the window edge, not when it appeared.
- `history_limited`: the account's history does not reach the requested start; results
  start at the date named.

**Consequence:** never describe a `first_seen` that coincides with the window start or
a data floor as an origin, a launch or a handover. Widen the window; if `first_seen`
moves with the window edge, it is censored. Do not compare peer counts across the
90-day boundary.

## Partial results

When part of a response could not be read (a sub-query failed or timed out) the tool
carries a `partial_result` warning naming the missing parts, and totals that include
them are low. A section that could not be loaded is reported as unavailable
(`sections_unavailable`, `unavailable`, `not_checked`), never as "none": do not write
"no ROA" or "no IRR object" from it. Re-run, or check the section with
`bulk_registry`.

## rollup vs raw_events

`meta.source` tells you where a number came from:

- `rollup`: pre-aggregated per-day/per-collector counts. Cheap; the basis for
  `timeline` (day/week), `presence`/`origin_history`, `paths`, `origin_episode`,
  concentration. Bucketed **daily**, though `origin_episode` still reports each
  prefix's first and last announcement to the millisecond.
- `raw_events`: reconstructed from individual BGP messages. Used by
  `timeline` at `hour`/`10m`/`1m` (72-hour limit), `origin_reach`, `reachability`
  and `events_sample`. Bounded and slower; keep windows tight.
- `registry`: RPKI/IRR/RDAP/PeeringDB reference data, refreshed periodically
  (RDAP is cached; see `cached_at`).

Rollup and raw counts can disagree by a fair margin for the same window; prefer
whichever the tool used and do not mix them in one comparison.

## Persistence over first_seen

The single most important habit: classify persistence (`persistent` /
`intermittent` / `transient`) before narrating. Use `inventory`,
`origin_history`, or `presence`; never infer it from a lone `first_seen`.

## Withdrawals have no origin

A BGP withdrawal names a prefix, not an AS path. Withdrawal counts therefore
exist per prefix but cannot be attributed to an ASN: `timeline` on an `asn:`
target returns `withdrawals: null` with a `withdrawals_unattributable` warning.
Use a prefix target, `reachability` or `origin_reach` for withdrawal behaviour.

## Relationship data lags

AS relationships are rebuilt daily from the previous day's updates. Responses
carry `data_through`; when a window ends later, `relationships` warns
`relationships_stale` and names the window it served. Cite the served window.

## Covering holders

When a detection or an episode names the holder of a covering block, that holder
announced the block on at least one full day (detections: 24 hours of observed
span; episodes: 2 or more baseline days). Default routes and blocks shorter than
/8 (IPv4) or /16 (IPv6) never count. A short leak of an aggregate does not make
the leaker the holder of everything underneath it.
