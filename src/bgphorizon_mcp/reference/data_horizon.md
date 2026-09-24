# Data horizon and known caveats

Read this before reasoning about *when* something started.

## The retention floor

Historical event and rollup data extends back a finite window. When a query
window begins at that floor, the earliest data is **censored**: a prefix's
`first_seen` on the floor date does not mean it appeared then, only that the
data does not go back further. The API emits a `window_start_censored`
warning in this case, and tools surface it.

**Consequence:** never describe a `first_seen` that coincides with the window
start (or the retention floor) as an origin, a launch, or a handover. Widen the
window; if `first_seen` moves with the window edge, it is censored.

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
