# Data horizon and known caveats

Read this before reasoning about *when* something started.

## The retention floor

Historical event and rollup data extends back a finite window. When a query
window begins at that floor, the earliest data is **censored**: a prefix's
`first_seen` on the floor date does not mean it appeared then — only that the
data does not go back further. The API emits a `window_start_at_data_floor`
warning in this case, and tools surface it.

**Consequence:** never describe a `first_seen` that coincides with the window
start (or the retention floor) as an origin, a launch, or a handover. Widen the
window; if `first_seen` moves with the window edge, it is censored.

## rollup vs raw_events

`meta.source` tells you where a number came from:

- `rollup` — pre-aggregated per-day/per-collector counts. Cheap; the basis for
  `timeline`, `presence`/`origin_history`, `paths`, concentration. Bucketed
  **daily** — sub-day granularity is not available from rollups.
- `raw_events` — reconstructed from individual BGP messages. Used by
  `reachability` and `events_sample`. Bounded and slower; keep windows tight.
- `registry` — RPKI/IRR/RDAP/PeeringDB reference data, refreshed periodically
  (RDAP is cached; see `cached_at`).

Rollup and raw counts can disagree by a fair margin for the same window; prefer
whichever the tool used and do not mix them in one comparison.

## Persistence over first_seen

The single most important habit: classify persistence (`persistent` /
`intermittent` / `transient`) before narrating. Use `inventory`,
`origin_history`, or `presence`; never infer it from a lone `first_seen`.
