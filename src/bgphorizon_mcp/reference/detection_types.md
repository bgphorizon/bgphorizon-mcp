# BGPHorizon detection types

Every detection is evaluated twice: "is this a violation?" and "is it *new*?"
The second is judged against a rolling 30-day baseline. A violation already
present in that window is **steady-state**; one never seen before is
**anomalous**. Alerting only ever considers anomalous incidents. The internet
carries enormous amounts of permanent, harmless policy violation, and what
matters is change. Each type therefore carries two severities (anomalous / steady).

## Catalog

| Type | Fires when | Severity (anomalous / steady) | Confidence |
|---|---|---|---|
| `rpki_invalid_asn` | A ROA covers the prefix and the origin AS is not authorized by any covering ROA | high / info | high |
| `rpki_invalid_length` | Origin is authorized but the announcement is more specific than the ROA max length | high / info | high |
| `irr_invalid_asn` | IRR route objects exist for the exact prefix and none match the origin | medium / info | medium |
| `unregistered_route` | No ROA coverage and no IRR object at all | low / info | medium |
| `reserved_as_in_path` | A reserved / private-use ASN appears in the public AS path | medium / low | high |
| `unallocated_as_in_path` | A path ASN has never been allocated by any RIR | medium / low | high |
| `path_loop` | The same ASN appears at non-adjacent path positions | medium / low | high |
| `first_as_violation` | The peer that exported the route is not the first AS in the path | medium / low | medium |
| `moas_conflict` | Two or more ASNs originate the same prefix concurrently. Severity when anomalous depends on how the new origin relates to the usual one: none or only an adjacency (high), provider or customer (medium), same organization (low); `details.related_to` records it | high, medium or low / info | medium |
| `origin_mismatch_new` | A (prefix, origin) pairing that has never existed before (high), returns after 30+ days dormant (medium), or is a new more-specific inside a block the same network already announces (info, `self_more_specific: true`) | high, medium or info / none | medium |

`moas_conflict` and `origin_mismatch_new` are the hijack-shaped detections, hence
high anomalous severity. Steady MOAS is almost always anycast or intentional
multihoming. A medium or low MOAS is still anomalous (it alerts) but the new origin is
the usual origin's provider, customer or sibling network, so describe it as a
possibly unannounced arrangement, not a hijack, and name the relation. An `origin_mismatch_new` at info severity is a network deaggregating
its own space; do not describe it as a hijack. For such an incident the actor also
appears in `baseline_asns`, so `direction` reads `queried_entity_is_baseline`
when you query that network: it is both parties.

## Reading `actor_as` vs `baseline_asns`

- **`baseline_asns`**: the origin(s) established as legitimate for the prefix
  (from history / RPKI / IRR). The rightful party.
- **`actor_as`**: the AS responsible for the *anomalous* condition. For a
  hijack-shaped detection, this is the **offending** origin, not the victim.

So if you are investigating AS X and X appears in `baseline_asns`, X is the
*victim/rightful* party. If X is the `actor_as` and not in `baseline_asns`, X is
the *offending* party. Inverting this makes a hijacker look like a victim, a real
error made in a past report where a court's own invalid announcements made it look
like the target of a hijack.

The `detections` tool computes an explicit `direction` field to remove this trap:
`queried_entity_is_invalid_party` | `queried_entity_is_baseline` |
`queried_entity_announced_own_space` | `third_party`. The own-space value is a network
announcing inside space it already holds (for example a new, smaller prefix of its
own block); it is neither the victim nor the offender.

### Order of `baseline_asns` and the usual origin

`baseline_asns` lists the prefix's current holders first: origins in the 30-day
baseline, then earlier origins that still count as holders, then (for a new
more-specific) the holders of the covering block. An earlier origin counts as a holder
only if it originated the prefix over at least 7 days, and, when the prefix has a
current holder, was seen within 30 days of the event. A network that announced the
prefix briefly, or a former holder that stopped long ago, is left out. The list can be
empty when the prefix's only history is short-lived announcements; treat that as "no
established holder", not as an error. Within each group the longest-standing origin comes
first. `notable_events` reports the first allocated entry as `usual_origin_as`, so on a
prefix with several origins it is the longest-standing current one. Treat the rest of
the list as other networks with a claim, not as a ranking. Incidents opened before
12 October 2026 may list origins in arbitrary order until the history re-sort runs,
and incidents opened before 15 October 2026 may still include short-lived earlier
origins until the history backfill runs.

### Dates in `origin_mismatch_new` details

`prior_first_seen`, `prior_last_seen` and `dormant_days` (kind `returned`) describe the
announcing network's own earlier run on this prefix: when `actor_as` last originated it
and how long it was absent. They are not about the other origins. `prior_origins` lists
every other network ever seen originating the prefix, with no dates, including
one-day announcements; use `origin_history` for when each one did.
`holder_origins` is the subset of them that counts toward `baseline_asns`.

## Severity levels

- **high**: plausibly an active routing incident; the prefix owner would want to
  know within minutes.
- **medium**: a real misconfiguration or policy problem worth fixing, rarely an
  immediate reachability threat.
- **low**: hygiene; weak evidence on its own.
- **info**: steady-state record, never alerted; useful for "everything currently
  invalid" queries.

Authoritative values live in the detector catalog (`services/internal/detector/catalog.go`).
