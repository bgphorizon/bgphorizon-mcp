# BGPHorizon detection types

Every detection is evaluated twice: "is this a violation?" and "is it *new*?"
The second is judged against a rolling 30-day baseline. A violation already
present in that window is **steady-state**; one never seen before is
**anomalous**. Alerting only ever considers anomalous incidents — the internet
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
| `moas_conflict` | Two or more ASNs originate the same prefix concurrently | high / info | medium |
| `origin_mismatch_new` | A (prefix, origin) pairing that has never existed before (high), or returns after 30+ days dormant (medium) | high or medium / – | medium |

`moas_conflict` and `origin_mismatch_new` are the hijack-shaped detections, hence
high anomalous severity. Steady MOAS is almost always anycast or intentional
multihoming.

## Reading `actor_as` vs `baseline_asns` — do not get this backwards

- **`baseline_asns`** — the origin(s) established as legitimate for the prefix
  (from history / RPKI / IRR). The rightful party.
- **`actor_as`** — the AS responsible for the *anomalous* condition. For a
  hijack-shaped detection, this is the **offending** origin, not the victim.

So if you are investigating AS X and X appears in `baseline_asns`, X is the
*victim/rightful* party. If X is the `actor_as` and not in `baseline_asns`, X is
the *offending* party. Inverting this makes a hijacker look like a victim — a real
error made in a past report where a court's own invalid announcements made it look
like the target of a hijack.

The `detections` tool computes an explicit `direction` field to remove this trap:
`queried_entity_is_invalid_party` | `queried_entity_is_baseline` | `third_party`.

## Severity levels

- **high** — plausibly an active routing incident; the prefix owner would want to
  know within minutes.
- **medium** — a real misconfiguration or policy problem worth fixing, rarely an
  immediate reachability threat.
- **low** — hygiene; weak evidence on its own.
- **info** — steady-state record, never alerted; useful for "everything currently
  invalid" queries.

Authoritative values live in the detector catalog (`services/internal/detector/catalog.go`).
