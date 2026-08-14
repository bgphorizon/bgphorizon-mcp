# Route collectors

BGPHorizon ingests from the two public route-collection projects. Collector
identity matters because **a signal seen from only one collector or peer is
usually a measurement artifact**, not a global routing event — the reason every
aggregate response carries `concentration` metadata.

## RouteViews (University of Oregon)

Collectors are named by location, e.g. `route-views.hkix` (Hong Kong),
`route-views.linx` (London), `route-views.sydney`, `route-views.amsix`
(Amsterdam), `route-views.sg` (Singapore), `route-views.chicago`,
`route-views.eqix` (Ashburn), `route-views.napafrica` (Johannesburg). The name
after `route-views.` is the exchange or city.

## RIPE RIS (RIPE NCC)

Collectors are named `rrc00` through `rrc26`. `rrc00` is multihop (global);
the rest are located at specific internet exchanges, e.g. `rrc03` AMS-IX
Amsterdam, `rrc15` São Paulo, `rrc24` multihop (LACNIC region).

## Using concentration correctly

- `top_collector_share` — fraction of observations from the single busiest
  collector. Above ~0.5, treat volume changes as a possible artifact until
  confirmed elsewhere; the `single_vantage_point` warning fires automatically.
- `effective_vantage_points` — inverse-Simpson index of collector shares; a low
  number (near 1) means the view rests on essentially one collector even if many
  are technically present.
- `unique_collectors` — how many collectors saw the prefix/ASN at all.

A prefix seen by 24 collectors with an even share is a robust global view; one
seen by 2 collectors, 90% from one, is a single window on the world.
