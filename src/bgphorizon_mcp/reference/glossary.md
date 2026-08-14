# BGP glossary (plain language)

Reusable definitions for report and briefing output — write to this level unless
the audience is known to be routing specialists.

- **ASN (Autonomous System Number)** — the identifier for one network's routing
  domain, e.g. AS13335 is Cloudflare. Written `AS13335` or just `13335`.
- **Prefix** — a block of IP addresses announced as a unit, in CIDR notation
  (`1.1.1.0/24` = 256 addresses; a smaller number after the slash means a larger
  block). A **more-specific** is a smaller block inside a larger one.
- **Origin AS** — the network at the end of the AS path; the one claiming to own
  the prefix.
- **AS path** — the sequence of networks a route traversed, right-to-left toward
  the origin. **Prepending** repeats an ASN to make a path look longer and thus
  less preferred (a deliberate backup signal).
- **Upstream / transit** — a provider a network buys connectivity from; the AS
  immediately before the origin on the path.
- **Announcement / withdrawal** — a route being advertised as reachable, or
  retracted. Counts of these are traffic-agnostic — they measure routing churn,
  not bytes.
- **Collector / peer / vantage point** — RouteViews and RIPE RIS run route
  **collectors** that receive routes from **peer** routers. A single collector
  peer is one viewpoint; a change seen from only one is likely a measurement
  artifact, not a global event.
- **RPKI / ROA** — Resource PKI; a **ROA** cryptographically states "AS X may
  originate this prefix, up to max-length /N." An announcement not matching any
  covering ROA is **RPKI-invalid** and can be rejected by validating networks.
- **IRR (Internet Routing Registry)** — a database of route objects operators use
  to build prefix filters. Less authoritative than RPKI and often stale.
- **RDAP / whois** — registration data: who holds the number resource, contacts,
  and when it last changed. A **recent transfer** matters because the old holder's
  ROAs often linger.
- **MOAS (Multiple Origin AS)** — a prefix originated by more than one ASN at once.
  Usually benign (anycast, multihoming); a *new* MOAS is hijack-shaped.
- **Persistence** — whether a prefix is announced steadily. `persistent`,
  `intermittent`, or `transient`. A prefix present 2 of 60 days is transient — do
  **not** describe it as a migration or handover.
- **Reachability / outage window** — how many observing peers had no route, and for
  how long. This is impact; a raw withdrawal count is not.
