# Report Methodology

The research procedure behind the published reports. Follow it in order — the
ordering is what prevents the two error classes documented at the bottom.

---

## The procedure

### 1. Identify before describing

Resolve every ASN and prefix through registry data before writing a word about
behaviour. Never infer an operator from a name.

```
identify(asn=N) / identify(prefix=P)
```

Record: registrant, registration date, allocation type, parent block, country,
abuse contact, maintainers.

**Look at `type` and `registration_date` together.** A `LEGACY` block registered
in 1990 and a `SUB-ALLOCATED PA` created last month are entirely different
objects, and the distinction has driven the framing of three reports.

**Check the parent.** `62.60.227.0/24` looked unremarkable until its parent
resolved to a 2002 Iranian research-institute allocation.

### 2. Establish a baseline

You cannot call anything anomalous without knowing what ordinary looks like.

```
platform_baseline(window=14d)      # is the whole platform busy today?
timeline(target, from, to)          # what does a normal day look like for this target?
```

One investigation was correctly abandoned at this step: platform trends showed the
day was entirely normal, so the "spike" was just the platform's ordinary volume.

### 3. Check persistence before claiming change

**The step that is easiest to skip and most costly to skip.**

```
origin_history(prefix, from, to)     # NOT inventory()'s first_seen
```

A first-seen date proves a prefix *appeared*. It says nothing about whether it
*stayed*. Before describing any migration, handover or takeover, confirm the new
state persisted across multiple days.

Classify explicitly:

| Pattern | Name | Description |
|---|---|---|
| New origin persists | **handover** | A real change |
| New origin reverts within ~1 day | **episode** | Transient; often maintenance or failover |
| Alternates repeatedly | **intermittent** | Instability, not a change |

### 4. Attribute the signal

Before reporting any volume change, check which vantage points produced it.

```
timeline(target, group_by="collector")
```

If one collector or peer supplies most of the signal, it is a **measurement
artifact** — that peer's session, not the target's routing. Say so and exclude it.

The tell for a flapping collector session: identical AS paths, all prefixes
re-announced in the same second, no withdrawals in between.

### 5. Quantify impact in reachability, not messages

"2,289 withdrawals" is meaningless to a reader. Convert it:

```
reachability(prefixes=[...], from, to, interval="10s")
```

→ *"At the peak, 979 of 1,323 tracked observations had no route — roughly 74% —
for about twenty minutes."*

Sample finely enough. A 2-minute interval missed an event whose median restore
time was 19 seconds.

### 6. Always report RPKI and IRR coverage

Including — especially — absence. A clean routing result on unsigned space is a
description of what happened, not a guarantee enforced by anything.

Check `max_length` too. A ROA on a `/24` with `max_length: 32` authorises any
more-specific under that origin.

### 7. Establish direction

For any conflict, determine who is the invalid party. Read `actor_as` against
`baseline_asns`.

In the AS54994 report the invalid party was the *court*, not the CDN. The pattern
read as "CDN takes government space"; the evidence said the opposite. Getting this
backwards inverts an entire report.

---

## Geolocating infrastructure

When the question is *where is this hosted*, in descending order of reliability:

1. **Reverse DNS.** Sweep the whole /24. Operator naming frequently encodes site
   codes and facility names. Absence of PTRs across an entire block is itself a
   signal — legitimate hosting almost always sets them.
2. **PeeringDB facility intersection.** Take the network's upstreams and intersect
   their facility lists. For one target, three upstreams shared exactly one city.
   This is the most reliable routing-only method.
3. **AS path composition.** Which IXPs and regional networks appear.
4. **Registry address.** Often a billing address, not a facility. Weak.
5. **Commercial geolocation.** Weakest. **Query at least three.** Their
   *disagreement* is more informative than any single answer — one prefix returned
   Rotterdam / London / London / `EU` / `IR`, which is the fingerprint of leased
   space with no stable anchor.

State a confidence level and the basis for it. "Frankfurt, moderate confidence,
being the only city common to all three upstreams" is honest. "Located in
Frankfurt" is not.

---

## Two errors made in real reports

Both survived until an explicit verification pass. Both are now steps in the
procedure above.

### Error 1 — mistaking transience for migration

**What happened.** `/api/asn/prefixes` returns `first_seen` per prefix. Used
across six DoD ASNs, it produced clean block-aligned waves that looked exactly
like a staged migration — 43 prefixes on one date, 112 on another, each confined
to one installation's /16. Most of a report was drafted on that reading.

**Why it was wrong.** `first_seen` records the first occurrence only. Day-by-day
origin counts showed every prefix reverting within 24 hours. Tracking one prefix
across seven months:

| date | announcements | origins |
|---|---|---|
| Jun 5 | **2,461** | AS1602 (91%), **AS1600 (9%)** |
| Jun 20 | 10 | AS1602 only |
| Aug 5 | **2,972** | AS1602 (81%), **AS1600 (19%)** |

Two brief episodes, not a handover. Nothing changed hands.

**Prevention.** Step 3. Never conclude change from `first_seen`.

### Error 2 — mistaking a collector artifact for an event

**What happened.** Daily announcements for a water utility's prefixes tripled from
28 July and stayed elevated. It read as a sustained routing regime change.

**Why it was wrong.** Nearly all of it came from one peer (AS3491 at
`route-views.hkix`) — 10,201 of its 10,392 messages after that date, every one
carrying an identical, correct AS path, with all seven prefixes re-announced in
the same second. A flapping collector session, not routing.

**Prevention.** Step 4. Check concentration before reporting volume.

---

## Verification pass

Never publish without one. Both errors above were caught here, not during
research. See [`QA-CHECKLIST.md`](QA-CHECKLIST.md).

The minimum: **every number in the output must trace to a specific call, and be
re-derived from source before publishing.** Machine-check it where possible —
extract the figures from the rendered document and diff them against the source
JSON.
