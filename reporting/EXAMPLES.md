# Published Reports — and what each one taught

Four reports, four different shapes. Useful mainly as evidence that the same
method produces very different documents, and that "no incident" is a legitimate
finding.

---

## 1. Transient origin changes in US Army address space

**Subject:** AS1516, AS1600, AS1602, AS1637, AS1649 (DoD / HQ USAISC)
**Verdict:** Not an incident — recurring transient episodes
**Shape:** 7 dated events, episode bars + per-prefix trace

Seven dates on which a sibling DoD ASN briefly co-originated another's address
space, each lasting hours and reverting. Every path stayed inside DoD's own
upstream chain, and the joining network prepended its AS 2–3× — deliberate
de-preferencing, i.e. backup-path engineering, not a leak.

**What it taught**

- **The `first_seen` trap.** The first draft called this a staged migration. It
  was wrong. Day-by-day origin counts showed reversion within 24 hours. This one
  error generated: methodology step 3, the `origin_history` tool, the
  `/api/presence` endpoint, and the `transient_not_persistent` warning.
- **Window-edge censoring.** 15 of 382 "handoffs" were artifacts of the retention
  floor. Corrected count: 367.
- **Prepending is signal.** `1600 1600 1600` is not noise — it is the tell that
  distinguishes intentional failover from a mistake.
- **Recording the correction in the report** cost nothing and made it stronger.

---

## 2. AS21799 / 144.166.0.0/16 — sixty-day review

**Subject:** Metropolitan Water District of Southern California
**Verdict:** No incident; two brief outages; zero RPKI
**Shape:** 60-day volume strip, two reachability curves, recommendations

Clean routing — no hijacks, no competing origins. Two withdrawal storms recovering
inside a minute, one of which hit only the three prefixes lacking a second transit
provider. And a large block of apparent instability that resolved to a measurement
artifact.

**What it taught**

- **The collector-artifact class.** A threefold sustained rise from one peer
  (AS3491 at `route-views.hkix`) flapping. 542 of 545 bursts re-announced all
  seven prefixes in the same second with an identical path. Produced methodology
  step 4, the `concentration` metadata requirement, and the
  `single_vantage_point` warning.
- **Geography can be a red herring.** "US water utility generating traffic at a
  Hong Kong exchange" sounds alarming. Route collectors are passive and never
  re-advertise; there was no mechanism for diversion. Worth stating explicitly
  rather than leaving the reader to wonder.
- **Reachability beats withdrawal counts.** "25% of vantage points for 20
  minutes" is actionable; "502 withdrawals" is not.
- **Single-homing shows up in who survives.** The June event hit exactly the
  prefixes without a second provider.

---

## 3. AS31753 / AS397496 — sixty-day review

**Subject:** Inmarsat Government
**Verdict:** One significant outage; one third-party announcement
**Shape:** topology block, daily strip, 3-hour outage curve

A two-wave outage removing four prefixes from ~74% of vantage points, and an
eighteen-minute announcement of a third party's address space that had no
precedent in ninety days.

**What it taught**

- **Verify the premise.** The request stated one AS announced nothing and the
  other announced nine prefixes. Neither was true — the first originates an IPv6
  /48 and is the second's sole transit; the second announces eighteen. Correcting
  this was the report's most useful contribution.
- **Path composition answers "authorised or not".** The 18-minute announcement
  travelled out through the address holder's own infrastructure — the opposite of
  interception. Path structure settled what registry data could not.
- **Single-transit dependency is a finding.** Every prefix through one upstream,
  which itself had one upstream.
- **Say what would resolve the ambiguity.** "Change records for 15:30–16:00 UTC
  would settle it" is more useful than hedging.

---

## 4. AS54994 — court address block transfer

**Subject:** Meteverse Limited; Los Angeles Superior Court
**Verdict:** Documented transfer with a ten-month invalid tail
**Shape:** handover strip (102 days × 3 prefixes), registry timeline

A legacy /16 transferred to a CDN in September 2025. The court kept announcing
three /24s from it until August 2026 — RPKI-invalid against the new holder's
ROAs the whole time. Staged handover completed five days before publication.

**What it taught**

- **Correct the premise in the report.** The request said "Municipal Court". That
  entity dissolved in 2000 and holds no routed space; the actual subject was the
  Superior Court. Reports should carry the correction, not the request's framing.
- **Direction inverts narratives.** The pattern reads as "CDN takes government
  space". The evidence said the court was the invalid party. Reading `actor_as`
  against `baseline_asns` is what produced the right story. Became methodology
  step 7 and the `direction` field on the `detections` tool.
- **Lead recommendations by impact, not narrative order.** The top item is the
  court's *current* space having zero ROAs — which appears late in the evidence.
- **Gaps in a migration are findings.** Two prefixes were absent from the global
  table for 22 and 26 days.
- **Leave unverified relationships unverified.** The Meteverse↔CDNetworks overlap
  is heavy but circumstantial; the report says so and draws no conclusion.

---

## Patterns across all four

**Two of four concluded "not an incident."** Both were more useful for it. A
report explaining why something alarming is benign has real value, and refusing
to inflate is what makes the ones that *do* report incidents credible.

**Every report found missing RPKI.** Four subjects, four cases of zero or partial
coverage — including a water utility, a satellite operator and a county court.
This is the most consistent finding in the corpus and is why it is a mandatory
section.

**Three of four required correcting the requester's premise.** Municipal vs
Superior Court; "announces no prefixes"; "migration" vs episodes. Verify the
framing before adopting it.

**Every substantive error was caught in QA, not research.** None were caught by
being careful during investigation. That is the argument for a mandatory
verification pass.

**The interesting finding is often the inverse of the obvious one.** CDN takes
court space → court was invalid. Foreign exchange sees US utility → passive
collector. Staged migration → transient episodes. When a pattern reads as a clean
story, that is the moment to check it hardest.
