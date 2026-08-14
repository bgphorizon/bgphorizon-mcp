# Writing Guide

House style for BGPHorizon reports. The research is covered in
[`METHODOLOGY.md`](METHODOLOGY.md); this is about the document.

---

## What a report is

A record of what the routing data showed, written so a competent non-specialist
can follow it and a specialist can check it. Not a thriller, not a marketing
asset, not a threat-intel bulletin.

The reader is usually one of:
- a **network operator** who needs to know whether to act
- a **security analyst** deciding whether it matters
- a **manager** who needs the impact in one sentence

Write for all three by putting the plain-language answer first and the evidence
underneath.

---

## Structure

```
Masthead                     brand, "Routing Report"
Title + standfirst           the finding in 3–4 sentences, no suspense
Dateline                     generated-at, window, subjects
Stat tiles                   4–5 numbers that frame the scale
Glossary (collapsed)         plain-language terms
01 …                         numbered sections, evidence-ordered
Recommendations              prioritised, actionable (if applicable)
Sources and scope            provenance + limits
```

Number sections. Readers cite them.

Order sections by **what the reader needs to know first**, not by the order you
discovered things. The AS54994 report was researched by stumbling onto a MOAS;
it's written as parties → transfer → handover → validation gap.

---

## Voice

**Lead with the answer.** The standfirst states the finding. No "we set out to
investigate…".

**Vary sentence length.** Long-short-long reads as human. Uniform medium-length
sentences read as generated.

**Concrete nouns, specific numbers.** "Roughly 74% of observed vantage points"
beats "a significant portion of the internet."

**Active voice, past tense for events, present for current state.**

### Avoid

| Don't | Do |
|---|---|
| "It's not X, it's Y" repeatedly | Vary construction; use it once at most |
| Em-dash every other sentence | Use commas, semicolons, full stops |
| "Notably," "Interestingly," "It's worth noting" | Just say the thing |
| "Deep dive", "unpack", "leverage" | "Examine", "explain", "use" |
| Tricolons everywhere | One list of three is fine; four in a row is a tic |
| Ending every section with a summary | Trust the reader |
| Hedging boilerplate | State the limit precisely, once |

**On em-dashes specifically:** they are fine sparingly. Several per paragraph is
the single strongest tell of generated prose.

---

## Honesty rules

These are not stylistic. They are what makes the reports usable.

### Separate observation from inference

State what the data shows. Mark interpretation as interpretation.

> **Observation:** "All three upstreams are present in Frankfurt."
> **Inference:** "The most probable location is Frankfurt, on the basis that it is
> the only city common to all three."

### You cannot see intent

Never assert *why* an operator did something. Prepending is observable; "they
wanted to de-prefer this path" is inference; "they were trying to hide something"
is unfounded.

Where intent matters, say what would resolve it: *"Change records for 15:30–16:00
UTC would settle it."*

### Registry names are labels, not facts

`FTRICHAR-NET` records how a block was described at allocation, possibly decades
ago. Use them as identifiers, never as claims about current use. Say so once in
the report.

### State limits plainly

Every report should name:
- the **data floor** — and that earlier events are invisible
- **collector sampling** — a partial view, not the whole internet
- **sample size** — seven episodes is not a cadence
- what **cannot be determined** from routing data alone

One sentence each. Not a disclaimer section.

### Do not manufacture severity

If it's routine, say routine. Two of four published reports concluded "not an
incident" and were more useful for it. A report that says "this looks alarming and
isn't, here's why" is worth more than one that inflates.

### Record corrections

If analysis changed mid-investigation, say so and explain the error. The DoD
report has a "correction we made during analysis" callout. It costs nothing and
tells the reader the work was checked.

---

## Numbers and evidence

**Every number traces to a call.** If you can't reproduce it, cut it.

**Round in prose, exact in tables.** "Roughly 74%" in a sentence; `979 of 1,323`
in the figure caption.

**Give numbers a denominator.** "2,289 withdrawals" is noise. "979 of 1,323
tracked observations" is a fact.

**Tabular numerals** for anything in columns (`font-variant-numeric: tabular-nums`
is already in the template).

**Cite the source of each class of data** in the scope section: routing from
public collectors, registry from RDAP/whois, RPKI from published repositories.

---

## Visuals

Charts follow the same honesty rules.

- **Colour encodes meaning.** In handover charts, one colour per party, held
  consistent across every figure in the document.
- **Separate artifact from signal visually.** When one collector dominates, show
  it as a separate stacked series so the reader sees the split.
- **Caption what the reader should take away**, plus the caveat. Captions are
  where "these are registry labels, not current facts" belongs.
- **Show gaps.** Absence of data is data — the handover strip renders
  "not announced" explicitly rather than leaving whitespace.
- **Never a dual-axis chart.** Two measures of different scale get two charts.

---

## Recommendations

When the report has an actionable audience:

- **Prioritise** — High / Medium / Low, ordered
- **Say what to do, not what's wrong** — "Create ROAs authorising AS21799 with
  max_length 24", not "RPKI coverage is inadequate"
- **Explain the consequence** — what changes if they do it
- **Include the ones you can't verify** — "Provider-side logs for 00:05–00:15 UTC
  would establish whether the cause was at the edge or upstream"
- **Order by impact, not by section order.** The AS54994 report leads with the
  court's unsigned space, which appears late in the evidence.

---

## Titles

Descriptive, specific, no clickbait.

> ✅ "AS54994: a court address block changes hands, ten months late"
> ✅ "Recurring transient origin changes in US Army address space"
> ❌ "SHOCKING: Chinese CDN seizes US court network"
> ❌ "An investigation into AS54994"

The title should survive being wrong about the interesting part.
