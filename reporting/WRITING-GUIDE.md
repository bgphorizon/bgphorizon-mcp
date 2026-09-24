# Writing Guide

<!-- style-lint: self-exempt: this file quotes the words it bans. -->

House style for BGPHorizon reports. The research is covered in
[`METHODOLOGY.md`](METHODOLOGY.md); this is about the document.

---

## What a report is

A record of what the routing data showed, written so a competent non-specialist
can follow it and a specialist can check it. It is a technical document in the
same plain register as the platform itself.

The reader is usually one of:
- a **network operator** who needs to know whether to act
- a **security analyst** deciding whether it matters
- a **manager** who needs the impact in one sentence

Write for all three by putting the plain-language answer first and the evidence
underneath.

---

## Structure

```
Masthead                     brand, "Routing report"
Title + standfirst           the finding in 3–4 sentences, no suspense
Dateline                     generated-at, window, subjects
Stat tiles                   4–5 numbers that frame the scale
Glossary (collapsed)         plain-language terms
01 …                         numbered sections, evidence-ordered
Recommendations              prioritized, actionable (if applicable)
Sources and scope            provenance + limits
```

Number sections. Readers cite them.

Order sections by what the reader needs to know first, never by the order you
discovered things. The AS54994 report was researched by stumbling onto a MOAS;
it's written as parties → transfer → handover → validation gap.

---

## Style rules

Reports use the same plain register as the platform's own pages and tooltips.
The test is whether a network engineer would believe a colleague wrote it.

**Lead with the answer.** The standfirst states the finding. No "we set out to
investigate", no build-up.

**One idea per sentence, but vary the length.** If a sentence needs a dash or a
second clause to carry a second point, make it two. Then read the paragraph
aloud: a run of sentences all the same length reads as generated whether they
are all long or all short. A short one after two longer ones is what a person
writing quickly actually produces.

**Concrete nouns, specific numbers.** "Roughly 74% of observed vantage points"
beats "a significant portion of the internet".

**Active voice. Past tense for events, present for current state.**

**Answer, do not narrate.** Never restate the question before answering it, and
never announce what a section is about to do. "To determine whether this was a
hijack, we examined the origin history" is two wasted lines: the finding and its
evidence say the same thing and say it faster.

**Confidence should vary with the evidence.** Say "AS20473 originated these
prefixes for the whole window" flatly when it is flat, and "the cause cannot be
determined from routing data" flatly when it cannot. Hedging everything to the
same degree is the giveaway: it means the writer never weighed anything.

**No filler.** Delete any word that does not change the meaning of the
sentence. "Actually", "really", "simply", "clearly" and "essentially" never
survive this test.

### Banned

These are hard rules, not preferences. The QA checklist greps for them and the
build script fails on the first three.

| Never | Instead |
|---|---|
| Em-dashes (`—`), in any position | A full stop, comma, colon or semicolon |
| "not X but Y", "not just X, it's Y", "it's not X, it's Y" | State Y. Mention X only if the reader would otherwise assume it |
| "Notably", "Interestingly", "Importantly", "Crucially", "It's worth noting", "Keep in mind" | Delete the word and keep the sentence |
| "Why this matters", "Key takeaways", "Bottom line", "In summary", "TL;DR" as headings or lead-ins | Put the point in the section's first sentence |
| "Deep dive", "unpack", "leverage", "robust", "comprehensive", "seamless", "landscape", "journey" | "Examine", "explain", "use", "reliable", "complete", plain nouns |
| "Classic", "textbook", "the shape of", "smoking gun", "red flag", "tell-tale" | Describe what was observed |
| Rhetorical questions ("So what changed?") | The answer |
| A summary paragraph closing each section | Nothing. The section ends when the evidence does |
| Three parallel items for rhythm ("fast, cheap and reliable") when only two are true | Only the items that are true |
| Emoji, exclamation marks, "SHOCKING"-style intensifiers | None |

The allowance is zero. If a contrast is the point ("the platform ingests BGP
updates rather than full tables"), write it as two plain statements: what the
data is, then what it does not cover.

### Headings

Section titles, figure titles and callout titles follow the platform's
conventions:

- **Sentence case.** "Origin changes in the court block", not "Origin Changes
  In The Court Block".
- **Descriptive, literal, complete.** The heading says what the section
  contains. "Upstream and downstream relationships", not "Who they depend on".
  "Reachability during the outage", not "Going dark".
- **No fragments for effect**, no puns, no colon-teasers ("One prefix: two
  stories"). A reader skimming only the headings should get the facts, not a
  trailer.
- **No question headings.**
- Figure captions state what the figure shows and its caveat, in that order,
  as plain sentences.

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
- the **data floor**, and that earlier events are invisible
- **collector sampling**: a partial view, not the whole internet
- **sample size**: seven episodes is not a cadence
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

- **Color encodes meaning.** In handover charts, one color per party, held
  consistent across every figure in the document.
- **Separate artifact from signal visually.** When one collector dominates, show
  it as a separate stacked series so the reader sees the split.
- **Caption what the reader should take away**, plus the caveat. Captions are
  where "these are registry labels, not current facts" belongs.
- **Show gaps.** Absence of data is data. The handover strip renders
  "not announced" explicitly rather than leaving whitespace.
- **Never a dual-axis chart.** Two measures of different scale get two charts.

---

## Recommendations

When the report has an actionable audience:

- **Prioritize**: High / Medium / Low, ordered
- **Say what to do, not what's wrong**: "Create ROAs authorizing AS21799 with
  max_length 24", not "RPKI coverage is inadequate"
- **Explain the consequence**: what changes if they do it
- **Include the ones you can't verify**: "Provider-side logs for 00:05–00:15 UTC
  would establish whether the cause was at the edge or upstream"
- **Order by impact, not by section order.** The AS54994 report leads with the
  court's unsigned space, which appears late in the evidence.

---

## Titles

Descriptive, specific, sentence case. The title is a statement of what the
report found, in the register of a status page.

> Good: "AS54994: court address block reassigned ten months after the transfer"
> Good: "Recurring transient origin changes in US Army address space"
> Bad: "SHOCKING: Chinese CDN seizes US court network"
> Bad: "An investigation into AS54994"
> Bad: "AS54994: a tale of two origins"

The title should still be accurate if the interesting part turns out to be
routine.
