# QA Checklist

Run before publishing. Every error that reached a draft was caught here, not
during research.

---

## 1. Data correctness

- [ ] **Every number traces to a specific call.** No figure you cannot reproduce.
- [ ] **Re-derive headline figures from source**, don't trust your notes.
- [ ] **One data path per report.** Rollup and raw-event counts disagree by ~21%.
      Pick one, say which in the scope section.
- [ ] **Window-edge events discarded or flagged.** Anything dated on day one of
      the window may be censored. This corrected one headline count from 382 → 367.
- [ ] **Persistence confirmed** for every claimed change. Not `first_seen`.
- [ ] **Concentration checked** for every volume claim. One vantage point ≠ event.
- [ ] **Direction verified** on every conflict. Who is the invalid party?
- [ ] **Every RPKI/IRR row actually queried.** Two rows once appeared in a draft
      table that had never been checked; both happened to be right, which is worse.
- [ ] **Entities appear only if verified.** One ASN sat in a draft table without a
      single lookup.

Machine-check it:

```python
# extract figures from the rendered HTML, diff against source JSON
import re, json
s = open('report.html').read()
src = json.load(open('report_data.json'))
for prefix, v in src['prefixes'].items():
    m = re.search(re.escape(prefix) + r'.*?<td class="num">([\d,]+)</td>', s, re.S)
    assert m and int(m.group(1).replace(',', '')) == v['ann'], prefix
```

---

## 2. Claims

- [ ] **Observation vs inference marked** throughout.
- [ ] **No intent asserted.** No "they wanted to", "in order to hide".
- [ ] **Registry names framed as labels**, with the caveat stated once.
- [ ] **Limits stated**: data floor, collector sampling, sample size.
- [ ] **Corrections recorded** if the analysis changed.
- [ ] **Severity not inflated.** If routine, say routine.
- [ ] **Unverified relationships excluded or explicitly flagged.** The
      Meteverse↔CDNetworks link was left as "indicated, not established".

---

## 3. Arithmetic

- [ ] Percentages match their fractions.
- [ ] Chart bar widths match the values (`value / max × 100`).
- [ ] Totals equal the sum of parts.
- [ ] Date arithmetic correct — gap days, durations, windows.
- [ ] Counts consistent between prose, tables and captions.

---

## 4. Document

- [ ] **HTML validates** — no unclosed tags:

```python
import re
VOID = {'area','base','br','col','embed','hr','img','input','link','meta','source','track','wbr'}
body = re.sub(r'<style.*?</style>', '', open('report.html').read(), flags=re.S)
stack = []
for close, name, _, self_close in re.findall(r'<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*?)(/?)>', body):
    n = name.lower()
    if n in VOID or self_close == '/': continue
    if close: assert stack and stack.pop() == n, f'mismatch at </{n}>'
    else: stack.append(n)
assert not stack, f'unclosed: {stack}'
```

- [ ] **No undefined CSS variables.**
- [ ] **Both themes styled** — check light and dark.
- [ ] **Print stylesheet works** — render the PDF and page through it.
- [ ] **Tables scroll** rather than pushing the body sideways.
- [ ] **Chart row counts match** the source series length.

---

## 5. Render and look at it

Structural validation does not catch layout. Open it.

```bash
chrome --headless --disable-gpu --window-size=1200,2400 \
  --screenshot=out.png file:///path/report.html
chrome --headless --disable-gpu --no-pdf-header-footer \
  --print-to-pdf=out.pdf file:///path/report.html
```

- [ ] No label collisions or overflow.
- [ ] Glyphs render (an ellipsis in a monospace column read as a stray dash and
      had to be removed).
- [ ] No prose accidentally set in monospace.
- [ ] Wordmark and headings correct.
- [ ] PDF page count sane; nothing split badly across pages.

---

## 6. Final read

- [ ] Read the standfirst alone. Does it state the finding?
- [ ] Read only the section headings. Do they tell the story in order?
- [ ] Read the recommendations alone. Are they actionable without the body?
- [ ] Scan for the tells in [`WRITING-GUIDE.md`](WRITING-GUIDE.md#avoid) —
      em-dash density, repeated "not X but Y", uniform sentence length.
- [ ] Would you be comfortable if the subject of the report read it?

That last one is the real test. Every published report should be defensible to the
network it describes.

---

## Errors this checklist has caught

Kept as evidence that the pass is not ceremonial.

| Error | Caught by |
|---|---|
| "Staged migration" that was transient episodes | §1 persistence |
| 3× volume rise that was one flapping collector peer | §1 concentration |
| 382 handoffs (15 were window-edge artifacts) → 367 | §1 window-edge |
| "No IRR coverage" — 9 of 13 blocks had objects | §1 every row queried |
| "Zero withdrawals from this peer" — there were 2 | §1 re-derive |
| Two RPKI rows never actually queried | §1 every row queried |
| An ASN in a table with no verification | §2 entities verified |
| Prose phrase accidentally set in monospace | §5 render |
| Ellipsis glyph unreadable in mono column | §5 render |
| Inventory row using rollup while others used raw | §1 one data path |
