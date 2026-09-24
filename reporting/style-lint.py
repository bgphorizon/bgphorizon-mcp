#!/usr/bin/env python3
"""Style lint for BGPHorizon reports.

Enforces the "Banned" table in WRITING-GUIDE.md on a rendered report (HTML) or a
Markdown draft. Exit 1 on any error; Title Case and question headings are
warnings.

    ./style-lint.py report.html
    ./style-lint.py draft.md
    ./style-lint.py reporting/*.md docs/*.md      # repo-wide sweep

Files that document the rules (and so must quote the banned words) opt out with
a "style-lint: self-exempt" marker.
"""
import re
import sys

BANNED = [
    (r"\bnot (just|only|merely|simply) [^.;:]{1,60}?,? (but|it'?s|it is)\b", "not X but Y"),
    (r"\bit'?s not [^.;:]{1,40}?, it'?s\b", "it's not X, it's Y"),
    (r"\b(notably|interestingly|importantly|crucially|essentially|arguably)\b", "editorial adverb"),
    (r"\b(it'?s|it is) worth noting\b", "filler"),
    (r"\bkeep in mind\b", "filler"),
    (r"\b(why this matters|key takeaways?|bottom line|in summary|tl;dr)\b", "summary lead-in"),
    (r"\b(deep dive|unpack|leverag(e|es|ing)|robust|comprehensive|seamless(ly)?|landscape|journey)\b", "marketing word"),
    (r"\b(classic|textbook|the shape of|smoking gun|red flag|tell-?tale)\b", "color word"),
    (r"\b(actually|really)\b", "filler"),
]


def visible_text(src: str, is_html: bool):
    if is_html:
        body = re.sub(r"<!--.*?-->|<style.*?</style>|<script.*?</script>", "", src, flags=re.S)
        heads = re.findall(r"<h[1-4][^>]*>(.*?)</h[1-4]>", body, flags=re.S)
        heads += re.findall(r'class="(?:kicker|sec-title|fig-title|co-title)[^"]*"[^>]*>(.*?)<', body, flags=re.S)
        heads = [" ".join(re.sub(r"<[^>]+>", " ", h).split()) for h in heads]
        text = re.sub(r"<[^>]+>", " ", body)
        text = re.sub(r"&mdash;|&#8212;", "—", text)
        return text, heads
    heads = re.findall(r"^#{1,4}\s+(.+)$", src, flags=re.M)
    return src, heads


# A file that documents the rules has to quote the words it bans. Those carry
# this marker so a repo-wide run reports real prose problems instead of drowning
# in its own examples.
EXEMPT_MARKER = "style-lint: self-exempt"


def lint(path: str):
    src = open(path, encoding="utf-8").read()
    if EXEMPT_MARKER in src:
        return [], []
    text, heads = visible_text(src, path.lower().endswith((".html", ".htm")))
    errs, warns = [], []
    for m in re.finditer(r".{0,50}—.{0,50}", text):
        errs.append("em-dash: " + " ".join(m.group(0).split()))
    for pat, label in BANNED:
        for m in re.finditer(r".{0,40}" + pat + r".{0,40}", text, flags=re.I):
            errs.append(f"{label}: " + " ".join(m.group(0).split()))
    for h in heads:
        # Product and organisation names are capitalised legitimately, and a
        # heading full of them is not Title Case. Internal capitals (RouteViews,
        # BGPHorizon, LangChain) and slash-separated lists are strong enough
        # signals to skip: a warning that cries wolf gets ignored, and then the
        # real ones do too.
        if "/" in h or re.search(r"[a-z][A-Z]", h):
            continue
        words = [w for w in re.findall(r"[A-Za-z][A-Za-z'-]*", h) if len(w) > 3]
        caps = [w for w in words if w[0].isupper() and not w.isupper()]
        if len(words) >= 3 and len(caps) >= len(words) - 1:
            warns.append("Title Case heading: " + h)
        if h.rstrip().endswith("?"):
            warns.append("question heading: " + h)
    return errs, warns


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    failed = False
    many = len(sys.argv) > 2
    for path in sys.argv[1:]:
        errs, warns = lint(path)
        if many and not errs and not warns:
            continue
        if many:
            print(path)
        for w in warns:
            print("   ! " + w)
        if errs:
            print("  STYLE LINT FAILED:")
            for e in errs:
                print("   - " + e)
            failed = True
    if failed:
        sys.exit(1)
    if not many:
        print("  style OK")


if __name__ == "__main__":
    main()
