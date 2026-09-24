#!/usr/bin/env bash
# Build a BGPHorizon report: inline CSS, validate structure and style, render PDF + screenshot.
#
#   ./build-report.sh my-report.html [outdir]
#
# Produces <outdir>/<name>.html (self-contained), .pdf, and .png.

set -euo pipefail

SRC="${1:?usage: build-report.sh <report.html> [outdir]}"
OUT="${2:-./build}"
NAME="$(basename "${SRC%.html}")"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CSS="$HERE/template-assets/report.css"

mkdir -p "$OUT"

# ---- 1. inline the stylesheet if the placeholder is still present -------------
python3 - "$SRC" "$CSS" "$OUT/$NAME.html" <<'PY'
import sys, re
src, css, dst = sys.argv[1:4]
html = open(src).read()
marker = '/* ---- inline the contents of template-assets/report.css here ---- */'
if marker in html:
    html = html.replace(marker, open(css).read())
    print("  inlined report.css")
else:
    print("  stylesheet already inline")
open(dst, 'w').write(html)
PY

# ---- 2. structural validation ------------------------------------------------
python3 - "$OUT/$NAME.html" <<'PY'
import sys, re
s = open(sys.argv[1]).read()
VOID = {'area','base','br','col','embed','hr','img','input','link','meta','source','track','wbr'}
# strip comments and style/script before checking structure; comments legitimately
# contain partial HTML snippets (the template's component reference does)
body = re.sub(r'<!--.*?-->', '', s, flags=re.S)
body = re.sub(r'<style.*?</style>', '', body, flags=re.S)
body = re.sub(r'<script.*?</script>', '', body, flags=re.S)
stack, errs = [], []
for close, name, _attrs, self_close in re.findall(r'<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*?)(/?)>', body):
    n = name.lower()
    if n in VOID or self_close == '/':
        continue
    if close:
        if not stack or stack[-1] != n:
            errs.append(f'</{n}> closes <{stack[-1] if stack else "nothing"}>')
        else:
            stack.pop()
    else:
        stack.append(n)
if stack: errs.append(f'unclosed at EOF: {stack}')

used = set(re.findall(r'var\((--[a-z0-9-]+)\)', s))
defined = set(re.findall(r'^\s*(--[a-z0-9-]+)\s*:', s, flags=re.M))
missing = sorted(used - defined)
if missing: errs.append(f'undefined CSS vars: {missing}')

if re.search(r'\{\{[A-Z_ ]+\}\}', body):
    errs.append('unreplaced {{PLACEHOLDER}} remains')

if errs:
    print("  VALIDATION FAILED:")
    for e in errs: print("   -", e)
    sys.exit(1)
print("  structure OK")
PY

# ---- 2b. style lint ----------------------------------------------------------
# The "Banned" table in WRITING-GUIDE.md: em-dashes, "not X but Y", filler words.
python3 "$HERE/style-lint.py" "$OUT/$NAME.html"

# ---- 3. render ---------------------------------------------------------------
find_chrome() {
  for c in ${CHROME_BIN:-} google-chrome google-chrome-stable chromium chromium-browser \
           "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe" \
           "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    command -v "$c" >/dev/null 2>&1 && { echo "$c"; return; }
    [ -x "$c" ] && { echo "$c"; return; }
  done
}

ABS="$(cd "$OUT" && pwd)/$NAME.html"
PDF_FINAL="$(cd "$OUT" && pwd)/$NAME.pdf"
PNG_FINAL="$(cd "$OUT" && pwd)/$NAME.png"
rm -f "$PDF_FINAL" "$PNG_FINAL"

render_with_chrome() {
  local chrome="$1" url="file://$ABS" pdf="$PDF_FINAL" png="$PNG_FINAL" windir=""
  # WSL: a Windows Chrome needs a Windows-visible path. If WSL interop is disabled the .exe
  # cannot run at all; the fallback below then takes over.
  if [[ "$chrome" == /mnt/c/* ]]; then
    windir="/mnt/c/temp/bgphorizon_build"; mkdir -p "$windir" || return 1
    cp "$OUT/$NAME.html" "$windir/" || return 1
    url="file:///C:/temp/bgphorizon_build/$NAME.html"
    pdf="C:\\temp\\bgphorizon_build\\$NAME.pdf"
    png="C:\\temp\\bgphorizon_build\\$NAME.png"
  fi
  "$chrome" --headless --disable-gpu --no-pdf-header-footer \
    --print-to-pdf="$pdf" "$url" >/dev/null 2>&1 || true
  "$chrome" --headless --disable-gpu --window-size=1200,2400 \
    --screenshot="$png" "$url" >/dev/null 2>&1 || true
  if [[ -n "$windir" ]]; then
    cp "$windir/$NAME.pdf" "$OUT/" 2>/dev/null || true
    cp "$windir/$NAME.png" "$OUT/" 2>/dev/null || true
  fi
  [[ -s "$PDF_FINAL" ]]
}

# Fallback: Playwright's bundled Chromium (pip install playwright && playwright install chromium).
render_with_playwright() {
  python3 - "$ABS" "$PDF_FINAL" "$PNG_FINAL" <<'PYR'
import sys
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit(1)
src, pdf, png = sys.argv[1:4]
with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page(viewport={"width": 1200, "height": 2400})
    page.goto("file://" + src)
    page.screenshot(path=png)
    page.emulate_media(media="print")
    page.pdf(path=pdf, print_background=True, prefer_css_page_size=True)
    b.close()
PYR
}

CHROME="$(find_chrome || true)"
RENDERED=""
if [[ -n "${CHROME:-}" ]] && render_with_chrome "$CHROME"; then
  RENDERED="chrome ($CHROME)"
elif render_with_playwright 2>/dev/null; then
  RENDERED="playwright"
fi

if [[ -z "$RENDERED" ]]; then
  echo "  could not render PDF/PNG: no working Chrome/Chromium"
  [[ -n "${CHROME:-}" ]] && echo "    found $CHROME but it did not produce output (on WSL, check that interop is enabled)"
  echo "    fix: install chromium, set CHROME_BIN=/path/to/chrome, or"
  echo "         pip install playwright && python3 -m playwright install chromium"
  echo "  → $OUT/$NAME.html (validated, style-linted)"
  exit 0
fi
echo "  rendered with $RENDERED"

python3 - "$OUT/$NAME.pdf" <<'PY'
import sys, os
p = sys.argv[1]
if not os.path.exists(p):
    print("  PDF not produced"); sys.exit(0)
d = open(p, 'rb').read()
pages = d.count(b'/Type /Page') - d.count(b'/Type /Pages')
print(f"  PDF OK: {pages} pages, {len(d)//1024} KB, valid={d[:5] == b'%PDF-'}")
PY

echo "  → $OUT/$NAME.{html,pdf,png}"
echo
echo "Now work through reporting/QA-CHECKLIST.md, especially §5: open the PNG."
