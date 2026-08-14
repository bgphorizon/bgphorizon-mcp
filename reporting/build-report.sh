#!/usr/bin/env bash
# Build a BGPHorizon report: inline CSS, validate, render PDF + screenshot.
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
# strip comments and style/script before checking structure — comments legitimately
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

# ---- 3. render ---------------------------------------------------------------
find_chrome() {
  for c in google-chrome chromium chromium-browser \
           "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe" \
           "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    command -v "$c" >/dev/null 2>&1 && { echo "$c"; return; }
    [ -x "$c" ] && { echo "$c"; return; }
  done
}
CHROME="$(find_chrome || true)"

if [ -z "${CHROME:-}" ]; then
  echo "  no Chrome found — HTML built, skipping PDF/PNG"
  echo "  → $OUT/$NAME.html"
  exit 0
fi

# WSL: Chrome needs a Windows-visible path
ABS="$(cd "$OUT" && pwd)/$NAME.html"
URL="file://$ABS"
if [[ "$CHROME" == /mnt/c/* ]]; then
  WINDIR="/mnt/c/temp/bgphorizon_build"; mkdir -p "$WINDIR"
  cp "$OUT/$NAME.html" "$WINDIR/"
  URL="file:///C:/temp/bgphorizon_build/$NAME.html"
  PDF_OUT="C:\\temp\\bgphorizon_build\\$NAME.pdf"
  PNG_OUT="C:\\temp\\bgphorizon_build\\$NAME.png"
else
  PDF_OUT="$(cd "$OUT" && pwd)/$NAME.pdf"
  PNG_OUT="$(cd "$OUT" && pwd)/$NAME.png"
fi

"$CHROME" --headless --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$PDF_OUT" "$URL" 2>/dev/null || true
"$CHROME" --headless --disable-gpu --window-size=1200,2400 \
  --screenshot="$PNG_OUT" "$URL" 2>/dev/null || true

if [[ "$CHROME" == /mnt/c/* ]]; then
  cp "$WINDIR/$NAME.pdf" "$OUT/" 2>/dev/null || true
  cp "$WINDIR/$NAME.png" "$OUT/" 2>/dev/null || true
fi

python3 - "$OUT/$NAME.pdf" <<'PY'
import sys, os
p = sys.argv[1]
if not os.path.exists(p):
    print("  PDF not produced"); sys.exit(0)
d = open(p, 'rb').read()
pages = d.count(b'/Type /Page') - d.count(b'/Type /Pages')
print(f"  PDF OK — {pages} pages, {len(d)//1024} KB, valid={d[:5] == b'%PDF-'}")
PY

echo "  → $OUT/$NAME.{html,pdf,png}"
echo
echo "Now work through reporting/QA-CHECKLIST.md — especially §5, open the PNG."
