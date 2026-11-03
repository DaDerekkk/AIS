#!/bin/sh
# Offline build with an existing TeX installation. No downloads or installs.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$HERE/../.." && pwd)
if [ -n "${BUILD_DIR:-}" ]; then
  mkdir -p "$BUILD_DIR"
  OUT=$(CDPATH= cd -- "$BUILD_DIR" && pwd)
else
  OUT=$(mktemp -d "${TMPDIR:-/tmp}/diagnostic-tex.XXXXXX")
  trap 'rm -rf "$OUT"' EXIT HUP INT TERM
fi
cd "$HERE"
if command -v tectonic >/dev/null 2>&1; then
  tectonic --only-cached --untrusted --keep-logs --outdir "$OUT" main.tex
elif command -v pdflatex >/dev/null 2>&1; then
  pdflatex -no-shell-escape -interaction=nonstopmode -halt-on-error -output-directory="$OUT" main.tex
  pdflatex -no-shell-escape -interaction=nonstopmode -halt-on-error -output-directory="$OUT" main.tex
else
  printf '%s\n' 'No preinstalled TeX engine found. Use the included PDF; nothing was installed.' >&2
  exit 1
fi
cp "$OUT/main.pdf" "$REPO/report/comp7611_diagnostic_report.pdf"
