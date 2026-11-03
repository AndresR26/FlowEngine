#!/usr/bin/env bash
# Genera las versiones PDF de los manuales / Builds PDF versions of the manuals
# Requiere / Requires: pandoc + google-chrome (o chromium)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/docs/pdf"; mkdir -p "$OUT"
TMP="$(mktemp -d)"
CHROME="$(command -v google-chrome || command -v chromium || command -v chromium-browser)"
build () {   # $1 = md relativo a docs/, $2 = nombre pdf, $3 = título
  local src="$ROOT/docs/$1" dir; dir="$(dirname "$src")"
  # quita bloques <details> (Mermaid) que no se renderizan en PDF
  perl -0pe 's/<details>.*?<\/details>\n?//gs' "$src" > "$dir/.tmp_pdf.md"
  pandoc "$dir/.tmp_pdf.md" -f gfm -t html5 -s --metadata title="$3" \
    --css "$ROOT/tools/pdf.css" --embed-resources --resource-path="$dir" \
    -V title= -o "$TMP/$2.html" 2>/dev/null
  rm -f "$dir/.tmp_pdf.md"
  "$CHROME" --headless=new --no-sandbox --disable-gpu --no-pdf-header-footer \
    --print-to-pdf="$OUT/$2.pdf" "file://$TMP/$2.html" 2>/dev/null
  echo "OK  docs/pdf/$2.pdf"
}
build es/manual_tecnico.md    Manual_Tecnico_FlowEngine_ES "Manual Técnico — FlowEngine"
build es/manual_usuario.md    Manual_Usuario_FlowEngine_ES "Manual de Usuario — FlowEngine"
build en/technical_manual.md  Technical_Manual_FlowEngine_EN "Technical Manual — FlowEngine"
build en/user_manual.md       User_Manual_FlowEngine_EN "User Manual — FlowEngine"
rm -rf "$TMP"
