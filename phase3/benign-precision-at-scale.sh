#!/usr/bin/env bash
# Precision at scale: static-score the top-N most-downloaded real packages and report
# the false-positive rate + every flagged case. Benign, offline — no burner, no codex.
# Extends benign-static-cohort.sh from 30 to thousands (docs/plan/corpus-and-eval-scaling.md).
#
#   go build -o dscore ./cmd/dscore
#   phase3/benign-precision-at-scale.sh pypi 1000 /tmp/prec
set -u
ECO="${1:-pypi}"; N="${2:-1000}"; OUT="${3:-/tmp/prec}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; DSCORE="$ROOT/dscore"
[ -x "$DSCORE" ] || { echo "build dscore first"; exit 2; }
mkdir -p "$OUT"; RES="$OUT/$ECO-results.tsv"; : > "$RES"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# top-N names
if [ "$ECO" = pypi ]; then
  curl -sL -m 30 "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json" \
    | python3 -c "import sys,json;print('\n'.join(r['project'] for r in json.load(sys.stdin)['rows']))" | head -n "$N" > "$OUT/names.txt"
else
  # npm: rank a name list by the downloads API is slow; expects $OUT/names.txt pre-seeded.
  [ -s "$OUT/names.txt" ] || { echo "npm: seed $OUT/names.txt with package names first"; exit 2; }
  head -n "$N" "$OUT/names.txt" > "$OUT/names.head"; mv "$OUT/names.head" "$OUT/names.txt"
fi
echo "scoring $(wc -l < "$OUT/names.txt" | tr -d ' ') $ECO packages (static-only)…"

flag=0; n=0
while read -r p; do
  [ -z "$p" ] && continue
  n=$((n+1))
  if [ "$ECO" = pypi ]; then
    url=$(curl -sL -m 20 "https://pypi.org/pypi/$p/json" 2>/dev/null | python3 -c "import sys,json
try:
 d=json.load(sys.stdin);v=d['info']['version']
 print(next((u['url'] for u in d['releases'].get(v,[]) if u['url'].endswith('.tar.gz')),''))
except Exception: print('')" 2>/dev/null)
  else
    url=$(curl -sL -m 20 "https://registry.npmjs.org/$p/latest" 2>/dev/null | python3 -c "import sys,json
try: print(json.load(sys.stdin)['dist']['tarball'])
except Exception: print('')" 2>/dev/null)
  fi
  [ -z "$url" ] && { echo -e "$p\tNO_ARTIFACT\t" >> "$RES"; continue; }
  f="$WORK/pkg"; curl -sL -m 60 -o "$f" "$url" 2>/dev/null || { echo -e "$p\tFETCH_ERR\t" >> "$RES"; continue; }
  out=$("$DSCORE" -tarball "$f" -ecosystem "$ECO" -name "$p" 2>/dev/null)
  dec=$(echo "$out" | python3 -c "import sys,json;print(json.load(sys.stdin)['decision'])" 2>/dev/null)
  rules=$(echo "$out" | python3 -c "import sys,json;print(','.join(sorted(set(s['rule'] for s in json.load(sys.stdin).get('signals',[]) if s['severity'] in ('high','critical','medium')))))" 2>/dev/null)
  echo -e "$p\t${dec:-ERR}\t$rules" >> "$RES"
  case "$dec" in block|quarantine) flag=$((flag+1)); echo "  FLAG[$flag]: $p -> $dec ($rules)";; esac
  [ $((n % 200)) -eq 0 ] && echo "  … $n scored, $flag flagged so far"
done < "$OUT/names.txt"

echo
echo "=== $ECO precision @ scale: $n scored, $flag flagged (block/quarantine) ==="
echo "FP rate: $(python3 -c "print(f'{$flag/$n*100:.2f}%')" 2>/dev/null)"
echo "flagged breakdown:"; awk -F'\t' '$2=="block"||$2=="quarantine"{print $2"\t"$3}' "$RES" | sort | uniq -c | sort -rn | head -20
