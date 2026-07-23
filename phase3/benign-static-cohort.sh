#!/usr/bin/env bash
# Local precision gate for the static rules. Fetches popular, legitimate npm/PyPI
# packages and runs dscore STATIC-ONLY (-tarball, no -trace), requiring that none
# block or quarantine. These are benign registry packages — safe to download to a
# laptop — so this needs no burner and no malware. It is the local analogue of the
# burner's benign detonation cohort, and it makes static-rule changes bankable
# without a detonation run.
#
#   go build -o dscore ./cmd/dscore && phase3/benign-static-cohort.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DSCORE="$ROOT/dscore"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
[ -x "$DSCORE" ] || { echo "build dscore first: go build -o dscore ./cmd/dscore"; exit 2; }

# A spread of shapes that stress the rules: minified bundles, native-build
# postinstalls (node-gyp/prebuilt fetch), env/config libs, networking clients.
NPM=(lodash react chalk express debug commander axios esbuild core-js bcrypt sharp node-gyp webpack typescript rimraf dotenv ws node-fetch)
PYPI=(requests numpy click flask urllib3 setuptools six certifi pyyaml rich cryptography boto3)

fail=0
score() { # eco name file
	out=$("$DSCORE" -tarball "$3" -ecosystem "$1" -name "$2" 2>/dev/null)
	dec=$(echo "$out" | python3 -c "import sys,json;print(json.load(sys.stdin)['decision'])" 2>/dev/null)
	rules=$(echo "$out" | python3 -c "import sys,json;print(','.join(sorted(set(s['rule'] for s in json.load(sys.stdin).get('signals',[])))))" 2>/dev/null)
	printf "  %-9s %-14s %-11s %s\n" "$1" "$2" "${dec:-ERR}" "$rules"
	case "$dec" in block|quarantine) fail=$((fail+1)); echo "    ^^ FLAGGED (precision regression)";; esac
}

echo "=== npm ==="
for p in "${NPM[@]}"; do
	url=$(curl -s "https://registry.npmjs.org/$p/latest" | python3 -c "import sys,json;print(json.load(sys.stdin)['dist']['tarball'])" 2>/dev/null)
	[ -z "$url" ] && { echo "  skip $p (no url)"; continue; }
	f="$WORK/$p.tgz"; curl -s -o "$f" "$url" 2>/dev/null || continue
	score npm "$p" "$f"
done

echo "=== pypi (sdist) ==="
for p in "${PYPI[@]}"; do
	url=$(curl -s "https://pypi.org/pypi/$p/json" | python3 -c "import sys,json;d=json.load(sys.stdin);v=d['info']['version'];print(next(u['url'] for u in d['releases'][v] if u['url'].endswith('.tar.gz')))" 2>/dev/null)
	[ -z "$url" ] && { echo "  skip $p (no sdist)"; continue; }
	f="$WORK/$(basename "$url")"; curl -s -o "$f" "$url" 2>/dev/null || continue
	score pypi "$p" "$f"
done

echo
if [ "$fail" -eq 0 ]; then echo "PASS: 0 benign packages blocked/quarantined"; else echo "FAIL: $fail benign package(s) flagged"; fi
exit "$fail"
