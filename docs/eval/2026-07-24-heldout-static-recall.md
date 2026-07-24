# Held-out static recall on cross-source-confirmed malware (2026-07-24)

First real held-out evaluation. Two disjoint random samples of 150, drawn from the
3,372 packages that **both** Datadog and the Backstabber's Knife Collection flag as
malicious (cross-source-confirmed, fetchable artifacts). Static-only — no detonation,
no panel. The point is an honest recall number the rules were not tuned to hit.

## Method

- **Pool:** Datadog ∩ Backstabber's = npm 2,751 + pypi 621 (see
  `docs/plan/corpus-and-eval-scaling.md`). Two curators independently flagged each,
  which cuts the ~28% CTF/PoC contamination raw Datadog carries.
- **Sampling:** deterministic. Rank each name by `md5(ecosystem:name)`; take a
  proportional 120 npm + 30 pypi. Set 1 is ranks [0,120)/[0,30); Set 2 is the disjoint
  slice [120,240)/[30,60). Reproducible, no overlap, no accidental leak.
- **Scoring:** `dscore -tarball` static path only. Artifacts fetched, unzipped, and
  repacked to registry-shape tarballs on the burner (custody — malware source never
  touches the laptop). "Caught" = block or quarantine; "missed" = allow.
- **Discipline:** Set 1 was scored **once** with the frozen v1 rules before any miss
  was inspected — that is the unbiased v1 number. Misses were then diagnosed and three
  rules added (v2). Set 2 — never inspected during that tuning — is the unbiased v2
  number.

## Result

| | rules | npm | pypi | total | recall |
|---|---|---|---|---|---|
| **Set 1** (unbiased v1) | v1 | 61/120 | 7/30 | 68/150 | **45.3%** |
| Set 1 (same-set lift) | v2 | — | — | 80/150 | 53.3% |
| **Set 2** (unbiased v2, fresh) | v2 | 67/120 | 12/30 | 79/150 | **52.7%** |

The load-bearing numbers are the two **bold** rows: 45.3% is what the frozen detector
actually caught on unseen cross-confirmed malware; 52.7% is the improved detector on a
second unseen sample. The +12 same-set lift (53.3%) and the fresh-set 52.7% agree to
within a point — the new rules **generalize**, they are not overfit to Set 1's misses.

pypi was the weak half (23% → static barely saw Python malware) and roughly doubled
(7→12/30) once it had obfuscation and webhook coverage.

## Why 45% and not 90%

The 71% from the phase-3 curated cohort was behavioral (detonation) on a hand-picked
set. This is **static-only** on a **random** draw. The gap is the honest cost of both.
Bucketing Set 1's 81 misses by source signature:

| bucket | n | recoverable by | 
|---|---|---|
| STAGED_EXEC (download/decode → exec) | 25 | tighter static rules |
| NET_BEACON (fetches at runtime) | 26 | **detonation** |
| OBFUSCATED | 10 | static obfuscation fingerprints |
| EXEC_ONLY | 9 | — |
| INERT / PoC (contamination) | 6 | nothing — correctly skipped |
| OTHER | 5 | — |

Two facts fall out. About **a third of the misses are behavioral** (NET_BEACON): a
package that only fetches its payload at runtime is invisible to any static rule and is
exactly what the detonation tier exists for. And **~7–12% of the "misses" are inert** —
dependency-confusion placeholders (`console.log('Hello, world!')`) and RCE-proof file
writes, labeled malicious by upload intent but carrying no payload. Static is *correct*
to pass them; they deflate the denominator.

## The three rules added (v2)

Each targets a miss cluster and is gated for precision. All emit `SevHigh` →
quarantine (fail-to-review), never an auto-block.

1. **Python string-escape obfuscation** (`obfuscated-code`, extended). `eval`/`exec`
   applied to an octal/hex escape-encoded string — the BlankOBF/Hyperion shape
   (`eval("\145\166\x61\x6c")`). The old fingerprint was JS `_0x`-only, so the entire
   Python stealer family scored allow. Recovers keyauthkey, axelo, wadokwaokda,
   robloxlogger. Benign Python never eval()s an escape-encoded literal.
2. **Shell recon in exec'd commands** (`host-recon-exfil`, extended). A `postinstall`
   that `exec`s `curl … $(whoami)/$(hostname) … cat /etc/passwd … | base64` — recon
   expressed as *shell* inside the command string, which the JS/Python-primitive
   detector missed. Recovers the oast.fun/interactsh beacon family (angular-trackjs).
   Fires only in install context, and only when recon **and** exfil are both present.
3. **Hardcoded Discord/Telegram webhook** (`hardcoded-webhook-exfil`, new). A webhook
   URL carrying a real snowflake id + token — the canonical token/cookie-stealer sink.
   Requiring the concrete id+token (not the bare API host) keeps client-library
   mentions out. Recovers xoloctwuaywkna and the Discord-stealer family.

Locked in by unit tests (`TestPythonEscapeObfuscation`, `TestShellReconExfilInHook`,
`TestHardcodedWebhookExfil`), each with a precision counter-case.

## Precision at scale

The rules must not buy recall with false positives. Re-scored the top-1500
most-downloaded npm + pypi packages (real, benign), static-only.

- **npm: 0 flagged / 1500.** Clean.
- **pypi: 26 flagged / 1421** with the initial v2 rules — **all pre-existing rules
  except one** (passlib, from the new shell-recon rule). This is the precision-at-scale
  workstream doing its job: benign scale surfaces FP classes a 30-package cohort never
  will. Diagnosing them drove a hardening pass (separate commits):
  - `passlib` (the one new-rule FP): `/etc/shadow` in a description docstring + an
    unrelated homepage URL. Rewrote shell-recon as a **proximity** match (recon token
    within 250 chars of a fetch/exec verb), so a real `curl "…$(whoami)…|base64"` beacon
    still fires but prose does not.
  - Placeholder IPs (`1.2.3.4`, repeated-octet `12.12.12.12`); Dockerfiles + build/
    packaging/nix dirs (`rm -rf /var` at image build); minified bundles (`mkfs`/`mkfifo`
    substrings in frontend chunks hard-BLOCKED streamlit + google-adk); PKG-INFO/egg-info
    metadata prose.

After the pass, **the 3 new rules are 0 FP across the full top-1500 npm + pypi**, and the
pypi residual is **9 / 1421 (~0.6%), all pre-existing rules** — genuine hard edges:
setup.py legitimately fetching at build (reportlab, statsmodels, vcrpy), a reverse-shell
*example* in a serial library (pyserial), a Dockerfile-generating `.py` (swesmith), a
wiper inside a test file (python-gnupg), a base64-URL in ansible-core, destructive build
steps in pep517 / openhands-sdk. These are documented, not fixed: distinguishing them
needs semantic context, and forcing them to `allow` risks real recall. No real C2/wiper
hides the way the fixed classes do, so recall is unaffected.

Two of the fixes were on the new rules themselves — `magika`'s hex-offset field names
(`offset_0x8000`) tripping the `_0x` fingerprint, and `re.compile("\x89…")` over
magic-byte signatures reading as escape-obfuscation. Both are the precision-at-scale
loop working as intended: a rule that looks clean on 30 packages meets its FP class at
1500 and gets tightened.

## Honest limits

- **Static-only.** The 52.7% is a floor. The 26/81 NET_BEACON misses are what the
  behavioral tier is for; the layered number (static + detonation + panel) is not
  measured here.
- **The STAGED_EXEC gap remains** (~25/150). Download-then-exec (`exec(urlopen().read())`,
  `exec(b64decode(...))`) is the largest recoverable cluster still missed. It is
  FP-prone; a precise rule needs its own tuning pass and a fresh held-out.
- **One cross-source pair.** Datadog ∩ Backstabber's is cleaner than either alone but is
  still two curators with overlapping sourcing. A third independent source would harden
  the label further.
- **Recall denominator includes contamination.** ~7–12% of the pool is inert PoC;
  true recall on packages that actually carry a payload is meaningfully higher than the
  headline.

## Behavioral lift (measured)

Static is only the first tier. To measure what the behavioral tier adds, I detonated
**Set 2's static-misses** — the packages static *allowed* — in the patched
package-analysis sandbox (import-phase continue + CI-env baits), and re-scored each with
the trace. Any flip from `allow` to block/quarantine is a behavioral catch static could
not have made.

**Containment.** Real malware, so egress runs behind a recording sinkhole: a fake DNS
resolver + TLS sink + iptables redirect. Verified before the run — a test connection to
`evil-c2-test.example` resolved to the sink, connected to the sink, and the sink
**captured the full request**; nothing reached the real internet. C2 lookups from live
samples (e.g. `packages.storeartifact.com`) landed in the sink, contained.

**Result (npm).** Of the **53 npm packages static allowed, detonation caught 34 (64%)**
(3 more errored/timed out in the sandbox). Combined with Set 2's static recall, npm goes
from **56% static-only (67/120) → 84% static+behavioral (101/120)**. Static missed these
because the payload is a runtime beacon — the source ships no visible C2, and only at
require/postinstall time does it resolve and connect to its collaborator host. The catches
came through diverse runtime signals, not one blunt rule:

| signal | n | what it caught |
|---|---|---|
| `unknown-domain` | 29 | C2 / collaborator beacons |
| `process-spawn` | 4 | shelling out at install/import |
| `data-destruction` | 3 | wipers that only fire at runtime |
| `dns-exfil` | 2 | data tunneled over DNS |
| `sensitive-read:ssh-private-key` | 1 | read `~/.ssh` (the honeytoken paid off) |
| `exfil-chain` | 1 | read-then-send |

This is the whole point of detonating: static and behavioral catch different things, and
the layered detector catches what neither tier catches alone.

**pypi is undercounted here — do not read the pypi rows as recall.** `pip` needs to fetch
build dependencies to reach an import-time payload, and the sinkhole's registry allowlist
is currently broken (the FORWARD DROP is ordered before the registry ACCEPTs; the host
can't even reach the anycast registry IP). So dep-requiring pypi stealers fail to install
and never run. Fixing the allowlist is the top detonation follow-up; until then the pypi
behavioral number is a floor, not a measurement.

## Next

1. **Staged-exec static rule** — the largest recoverable static gap (~25/150):
   `exec(urlopen().read())`, `exec(b64decode(...))`. FP-prone; tune on Set 1 misses,
   eval on a third fresh slice (`phase3/heldout/split.py … 3`), never Set 1 or Set 2.
2. **Fix the sinkhole registry allowlist** so pypi detonation gets real build deps and
   the pypi behavioral tier becomes a measurement, not a floor.
3. Keep the split manifest committed so later draws stay disjoint.
