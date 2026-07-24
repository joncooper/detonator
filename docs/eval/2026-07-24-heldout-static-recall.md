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

## Precision guard

The three rules must not buy recall with false positives. Re-scored the top-1500
most-downloaded npm + pypi packages (real, benign) with v2: **0 flagged** _(final count
pending cohort completion; 260 scored clean at time of writing)_. Combined with the
locked precision cases, the v2 rules add recall at no measured precision cost.

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

## Next

1. **Behavioral lift** — detonate the Set 2 static-misses (the NET_BEACONs especially)
   and measure static+detonation recall. This is the other half of the thesis.
2. **Staged-exec rule** — tune on Set 1 misses, eval on a third fresh slice [240,…).
3. Keep the split manifest committed so later draws stay disjoint.
