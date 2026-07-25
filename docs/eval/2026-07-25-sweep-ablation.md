# Threshold sweep + rule ablation: the gate is coverage-limited, not calibration-limited (2026-07-25)

The engine has always been a fixed ladder — Critical blocks, one High quarantines, two
Mediums quarantine — and we had grown to 32 rules, **22 of which can quarantine on their
own**, with every new rule reflexively graded High. None of that had ever been measured.
This is the measurement.

Corpus: **850 malicious** (the 2026 temporal held-out, campaign-pure — see
`2026-07-25-honest-split.md`) and **1,184 benign** (top-downloaded npm + pypi), scored by
`cmd/deval`, which analyzes each sample once and replays policies over the cached signals
so a full 32-rule ablation costs one analysis pass.

Operating point in force: **~1% benign quarantine tolerable, ~0 hard blocks.**

## 1. We have ~12× false-positive headroom

**0.08% benign flagged (1 of 1,184)** against a 1% budget. The detector is far more
conservative than the chosen operating point. That reframes the question from "how do we
stay safe" to "how do we spend the headroom".

## 2. Thresholds are not the lever — every direction is worse

| criticalQ | highQ | mediumQ | recall | benign FP |
|---|---|---|---|---|
| 1 | 1 | 1 | 60.9% | **1.35%** |
| **1** | **1** | **2 (shipped)** | **60.7%** | **0.08%** |
| 1 | 2 | 2 | 20.4% | 0.08% |
| 1 | 3 | 2 | 18.5% | 0.08% |
| 2 | 1 | 2 | 47.5% | 0.00% |

Three findings:

- **Recall rests almost entirely on single High signals.** Requiring two Highs collapses
  recall 60.7% → 20.4%. There is no redundancy: catches are one-signal deep.
- **The Medium tier is inert.** mediumQuorum 2, 3, 4 are *identical* — the `≥2 Medium`
  branch never decides anything on this corpus.
- **Lowering to mediumQuorum=1 is a bad trade and lands over budget**: +0.2pt recall for
  +1.27pt FP (0.08% → 1.35%), because the Medium tier is populated by anti-informative
  rules (below). Rejected empirically, not by argument.

The shipped point is already the max-recall corner of the grid. **Recall must come from
coverage, not calibration.**

## 3. Five rules contribute exactly zero recall; three are anti-informative

| rule | fires on malware | fires on benign | Δrecall if disabled |
|---|---|---|---|
| `obfuscated-blob` | 25 | **68** | 0.00% |
| `embedded-secret` | 70 | **47** | 0.00% |
| `embedded-private-key` | 1 | **15** | 0.00% |
| `npm-install-hook` | 406 | 2 | 0.00% |
| `embedded-aws-key` | 1 | 0 | 0.00% |

The top three fire *more often on benign packages than on malware*. They are graded below
the decision threshold so they cost no false positives today — but they are not free:
they pad the human review queue, and **they are fed to the Codex panel as evidence**.
Anti-informative signals in an adjudicator's prompt are a live risk, since the panel is
what we lean on for the cases the rules can't resolve.

Load-bearing rules, by contrast:

| rule | Δrecall if disabled | catches |
|---|---|---|
| `host-recon-exfil` | **24.82%** | 211 |
| `npm-install-hook-danger` | 12.59% | 107 |
| `encoded-network-indicator` | 9.06% | 77 |
| `py-setup-execution` | 3.18% | 27 |
| `npm-install-hook-network` | 2.94% | 25 |

**Concentration risk:** one rule carries a quarter of all recall. If attackers adapt to
`host-recon-exfil`, 25% of detection evaporates at once.

`py-setup-execution` is also the only rule causing the single benign false positive.

## 4. Why the misses were missed — and the rule it produced

Of 334 missed malware samples:

- **171 (51%) emit no signal at all** → only a new rule can reach them.
- **163 (49%) emit a sub-threshold signal** → a re-grading might reach them. 152 of those
  are the bare `npm-install-hook`.

So we priced re-grading (new `deval -mode promote`, backed by
`engine.Policy.SeverityOverride`):

| promotion | recall | benign FP |
|---|---|---|
| `npm-install-hook` → high | 60.7% → **78.6%** | 0.08% → 0.25% |
| `obfuscated-blob` → high | 62.2% | **5.74%** |
| `embedded-secret` → high | 61.3% | **4.05%** |

The first line is tempting — 18 points of recall, still inside budget. **We did not take
it.** Its two false positives are `esbuild` and `core-js`, packages sitting in millions of
dependency trees. A 0.25% *rate* badly understates the pain when the false positives are
that widely installed; download-weighted, this is the worst possible pair to break.

Instead we read the 152. Their install hook is innocuous at the command level
(`node postinstall.js`) — **the endpoint lives one file away, in the hook's target
script**, which `npm-install-hook-network` never inspects. That gap became
`install-hook-external-fetch` (shipped in `e1aa688`): a network call from a hook target to
a hardcoded endpoint outside the registry/dev-infra allowlist.

The rule needs a **second indicator**, and finding that out was the useful part: the first
version broke the synthetic corpus control `benign-platform-detect-download`, because
packages legitimately fetch their own prebuilt binaries from vendor CDNs and no allowlist
enumerates every vendor. It now fires only when the host is an ephemeral
tunnel/collaborator endpoint (oastify, ngrok, webhook.site, interact.sh …) **or** host
identity flows out with the request — *call home with who I am* rather than *fetch a
binary*. Verified: esbuild, core-js, and vendor-CDN downloads stay clean; the oastify and
ngrok beacons are caught; the inert HubSpot dependency-confusion PoC correctly stays
allowed.

**Measured on the full corpus:**

| | recall | benign FP |
|---|---|---|
| before | 60.7% (516/850) | 0.08% |
| **after `install-hook-external-fetch`** | **63.8% (542/850)** | **0.08%** |

**+3.1pt recall at zero false-positive cost.** The rule fires on **141 malware and 0
benign** — many of those 141 were already caught by other rules, so the net gain is 26
samples, but the precision profile is clean. Misses fall 334 → 308.

That is a third of what blanket promotion offered (78.6%), bought without breaking
esbuild or core-js. The remaining `npm-install-hook` sub-threshold misses (126) are the
honest cost of that choice, and they are the right place for the next rule-mining pass.

## What this changes

1. **Stop grading new rules High by reflex.** Grade, then sweep it with
   `deval -mode promote` before shipping. The capability now exists.
2. **Recall work must be coverage work.** Half the misses are silent; thresholds are
   exhausted. New rules and new evidence (behavioral, diff) are the only paths.
3. **Prune or quarantine the anti-informative signals** — at minimum keep
   `obfuscated-blob`, `embedded-secret`, and `embedded-private-key` out of the panel
   prompt, where they are actively misleading.
4. **Diversify away from `host-recon-exfil`.** A quarter of recall in one regex is fragile.
5. **Weight benign FP by downloads**, not per-package. Breaking esbuild is not equivalent
   to breaking the 600th most-popular package, and a flat rate hides that.

## Limits

- Static-only. Behavioral and panel precision are still unmeasured — that is the next
  phase and the largest remaining unknown.
- The benign corpus is top-downloads, which under-represents the long tail; the true
  install-hook prevalence across all of npm is higher than the 2/600 seen here.
- One temporal draw. Recall may drift with campaign fashion rather than detector quality.
