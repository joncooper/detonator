# Phase-3 eval: curated real-malware cohort

**Date:** 2026-07-22
**Cohort:** 42 samples (34 npm, 8 pypi), curated from 120 random Datadog
`malicious_intent` candidates by an **independent** screen — one that drops
CTF/PoC/research-beacon noise and keeps only samples with a real payload, then
class-labels from source. The screen uses generic analyst patterns, not the
detector's rules, so recall is not measured against the detector's own blind spots.
**Pipeline:** same as phase-1 — gVisor detonation, CI-env spoofed, egress-contained
through the recording sinkhole, scored blind by `dscore`.

## Why curate

Phase-1 showed the `malicious_intent` set is labeled by upload intent, not behavior:
of 120 candidates here, **34 (28%) were research beacons** (dependency-confusion PoCs
posting to Burp Collaborator / oastify / interactsh) and 6 were CTF flag-hunters. A
recall number over that mix measures "flagged an intent-labeled upload," not "caught
working malware." The screen removes that noise so the denominator is real payloads.

## Results

| | block | quarantine | allow | NO_TRACE | NO_PKG |
|---|---|---|---|---|---|
| npm (34) | 12 | 7 | 10 | 5 | 0 |
| pypi (8) | 6 | 0 | 0 | 0 | 2 |
| **total** | **18** | **7** | **10** | **5** | **2** |

**Recall on samples that detonated: 25/35 = 71%** (npm 19/29 = 66%, pypi 6/6 = 100%).

Real signals fired broadly: `data-destruction`, `exfil-chain`, `unknown-domain`,
`hardcoded-ip-endpoint`, `obfuscated-blob`, `dynamic-exec-decoded`,
`encoded-network-indicator`, `embedded-secret`, `sensitive-read:ssh-private-key`,
`npm-install-hook-danger`. On pypi, `py-setup-execution` + `dynamic-exec-decoded`
carried the blocks.

## The 10 npm allows, diagnosed

This is the point of the run: on a curated cohort an `allow` is a candidate miss, not
dormant noise. They split three ways.

**1. Require-time payload, never triggered (the dominant gap).** The malicious code
lives in the package's *main module*, which runs on `require`/import — not in an
install hook. The install-phase detonation never imports it, and the harness's import
phase is truncated by the idle watchdog, so nothing executes. `lodash-twist` is the
clearest: `index.js` is `_0x`-obfuscated with `eval('this;')`, no install hook. Static
flagged `obfuscated-blob` but that signal alone is sub-threshold (obfuscation FP-risks
on minified libs), so the verdict was `allow`. **Two real levers here:** trigger
coverage for import-time payloads (OSCAR-style export fuzzing / a real import phase),
and raising obfuscation severity when it sits on a require-time entry point with no
legitimate build.

**2. Install-hook stealer that ran, exfil under-detected.** `login-paypal` (postinstall
`node index.js`) reads `os.hostname()` + `process.env.USER`, but the collect-and-send
did not surface as an `unknown-domain` or a flagged env-exfil. Root cause: the
`install-env-exfil` static rule was tightened earlier to kill esbuild/click false
positives, and credential reads are info-tier because npm reads `.npmrc` itself. That
precision fix now under-catches real host/env stealers whose exfil isn't
send-adjacent. Precision/recall tradeoff, exposed honestly.

**3. Screen over-inclusion — not a miss.** `tailwindcss-setgrid` / `-setfontstyle` /
`openclaw-droid` have benign scripts and use `process.env` in ordinary ways (passing
env to a subprocess). The curation regex over-matched `process.env`; these are not
install-time threats. So the 10 allows are not 10 misses — the screen itself is
imperfect, and the 71% denominator still carries some non-payload noise.

## Harness gaps (not detector results)

7 of 42 produced no usable trace: 5 `NO_TRACE` (install errored before any behavior)
and 2 `NO_PKG` (pypi wheels with a `.dist-info/` layout the repack doesn't handle —
it only builds sdists). Both are pipeline fixes, not detection outcomes.

## Honest caveats

- **Selection overlaps static patterns.** The screen's "stealer/obfuscated" labels
  overlap the detector's static rules, so static recall is partly self-selected. The
  less-biased signal is behavioral — but require-time payloads make behavior blind on
  exactly the samples that matter, which is why the gap shows up as `allow`.
- **pypi 6/6 rests on `py-setup-execution`**, which fires on any `setup.py` that runs
  code. It is not yet baseline-tested against benign pypi packages with real build
  logic (numpy-style). Treat pypi recall as provisional until that cohort runs.
- The screen has false positives (benign `process.env`), so 71% mixes real gaps with
  denominator noise. Both directions are documented rather than smoothed.

## Bottom line

On a cohort curated for real payloads: **71% caught, and the misses have a clear
shape** — not missing malware *classes* (there are almost none: 0 miners/wipers/
reverse-shells in 120 candidates; supply-chain malware is stealer- and
loader-dominated), but **payloads that run at import time**, where install-phase
detonation is blind and obfuscation-alone is scored too low to act. The two highest-
value next steps are import-time trigger coverage and revisiting obfuscation severity.
The pypi wheel repack and the env-exfil precision/recall balance are the follow-ons.
