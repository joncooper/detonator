# Plan: scale the corpus + a real held-out eval

## Why

The detector's two weakest honest points (see `docs/eval/`):

1. **No precision at scale.** The only false-positive number is 0/30 benign packages.
   A detector lives or dies on FP rate at registry scale — 90% recall is worthless if
   it flags 1% of real installs.
2. **No cross-source / held-out recall.** Every eval is small, single-source (Datadog),
   and labeled by *upload intent* (~28% CTF/PoC contamination). That guards against
   nothing except gross error, and it lets rules overfit the ~80 samples we've inspected.

This plan fixes both **without detonating thousands.**

## The load-bearing insight — three cost tiers

Each analysis layer has a different budget, so scale each to what it can afford:

1. **Static** — free (offline, no burner). Run it on **everything**: 10k benign + all
   the malicious we can acquire.
2. **Detonation (behavioral)** — burner-minutes per sample, but **the burner runs
   overnight**, so this scales to **hundreds–low-thousands**, not a sampled few hundred.
   Detonate the whole tune set and the whole held-out.
3. **Codex panel** — 3 codex calls per package, and **codex tokens are the finite
   resource**. Run the panel **only on the ambiguous subset** (the cases the rules leave
   as allow/quarantine and can't resolve) — a fraction of the corpus — not every sample.
   Use **Sol medium** (`gpt-5.6-sol`, effort medium) for bulk and **Terra high** for the
   hardest adjudications; avoid xhigh to conserve tokens.

The underrated win is still **precision at scale** — benign is free, clean, static-only,
and the number we're actually missing. Do it first; it costs no burner and no tokens.

## Three scoped workstreams

### 1. Precision at scale (benign)

- **Source:** the top 5–10k most-downloaded npm + pypi packages — npm registry download
  API; `hugovk/top-pypi-packages` (or the pypi BigQuery download stats) for pypi. Real,
  clean, no custody concern.
- **Method:** fetch tarballs/sdists, static-score offline (`dscore -tarball`, no trace).
  This is `phase3/benign-static-cohort.sh` scaled from 30 → thousands.
- **Output:** the real static FP rate + every FP case to fix. The 30-package cohort
  already surfaced 5 pypi FPs; 10k will surface more (build-tooling, vendored deps,
  version-string edge cases). Fix them, re-run, converge toward a trustworthy FP rate.
- **Cost:** cheap, no burner, hours. **Highest-leverage single number we're missing —
  do this first.**

### 2. Backstabber's — tune set (many)

- **Source:** `dasfreak/Backstabbers-Knife-Collection` — a curated, manually-verified set
  of real npm/pypi/ruby supply-chain malware, **much less CTF noise than Datadog**.
  (Verify current size ~2–3k, password convention, and access before relying on it.)
- **Use:** the *smaller* deterministic split (see discipline below). Static-score all +
  detonate a sample. Diagnose misses → new / tightened rules. Cleaner, more diverse
  tuning data than the ~80 Datadog + synthetic cases we've tuned on so far.

### 3. Backstabber's — held-out (more)

- **Use:** the *larger* remaining split, **never inspected during tuning**. After
  workstream 2 tunes and the rules are **frozen**, eval this exactly once → an unbiased
  recall (+ precision) number. Held-out is deliberately larger than the tune set for a
  robust estimate.
- Detonate the held-out once (behavioral), static-score it, and run the panel over the
  ambiguous subset. Report **per-source** so single-source bias stays visible.

## Sources and their roles

| Source | Role | Notes |
|---|---|---|
| top-N npm/pypi downloads | benign precision @ scale | free, clean, static-scalable |
| Backstabber's Knife Collection | tune + held-out (clean) | manually verified, low CTF noise, cross-source |
| Datadog `malicious_intent` | bulk (screened) | ~27k, but intent-labeled / noisy |
| `ossf/malicious-packages` (OSV) | labels / selection cross-ref | advisories, not always the artifact |
| MalwareBazaar | cross-source diversity check | thin on npm/pypi (mostly binaries); key on hand |

## Held-out discipline (the whole point)

- **Deterministic, committed split.** Bucket by a hash of (ecosystem, name) — e.g.
  `sha256` low bits → tune vs held-out — and commit the manifest of which hashes are
  held-out. Reproducible; adding samples later keeps the split stable; no accidental leak.
- **Never** static-score, detonate, or read a held-out sample during tuning.
- **Eval the held-out exactly once per rule-freeze.** Peeking, then re-tuning, invalidates
  it — from then on it's a tune set.

## Order

1. **Precision at scale** (benign top-N) — cheap, unblocks the FP number; fix what it finds.
2. **Acquire Backstabber's**, hash-split into tune (smaller) + held-out (larger), commit the split.
3. **Tune** on the tune set; freeze the rules.
4. **Eval once** on held-out (static + sampled detonation + panel) → the honest recall +
   precision, per-source. This is the number we can actually stand behind.

## Resources / budget (confirmed)

- **Burner: overnight is fine.** Detonation is no longer the hard limit — detonate the
  full tune + held-out sets, not a sample.
- **Codex tokens are the finite resource.** The panel is 3 calls/package. Spend them
  where they matter: the **ambiguous subset** only (rules-uncertain cases), not the whole
  corpus. Model: **Sol medium** for bulk, **Terra high** for the hardest calls; not xhigh.
- **Don't re-detonate or re-invoke codex to refine.** The raw-capture path (`-triage-raw`,
  saved traces) exists so the analysis is redone offline for free.

Rough budgeting: if a held-out draw has ~1–2k malicious samples, static-score all of them
(free), detonate all of them (overnight), but panel only the few hundred the rules can't
resolve — keeping codex spend to ~(ambiguous count × 3) calls.
