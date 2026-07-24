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

### Backstabber's is a name index, not artifacts (verified)

`dasfreak/Backstabbers-Knife-Collection` on GitHub is the searchable **website + a name
index** (`data/packages.json`): **npm 10,537 + pypi 4,040** curated, manually-verified
malicious package *names* across 7 ecosystems — but **no artifacts in the repo** (the
samples are the separate academic archive). So use it as a **cross-source label filter**,
not an artifact source:

- Fetch artifacts from **Datadog** (27k, directly fetchable). A Datadog sample whose name
  is in Backstabber's is **cross-source-confirmed malicious** (two independent curators
  flagged it) — a much cleaner label than raw Datadog, which cuts the CTF/PoC noise.
- Optionally pursue the separate Backstabber's academic archive later for true
  different-curator *artifacts*; not needed for a first held-out.

### 2. Tune set (many) — Datadog ∩ Backstabber's, smaller split

- The Datadog samples whose names appear in Backstabber's, screened for a real payload.
- The *smaller* deterministic split (see discipline). Static-score all + detonate.
  Diagnose misses → new / tightened rules. Cleaner, more diverse than the ~80 Datadog +
  synthetic cases tuned on so far.

### 3. Held-out (more) — same set, larger split

- The *larger* remaining split of Datadog ∩ Backstabber's, **never inspected during
  tuning**. After workstream 2 freezes the rules, eval this once → an unbiased recall.
- Detonate it (behavioral — overnight budget covers it), static-score it, run the panel
  over the ambiguous subset. Report per-source so single-source bias stays visible.

## Sources and their roles

| Source | Role | Notes |
|---|---|---|
| top-N npm/pypi downloads | benign precision @ scale | free, clean, static-scalable (`npm-high-impact`, `hugovk/top-pypi-packages`) |
| Backstabber's Knife Collection | cross-source **label filter** | names only (npm 10.5k + pypi 4k); no artifacts in repo; cuts Datadog noise |
| Datadog `malicious_intent` | artifact source (bulk) | ~27k, directly fetchable, but intent-labeled / noisy — filter via Backstabber's |
| `ossf/malicious-packages` (OSV) | labels / selection cross-ref | advisories, not always the artifact |
| MalwareBazaar | cross-source diversity check | thin on npm/pypi (mostly binaries); key on hand |

## Held-out discipline (the whole point)

- **Deterministic, committed split.** Bucket by a hash of (ecosystem, name) — e.g.
  `sha256` low bits → tune vs held-out — and commit the manifest of which hashes are
  held-out. Reproducible; adding samples later keeps the split stable; no accidental leak.
- **Never** static-score, detonate, or read a held-out sample during tuning.
- **Eval the held-out exactly once per rule-freeze.** Peeking, then re-tuning, invalidates
  it — from then on it's a tune set.

## Sizing (measured)

Cross-referencing the fetchable Datadog artifacts against the Backstabber's name index:

- Datadog unique malicious names: **npm 12,601 + pypi 1,816**.
- **Datadog ∩ Backstabber's: npm 2,751 + pypi 621 = 3,372** cross-source-confirmed
  malicious samples with fetchable artifacts. This is the tune + held-out pool.

**Detonation budget is the hard limit.** At ~3 min/sample, 3,372 samples is ~160 hours —
you cannot detonate the pool. So:

- **Static** — score all 3,372 (fetch on a burner for custody, `dscore -tarball`, fast).
  This is a real static **recall at scale** number, the complement to precision at scale.
- **Detonation** — a random sample of ~150–300 (a night's burner budget), for behavioral
  recall + the panel. Report it as a sample, not the whole pool.
- **Panel** — the ambiguous subset of the detonated sample only (codex tokens).

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
