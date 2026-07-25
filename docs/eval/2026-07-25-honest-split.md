# Leak-free splits: the honest static recall is ~60%, and one hypothesis was wrong (2026-07-25)

The held-out eval had a structural flaw: malware arrives in **campaigns** of near-identical
packages, and a random `md5(eco:name)` split scatters one campaign across tune and
held-out. Catching one member then scores as generalization when it is memorization.

Measured: `elf-stats-*` appeared **9× in the tune set and 17× in the "held-out" set**, and
21% of the npm held-out sat in multi-member campaign clusters. The cause is visible in the
dataset — **one npm bulk upload on 2025-12-03 put 207 `elf-stats-*` packages into the
pool**, 6% of it.

So we rebuilt the splitting methodology and re-measured. **The correction did not lower the
number — it raised it.** That prediction was wrong, and why it was wrong is the useful part.

## Pool structure (measured)

The "3,372 cross-confirmed samples" is not 3,372 independent observations:

- **1,537 campaigns**, not 3,372 independent samples. **56% of the pool sits in just 70
  campaigns**; the largest are 414, 290, 74, 70, 65 packages.
- First-seen by year: 2022:224, 2023:280, 2024:34, **2025:1755, 2026:1079**.

Effective N for generalization is roughly half the headline count. Any recall number
weighted per-package is really a weighted average over a few dozen campaigns.

## The two leak-free splits

`phase3/heldout/split.py` (rewritten) builds campaign clusters by union-find over
(a) same-ecosystem **bulk-upload days** (≥10 packages) and (b) shared multi-token **name
prefixes** (≥3 members). Clustering is deliberately over-merging: over-merging costs a
little sample size, under-merging leaks.

- **`--mode campaign`** — hash split, but whole clusters land on one side. Verified: 0
  overlap between slices, no family spans them.
- **`--mode temporal --cutoff 2026-01-01`** — train on ≤2025, test on 2026-only. Campaigns
  straddling the cutoff are pulled wholly to the train side (205 packages moved), so the
  test set is strictly novel. **This is the question a detector must answer — does it catch
  *tomorrow's* malware — and no random split can answer it.**

Both modes assert purity and exit non-zero on a leak.

`phase3/heldout/pool-dates.tsv` (names + dates only, no artifacts) makes this reproducible
without re-cloning the 27k-sample dataset; `build-pool-dates.py` regenerates it.

## Results

| split | rules | npm | pypi | total |
|---|---|---|---|---|
| Set 2 (random, leaky) | v2 (2026-07-24) | 67/120 (55.8%) | 12/30 (40.0%) | **79/150 = 52.7%** |
| Set 2 (random, leaky) | current | 71/120 (59.2%) | 12/29 (41.4%) | **83/149 = 55.7%** |
| **Temporal 2026 (campaign-pure)** | current | 475/793 (59.9%) | 41/57 (71.9%) | **516/850 = 60.7%** |

Decomposing the 52.7% → 60.7% move:

- **+3.0pt is real rule improvement** (52.7 → 55.7 on the *same* set: the `.pipe()`
  reverse-shell rule and the precision fixes shipped 2026-07-25).
- **+5.0pt is composition, not capability.** npm recall is essentially identical across
  splits (59.2% vs 59.9%) — that is the stable, trustworthy number. The lift comes from
  ecosystem mix: Set 2 is 20% pypi at 41% recall, while the 2026 cohort is only 6.7% pypi
  *and* that pypi scores 72%. The Python string-escape/obfuscation and webhook rules added
  this week landed squarely on the 2026 pypi wave.

**Robustness:** the temporal test set is not campaign-dominated — 874 packages across 642
campaigns, largest only 23 — and **per-campaign recall (61.1%) matches per-package (60.7%)**.
The old split could not make that claim (21% clustered). And 874 samples is a far tighter
interval than 150.

## The hypothesis that was wrong

We predicted removing campaign leakage would *lower* the headline. It did not. The reason:
the largest leaked campaign, `elf-stats-*`, is a family of **raw-IP `.pipe()` reverse
shells that static largely MISSED** (they were the bulk of the two-tier residual). Leakage
inflates a score only when the leaked campaign is one you *catch*. Here the duplicated
family was one we failed on, so the leak was **depressing** the number, not inflating it.

The methodology fix is still correct and worth keeping — a split whose bias depends on
which campaigns you happen to catch is not a measurement — but the honest finding is that
the old number was not dishonest in the direction we assumed.

## What this changes

- **Quote npm ~60% static recall**, from the temporal split, not 52.7%.
- **pypi is now the stronger half (72%)**, reversing the earlier picture — the Python
  obfuscation rules did real work.
- Use `--mode temporal` as the default eval going forward; it is the only split that tests
  what we actually care about, and it now has 874 samples behind it.
- Report per-campaign alongside per-package recall. When they diverge, the per-package
  number is being driven by a few big families.

## Limits

- 2026 is one year of malware; a single cutoff is one draw. Recall may drift with campaign
  fashion, not detector quality — the per-campaign number is the guard against that.
- pypi's 57 test samples is small; its 72% has a wide interval.
- Static-only. The behavioral and panel tiers are unmeasured here and their **precision**
  remains unmeasured entirely (next: Phase A2 sweep/ablation, then a benign behavioral
  corpus).
