# Held-out eval manifest

Reproducible malicious-package sample for the held-out static recall eval
(`docs/eval/2026-07-24-heldout-static-recall.md`). **Names only — no artifacts.**

- `split.py` — deterministic md5 hash-split over the cross-confirmed pool
  (Datadog ∩ Backstabber's). Disjoint slices per set; later draws never overlap.
- `set1-names.tsv`, `set2-names.tsv` — the exact `ecosystem<TAB>name` draws scored.

Regenerate: `split.py xref-npm.txt xref-pypi.txt 2` where the xref files are
Datadog malicious names filtered to those present in the Backstabber's name index.
