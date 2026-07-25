#!/usr/bin/env python3
"""Build pool-dates.tsv: the cross-confirmed malicious pool with first-seen dates.

Names and dates only -- no artifacts, no code. This is the manifest that makes the
temporal and campaign splits reproducible without re-cloning the 27k-sample dataset.

The Datadog paths carry the date:
  samples/<eco>/malicious_intent/<name>/[<ver>/]YYYY-MM-DD-<name>[-v<ver>].zip

Usage:
  # one blobless clone, no artifacts fetched
  GIT_LFS_SKIP_SMUDGE=1 git clone --filter=blob:none --no-checkout --depth 1 \
    https://github.com/DataDog/malicious-software-packages-dataset.git dd
  cd dd && git ls-tree -r --name-only HEAD samples/npm/malicious_intent  > tree-npm.txt
           git ls-tree -r --name-only HEAD samples/pypi/malicious_intent > tree-pypi.txt
  build-pool-dates.py tree-npm.txt tree-pypi.txt xref-npm.txt xref-pypi.txt > pool-dates.tsv

xref-*.txt are the Datadog names that also appear in the Backstabber's Knife Collection
name index -- the cross-source-confirmed pool (see docs/plan/corpus-and-eval-scaling.md).
"""
import sys, re, collections


def dates_from_tree(path):
    """name -> earliest date seen, from the dataset's zip paths."""
    seen = collections.defaultdict(list)
    for line in open(path):
        line = line.strip()
        if not line.endswith(".zip"):
            continue
        parts = line.split("/")
        if len(parts) < 5 or parts[2] != "malicious_intent":
            continue
        m = re.search(r"(\d{4}-\d{2}-\d{2})", parts[-1])
        if m:
            seen[parts[3]].append(m.group(1))
    return {n: min(ds) for n, ds in seen.items()}


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    tree_npm, tree_pypi, xref_npm, xref_pypi = sys.argv[1:5]
    dates = {"npm": dates_from_tree(tree_npm), "pypi": dates_from_tree(tree_pypi)}
    rows = []
    for eco, xref in (("npm", xref_npm), ("pypi", xref_pypi)):
        for line in open(xref):
            n = line.strip()
            if n and n in dates[eco]:
                rows.append((eco, n, dates[eco][n]))
    rows.sort()
    for e, n, d in rows:
        print(f"{e}\t{n}\t{d}")
    sys.stderr.write(f"pool-dates: {len(rows)} packages\n")


if __name__ == "__main__":
    main()
