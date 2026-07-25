#!/usr/bin/env python3
"""Held-out splits over the Datadog x Backstabber's pool, without leakage.

The naive md5(eco:name) split leaks: malware arrives in CAMPAIGNS of near-identical
packages (one npm bulk upload on 2025-12-03 put 207 `elf-stats-*` packages in the pool,
6% of it). A random split scatters one campaign across tune and held-out, so catching
one member scores as "generalization" when it is memorization. Measured on the first
split: elf-stats-* was 9x in tune and 17x in held-out.

Two leak-free modes:

  campaign  hash split, but whole campaign CLUSTERS are assigned to one side, so no
            family spans tune/held-out.
  temporal  train on packages first seen <= cutoff, test on those after. This is the
            question a detector actually has to answer -- does it catch TOMORROW's
            malware -- which no random split can answer.

Clusters are built conservatively (over-merging is safe; under-merging leaks):
union-find over (a) same-ecosystem bulk-upload days and (b) shared multi-token name
prefixes.

Usage:
  split.py pool-dates.tsv --mode temporal --cutoff 2026-01-01 [--side test]
  split.py pool-dates.tsv --mode campaign --set 1 [--npm 120 --pypi 30]
  split.py pool-dates.tsv --stats

Pool format (tsv, names + dates only, no artifacts): ecosystem<TAB>name<TAB>YYYY-MM-DD
Regenerate with tools/build-pool-dates.py against the Datadog dataset tree.
"""
import sys, argparse, hashlib, collections

BULK_DAY_MIN = 10   # packages on one ecosystem-day that read as a bulk campaign upload
PREFIX_TOKENS = 2   # hyphen-tokens of shared prefix that read as one family
PREFIX_MIN = 3      # members needed before a shared prefix counts as a campaign


def load(path):
    rows = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            rows.append((parts[0], parts[1], parts[2]))
    return rows


class Union:
    """Minimal union-find over package keys."""

    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def campaign_clusters(rows):
    """Map each (eco, name) to a campaign id. Conservative: over-merge rather than leak."""
    u = Union()
    keys = [(e, n) for e, n, _ in rows]
    for k in keys:
        u.find(k)

    # (a) bulk-upload days: one ecosystem, one date, many packages -> one campaign.
    byday = collections.defaultdict(list)
    for e, n, d in rows:
        byday[(e, d)].append((e, n))
    for members in byday.values():
        if len(members) >= BULK_DAY_MIN:
            for m in members[1:]:
                u.union(members[0], m)

    # (b) shared multi-token name prefix (elf-stats-*, transform-*) -> one campaign.
    byprefix = collections.defaultdict(list)
    for e, n, _ in rows:
        toks = n.split("-")
        if len(toks) > PREFIX_TOKENS:
            byprefix[(e, "-".join(toks[:PREFIX_TOKENS]))].append((e, n))
    for members in byprefix.values():
        if len(members) >= PREFIX_MIN:
            for m in members[1:]:
                u.union(members[0], m)

    return {k: u.find(k) for k in keys}


def assert_pure(train, test, clusters, label):
    """Fail loudly if any campaign spans both sides -- the bug this script exists to fix."""
    ctr = {clusters[(e, n)] for e, n, _ in train}
    cte = {clusters[(e, n)] for e, n, _ in test}
    spanning = ctr & cte
    if spanning:
        sys.exit(f"LEAK ({label}): {len(spanning)} campaign(s) span train and test")


def emit(rows):
    for e, n, d in rows:
        print(f"{e}\t{n}\t{d}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pool")
    ap.add_argument("--mode", choices=("temporal", "campaign"), default="temporal")
    ap.add_argument("--cutoff", default="2026-01-01", help="temporal: train <= cutoff < test")
    ap.add_argument("--side", choices=("train", "test", "both"), default="test")
    ap.add_argument("--set", type=int, default=1, help="campaign: which disjoint slice")
    ap.add_argument("--npm", type=int, default=120)
    ap.add_argument("--pypi", type=int, default=30)
    ap.add_argument("--stats", action="store_true")
    a = ap.parse_args()

    rows = load(a.pool)
    clusters = campaign_clusters(rows)

    if a.stats:
        sizes = collections.Counter(clusters.values())
        multi = {c: n for c, n in sizes.items() if n > 1}
        print(f"pool: {len(rows)} packages, {len(sizes)} campaigns")
        print(f"  in multi-member campaigns: {sum(multi.values())} "
              f"({sum(multi.values())/len(rows)*100:.0f}%) across {len(multi)} campaigns")
        print(f"  largest: {[n for _, n in sizes.most_common(5)]}")
        years = collections.Counter(d[:4] for _, _, d in rows)
        print(f"  first-seen by year: {dict(sorted(years.items()))}")
        for cut in ("2025-01-01", "2025-07-01", "2026-01-01"):
            tr = sum(1 for _, _, d in rows if d < cut)
            print(f"  cutoff {cut}: train={tr} test={len(rows)-tr}")
        return

    if a.mode == "temporal":
        train = [r for r in rows if r[2] < a.cutoff]
        test = [r for r in rows if r[2] >= a.cutoff]
        # A campaign straddling the cutoff would leak; keep it wholly on the TRAIN side
        # so the test set stays strictly novel.
        ctr = {clusters[(e, n)] for e, n, _ in train}
        moved = [r for r in test if clusters[(r[0], r[1])] in ctr]
        test = [r for r in test if clusters[(r[0], r[1])] not in ctr]
        train += moved
        assert_pure(train, test, clusters, "temporal")
        sys.stderr.write(
            f"temporal cutoff {a.cutoff}: train={len(train)} test={len(test)} "
            f"({len(moved)} moved to train to keep campaigns whole)\n")
        emit(train if a.side == "train" else test if a.side == "test" else train + test)
        return

    # campaign mode: deterministic hash over the CLUSTER, so families never span slices.
    order = sorted({clusters[(e, n)] for e, n, _ in rows},
                   key=lambda c: hashlib.md5(str(c).encode()).hexdigest())
    members = collections.defaultdict(list)
    for e, n, d in rows:
        members[clusters[(e, n)]].append((e, n, d))
    want = {"npm": a.npm, "pypi": a.pypi}
    skip = {"npm": a.npm * (a.set - 1), "pypi": a.pypi * (a.set - 1)}
    got = {"npm": [], "pypi": []}
    seen = {"npm": 0, "pypi": 0}
    for c in order:
        for e, n, d in members[c]:
            if seen[e] < skip[e]:
                seen[e] += 1
            elif len(got[e]) < want[e]:
                got[e].append((e, n, d))
                seen[e] += 1
    emit(got["npm"] + got["pypi"])


if __name__ == "__main__":
    main()
