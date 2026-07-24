#!/usr/bin/env python3
"""Deterministic held-out split over the Datadog ∩ Backstabber's pool.

Ranks each malicious name by md5(ecosystem:name) and takes disjoint proportional
slices. Reproducible: same pool -> same samples, so later draws never overlap earlier
ones. Usage: split.py <xref-npm.txt> <xref-pypi.txt> <set:1|2|3>
"""
import sys, hashlib
def rank(path, eco):
    names = [l.strip() for l in open(path) if l.strip()]
    names.sort(key=lambda x: hashlib.md5(f"{eco}:{x}".encode()).hexdigest())
    return names
SLICES = {"1": (0, 120, 0, 30), "2": (120, 240, 30, 60), "3": (240, 360, 60, 90)}
npm_a, npm_b, py_a, py_b = SLICES[sys.argv[3]]
npm = [("npm", n) for n in rank(sys.argv[1], "npm")[npm_a:npm_b]]
pypi = [("pypi", n) for n in rank(sys.argv[2], "pypi")[py_a:py_b]]
for e, n in npm + pypi:
    print(f"{e}\t{n}")
