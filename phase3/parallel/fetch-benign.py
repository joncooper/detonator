#!/usr/bin/env python3
"""Fetch top-downloaded benign packages for the behavioural false-positive corpus.

Recall is measured against malware; precision has to be measured against what
developers actually install. Top-downloads is the right benign population because
a false positive there is what would actually break a build.
"""
import json, os, re, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor

N_NPM = int(sys.argv[1]) if len(sys.argv) > 1 else 200
N_PYPI = int(sys.argv[2]) if len(sys.argv) > 2 else 100
OUT = "/home/ubuntu/benign"
for e in ("npm", "pypi"):
    os.makedirs(f"{OUT}/{e}", exist_ok=True)


def npm_names(n):
    src = urllib.request.urlopen(
        "https://unpkg.com/npm-high-impact@latest/lib/top-download.js", timeout=40).read().decode()
    names = re.findall(r'"([a-z0-9@/._-]{2,})"', src)
    return list(dict.fromkeys(names))[:n]


def pypi_names(n):
    d = json.load(urllib.request.urlopen(
        "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json",
        timeout=40))
    return [r["project"] for r in d["rows"]][:n]


def fetch(a):
    eco, name = a
    p = f"{OUT}/{eco}/{name.replace('/', '_')}.tgz"
    if os.path.exists(p) and os.path.getsize(p) > 0:
        return (eco, name, p)
    try:
        if eco == "npm":
            d = json.load(urllib.request.urlopen(
                f"https://registry.npmjs.org/{name}/latest", timeout=25))
            url = d["dist"]["tarball"]
        else:
            d = json.load(urllib.request.urlopen(
                f"https://pypi.org/pypi/{name}/json", timeout=25))
            v = d["info"]["version"]
            url = next((u["url"] for u in d["releases"].get(v, [])
                        if u["url"].endswith(".tar.gz")), "")
        if not url:
            return None
        urllib.request.urlretrieve(url, p)
        return (eco, name, p)
    except Exception:
        return None


want = [("npm", n) for n in npm_names(N_NPM)] + [("pypi", n) for n in pypi_names(N_PYPI)]
with ThreadPoolExecutor(max_workers=12) as ex:
    got = [r for r in ex.map(fetch, want) if r]
with open("/home/ubuntu/benign-manifest.tsv", "w") as f:
    for e, n, p in got:
        f.write(f"{e}\t{n}\t{p}\n")
print(f"benign staged: {len(got)} "
      f"(npm {sum(1 for r in got if r[0]=='npm')}, pypi {sum(1 for r in got if r[0]=='pypi')})")
