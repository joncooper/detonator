#!/usr/bin/env python3
"""Parallel detonation harness. Usage: pdet.py <manifest.tsv> <workers> [limit] [offset]

manifest: eco<TAB>name<TAB>tarball_path  (tarball already repacked/fetched)

Each detonation gets its own results dir; DETONATOR_PARALLEL makes the sandbox
scope its cleanup to its own container instead of `podman rm --all --force`,
which is what made concurrency lose ~33% of traces.
"""
import os, sys, glob, json, subprocess, shutil, collections
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = "/home/ubuntu"
OUT = os.environ.get("PDET_OUT", ROOT + "/corpus2")
DSCORE = ROOT + "/dscore"
MANIFEST, WORKERS = sys.argv[1], int(sys.argv[2])
LIMIT = int(sys.argv[3]) if len(sys.argv) > 3 else 10**9
OFFSET = int(sys.argv[4]) if len(sys.argv) > 4 else 0
for d in ("traces", "logs", "res"):
    os.makedirs(f"{OUT}/{d}", exist_ok=True)

rows = [l.strip().split("\t") for l in open(MANIFEST) if l.strip()][OFFSET:OFFSET + LIMIT]

env_base = dict(os.environ)
env_base["DETONATOR_PARALLEL"] = "1"
gw = env_base.get("DOCKER_GW", "172.17.0.1")
env_base.setdefault("DETONATOR_NPM_REGISTRY", f"http://{gw}:4873")
env_base.setdefault("DETONATOR_PIP_INDEX_URL", f"http://{gw}:3141/index/")
env_base.setdefault("DETONATOR_PIP_TRUSTED_HOST", gw)


# Each worker claims its own podman container store. The analysis containers
# otherwise share /var/lib/containers, so podman's analysis-net IPAM state is
# shared and concurrent starts race ("error configuring network namespace ...:
# error adding pod"). run_analysis.sh honours CONTAINER_DIR_OVERRIDE, so this
# needs no patch. Stores are pre-seeded with the sandbox image by mkstores.sh.
_slots = None
if os.path.isdir("/home/ubuntu/stores"):
    import queue
    _slots = queue.Queue()
    for _d in sorted(glob.glob("/home/ubuntu/stores/w*")):
        _slots.put(_d)


def one(eco, name, tb):
    store = _slots.get() if _slots else None
    try:
        return _one(eco, name, tb, store)
    finally:
        if store:
            _slots.put(store)


def _one(eco, name, tb, store):
    rd = f"{OUT}/res/{name}"
    shutil.rmtree(rd, ignore_errors=True)
    os.makedirs(rd, exist_ok=True)
    env = dict(env_base,
               RESULTS_DIR=rd, STATIC_RESULTS_DIR=rd + "/s", FILE_WRITE_RESULTS_DIR=rd + "/fw",
               ANALYZED_PACKAGES_DIR=rd + "/p", LOGS_DIR=rd + "/l", STRACE_LOGS_DIR=rd + "/st")
    if store:
        env["CONTAINER_DIR_OVERRIDE"] = store
    logp = f"{OUT}/logs/{name}.log"
    try:
        with open(logp, "w") as lg:
            subprocess.run(
                ["sudo", "-E", "bash", "/opt/package-analysis/scripts/run_analysis.sh",
                 "-nointeractive", "-ecosystem", eco, "-package", name, "-local", tb, "-nopull"],
                stdout=lg, stderr=subprocess.STDOUT, env=env, timeout=600)
    except subprocess.TimeoutExpired:
        return (name, "TIMEOUT", "", 0)
    trace = rd + "/results.json"
    if not os.path.exists(trace):
        return (name, "NO_TRACE", "", 0)
    shutil.copy(trace, f"{OUT}/traces/{name}.json")
    installed = sum(1 for l in open(logp, errors="ignore") if "Install succeeded" in l)
    try:
        j = json.loads(subprocess.run(
            [DSCORE, "-trace", trace, "-tarball", tb, "-ecosystem", eco, "-name", name],
            capture_output=True, text=True).stdout)
        rules = sorted(set(f"{s.get('stage','?')}:{s['rule']}" for s in j.get("signals", [])
                           if s.get("severity") in ("high", "critical", "medium")))
        return (name, j.get("decision", "ERR"), ",".join(rules), installed)
    except Exception as e:
        return (name, "SCORE_ERR", str(e)[:40], installed)


res = open(f"{OUT}/results.tsv", "a")
done = collections.Counter()
with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    futs = {ex.submit(one, r[0], r[1], r[2]): r[1] for r in rows}
    for i, f in enumerate(as_completed(futs), 1):
        name, dec, rules, inst = f.result()
        done[dec] += 1
        res.write(f"{name}\t{dec}\t{rules}\t{inst}\n"); res.flush()
        print(f"  {i}/{len(rows)} {name}: {dec} (install_ok={inst})", flush=True)
print("\n=== done ===")
for k, v in done.most_common():
    print(f"  {k}: {v}")
lost = done["NO_TRACE"] + done["TIMEOUT"]
print(f"trace loss: {lost}/{sum(done.values())} = {lost/max(1,sum(done.values()))*100:.1f}%")
