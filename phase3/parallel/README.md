# Parallel detonation

Detonation did not parallelize: at 2–4 concurrent workers ~33–50% of runs produced
no trace. Three hypotheses, two wrong:

1. **Shared `runsc` root** (the original guess) — wrong; it is already per-container.
2. **`podman rm --all --force` in `Clean()`** — a real bug (upstream assumes one
   analysis per host, so one worker's cleanup force-removes every other worker's
   *running* sandbox) but patching it alone did not reduce trace loss.
3. **podman network/IPAM race** — the actual cause. Every analysis container
   bind-mounts the same `/var/lib/containers`, so the `analysis-net` network state is
   shared and concurrent container starts race allocating an IP:
   `error configuring network namespace ...: error adding pod <name>`.

**Fix:** give each worker its own container store. `run_analysis.sh` already honours
`CONTAINER_DIR_OVERRIDE`, so this needs no patch and no image rebuild — only ~3.6 GB
of disk per worker (grow the EBS volume first; the default 38 GB is too small).
`pdet.py` hands each worker a store from a pool.

Result: **0 trace loss at 4 workers**, from 10/20 lost before.

The `Clean()` scoping patch is kept anyway (`../patches/patch-parallel-safe-cleanup.py`)
because removing only your own container is strictly more correct either way.

## Gotchas

- Store dirs are **root-owned**: a plain `du -sh` as `ubuntu` reports 12K and looks
  like the image load failed. Use `sudo du`.
- `cp -a` of an overlay store is unreliable — `podman load` into each store instead.
- Long-running jobs must be launched under `systemd-run --unit=... --collect`; plain
  background shells get reaped.

## Registry mirrors

`setup-mirrors.sh` runs verdaccio (npm) and proxpi (pypi) as caching uplinks so a
detonating package resolves its **real** dependencies with zero internet egress —
replacing the IP allowlist, which could not work against anycast CDNs and had a
FORWARD DROP ordered before its ACCEPTs. Wired through `DETONATOR_NPM_REGISTRY` /
`DETONATOR_PIP_INDEX_URL`, forwarded into the container by the run_analysis.sh patch.

Verified: a pypi package with dependencies installed via `172.17.0.1:3141`.
**Known gap:** the nested sandbox network does not reliably route to the host bridge
(npm saw `ETIMEDOUT`), so the mirror is not yet dependable from inside the sandbox.
That only blocks the *malware* path, where the sinkhole denies the real registry;
benign runs can use the real registry directly.
