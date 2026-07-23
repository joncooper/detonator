# Phase-2 finding: why import-time payloads don't fire

**Date:** 2026-07-23
**Status:** root cause diagnosed, fix applied and measured. The fix works (the
import phase now runs), but it added **0 new detections** on the phase-3 cohort — its
value is prospective, not retrospective. Details below.

## The gap

Phase-3's dominant miss class was **import-time payloads** — malicious code in a
package's main module that runs on `require`/import, which the install-phase
detonation doesn't trigger. Investigation on the burner pinned down exactly why.

## Root cause

The package-analysis node harness runs phases in order and **aborts on the first
failure**:

- `sandboxes/dynamicanalysis/analyze-node.js`, `install()`:
  ```js
  result = spawnSync('npm', ['install', installPkg], {stdio: 'inherit'});
  if (result.status === 0) { console.log('Install succeeded.'); }
  else { console.log('Install failed.'); process.exit(1); }   // <-- aborts here
  ```
- `internal/worker/rundynamic.go` (line ~202-211): when a phase does not complete
  successfully, it records the error and **does not attempt subsequent phases**.

The `import` phase is where the payload would fire — `importPkg()` does
`require(pkg.name)`. But it runs *after* `install`, and `install()` calls
`process.exit(1)` whenever `npm install` returns non-zero. So **any package whose
`npm install` exits non-zero never gets its `import` phase**, and its require-time
payload never executes.

`npm install` exits non-zero for a large fraction of real samples:
- dependency-heavy typosquats (`core-pino`→pino, `morgan-logger`→morgan) whose
  dep tree fails to resolve in the contained (egress-denied) sandbox;
- even some dep-less packages (`lodash-twist`: 2m9s, "Install failed", no watchdog
  kill) — npm returns non-zero for reasons as mild as an audit/peer warning.

Confirmed against traces: `lodash-twist` has only an `install` phase
(`error_analysis`), no `import`; `supervot` (whose install *succeeded*) has both
`import` and `install` completed.

## The fix (scoped)

One-line harness change: don't `process.exit(1)` on install failure — log it and
let the `import` phase run anyway (the module is often unpacked into `node_modules`
even when the overall install returns non-zero). Alternatively, patch rundynamic to
run `import` independent of `install` status, or run the combined `all` phase.

Then rebuild the analysis image (~1hr, bundles gVisor) and re-detonate the affected
samples.

## Open question / ROI

The payoff is uncertain and worth weighing before spending the rebuild + re-detonation:
- The affected samples are largely dependency-heavy typosquats (whose `require`
  may still fail post-failed-install if deps are truly missing) and one 61-byte
  stub (`openclaw-droid`) — so behavioral yield on *this* cohort is unclear.
- Phase-1's static rules already catch the obfuscated / env-exfil ones
  (`lodash-twist`, `jwt-pack`, `healcode-client`).
- Phase-3 (Codex triage) reads source and can adjudicate subtle require-time malice
  **without** a rebuild, likely subsuming much of this gap more cheaply.

Recommendation: land the one-line harness fix as a correctness improvement
regardless; decide whether to spend the rebuild+re-detonation to *measure* it now,
or defer the measurement and let Phase-3 cover the same gap first.

## Result (measured)

The fix was applied and the affected samples re-detonated with a rebuilt sandbox image.

**The patch** (`sandboxes/dynamicanalysis/analyze-node.js`, `install()`):
```js
} else {
  // Do NOT abort on non-zero npm install: npm exits non-zero for benign reasons
  // (audit/peer warnings) and dep-resolution failures, but the target package is
  // usually still unpacked — so continue so the import phase runs require(pkg.name).
  console.log('Install failed (continuing to import phase).');   // was: process.exit(1)
}
```

Applying it required rebuilding the `dynamic-analysis` sandbox image **and** loading it
into the runtime store the orchestrator actually reads: the sandbox runs via a podman
bundled *inside* the analysis image, from `/var/lib/containers`, not the host docker
store. So the deploy is `docker build` → `docker save | podman load` (via the analysis
image's podman, `--privileged`, store mounted) → retag to
`gcr.io/ossf-malware-analysis/dynamic-analysis:latest`.

**Confirmed working:** `lodash-twist`, previously `{install: error_analysis}` with no
import phase, now runs `{import: completed, install: completed}` and logs the patched
message. The 8 static-miss / allow samples were re-detonated.

**Yield: 0 new detections.** Every re-detonated sample still scored `allow` (or produced
no trace):
- `core-pino`, `bingo-logger` (pino typosquats): still `NO_TRACE` — dependency
  resolution fails hard enough that no usable trace is produced even with the patch.
- `morgan-logger`, `openclaw-droid`, `tailwindcss-setgrid`/`-setfontstyle`, `ctfvamp`,
  `test-thegenetic-module`: import phase now `completed`, but the require-time code
  produced **no observable behavior** (no sockets/DNS/writes/spawns). The screen-noise /
  CTF ones are simply benign; the typosquats' payloads are dormant or dependency-gated
  in this sandbox.
- `lodash-twist` itself: import ran, payload did nothing observable — it remains caught
  by static `obfuscated-code`, not by behavior.

**Verdict.** The gap was real and the fix is correct — the detonation is now strictly
more thorough, so a future package with a live require-time payload will be caught
behaviorally where it previously would not. But on this cohort the yield is zero: the
samples that reach import don't exercise it maliciously, and the dependency-heavy
typosquats still can't be installed/traced under egress-deny. **Open questions for a
future effort:** (1) install the dependency tree (needs a controlled registry mirror, or
relaxing egress to the registry only) so typosquats-with-deps actually trace; (2) the
patch lives on the burner — persist it (a patch file applied by burner setup) so it
survives teardown; (3) OSCAR-style export fuzzing for function-gated payloads remains
unaddressed.
