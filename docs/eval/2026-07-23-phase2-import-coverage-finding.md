# Phase-2 finding: why import-time payloads don't fire

**Date:** 2026-07-23
**Status:** root cause diagnosed; fix scoped but not yet applied (decision pending).

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
