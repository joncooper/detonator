# Detonator

A local registry proxy that refuses to serve an npm or PyPI package version to your machine until it has been statically scanned, **detonated** in a gVisor sandbox on a disposable host, behaviorally judged, and diffed against the last known-good version. Nothing installs until it earns a signed verdict.

Design borrows Ant Group's **OSCAR** dynamic-analysis approach, reuses **OpenSSF** sandbox + data assets (`package-analysis`, `malicious-packages`, OSV, Sigstore, Scorecard), and uses **OpenAI Codex** as the triage brain behind a pluggable model interface.

## Layout

```
docs/build-plan.md     The full design + phased build plan (start here)
phase0/                Turnkey Phase 0: stand up a burner, prove the telemetry + verdict path
  RUNBOOK.md           Step-by-step
  burner-launch.sh     Launch a hardened, credential-free EC2 detonation host (run locally)
  burner-setup.sh      First-boot setup: Docker + gVisor + package-analysis + lockdown
  tripwire-src/        Synthetic, HARMLESS test sample that trips every hook
  verdict-schema.json  Structured-output schema for the Codex triage stage
```

## Safety

This repo contains **no malware**. Phase 0 validates the pipeline with benign packages and a synthetic sample. Live samples from `ossf/malicious-packages` run **only** on the disposable burner in Phase 3 — never on a laptop, never in a general-purpose environment.

Status: pre-Phase-0. See `docs/build-plan.md` §5 for the roadmap.
