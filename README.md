# Detonator

A local registry proxy that refuses to serve an npm or PyPI package version to your machine until it has been statically scanned, **detonated** in a gVisor sandbox on a disposable host, behaviorally judged, and diffed against the last known-good version. Nothing installs until it earns a signed verdict.

Design borrows Ant Group's **OSCAR** dynamic-analysis approach, reuses **OpenSSF** sandbox + data assets (`package-analysis`, `malicious-packages`, OSV, Sigstore, Scorecard), and uses **OpenAI Codex** as the triage brain behind a pluggable model interface.

## Layout

```
docs/build-plan.md     The full design + phased build plan (start here)
cmd/detonator/         The proxy binary
internal/
  proxy/               npm + PyPI pull-through registry (the enforcement point)
  cache/               content-addressed artifacts + verdicts, TTL'd metadata
  gate/                admission-gate interface (Phase 1: always-allow stub)
  verdict/             shared verdict / artifact / signal types
  config/              runtime config
phase0/                Turnkey Phase 0: stand up a burner, prove the telemetry + verdict path
  RUNBOOK.md           Step-by-step
  burner-launch.sh     Launch a hardened, credential-free EC2 detonation host (run locally)
  burner-setup.sh      First-boot setup: Docker + gVisor + package-analysis + lockdown
  tripwire-src/        Synthetic, HARMLESS test sample that trips every hook
  verdict-schema.json  Structured-output schema for the Codex triage stage
```

## Run the proxy (Phase 1)

```
go build ./cmd/detonator && ./detonator            # listens on 127.0.0.1:8080

npm install --registry http://127.0.0.1:8080/npm/ <pkg>
pip install --index-url http://127.0.0.1:8080/pypi/simple/ <pkg>
```

Every artifact download is routed through the admission gate and cached by
digest. In Phase 1 the gate admits everything — the point is to prove the proxy
is a transparent drop-in before real analysis lands (build-plan §5).

## Safety

This repo contains **no malware**. Phase 0 validates the pipeline with benign packages and a synthetic sample. Live samples from `ossf/malicious-packages` run **only** on the disposable burner in Phase 3 — never on a laptop, never in a general-purpose environment.

Status: Phase 1 (the gate, dumb) — proxy is transparent for `npm install` /
`pip install`, always-allow gate. See `docs/build-plan.md` §5 for the roadmap.
