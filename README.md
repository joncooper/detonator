# Detonator

A local registry proxy that refuses to serve an npm or PyPI package version to your machine until it has been statically scanned, **detonated** in a gVisor sandbox on a disposable host, behaviorally judged, and diffed against the last known-good version. Nothing installs until it earns a signed verdict.

Design borrows Ant Group's **OSCAR** dynamic-analysis approach, reuses **OpenSSF** sandbox + data assets (`package-analysis`, `malicious-packages`, OSV, Sigstore, Scorecard), and uses **OpenAI Codex** as the triage brain behind a pluggable model interface.

## Layout

```
docs/build-plan.md     The full design + phased build plan (start here)
cmd/detonator/         The proxy binary
internal/
  proxy/               npm + PyPI pull-through registry (the enforcement point)
  cache/               content-addressed artifacts + verdicts, TTL'd metadata, history
  gate/                admission gate: allow-all stub + static-analysis pipeline
  artifact/            bounded npm/PyPI unpacking (inspection only, never executes)
  analyze/static/      install-hook / setup.py / obfuscation / secret rules
  analyze/osv/         OSV.dev known-vuln lookup
  analyze/differ/      version-over-version diff (surfaces new install hooks)
  engine/              signal → verdict, with policy (fail-to-review default)
  triage/              pluggable LLM triage: Model interface + mock + Codex
  sign/                verdict signing (ed25519 default; cosign backend seam)
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
digest. The default `--gate static` runs the analysis pipeline (static rules +
OSV + version diff) and blocks on known-critical vulns or obvious install-script
malware; `--gate allow-all` is the transparent Phase-1 stub.

Flags:
- `--osv` / `--osv-url` — OSV known-vuln lookup
- `--fail-closed` — block instead of quarantine on uncertainty
- `--triage` — LLM triage: `off` (default), `mock` (local), or `codex`
  (**sends package source to OpenAI**; opt-in, warns on start)
- `--sign` / `--signing-key` — sign cached verdicts (ed25519) so they can't be
  forged; a tampered or unsigned cache entry is re-analyzed, not trusted

## Safety

This repo contains **no malware**. Phase 0 validates the pipeline with benign packages and a synthetic sample. Live samples from `ossf/malicious-packages` run **only** on the disposable burner in Phase 3 — never on a laptop, never in a general-purpose environment.

Status: Phases 1–2 complete; Phase 4 machinery landed (verdict signing +
pluggable triage interface with a local mock; live Codex is opt-in). Phase 3
(detonation) and Phase 0 telemetry validation need the burner — next up. Phase 4
triage will consume the detonation behavior log once Phase 3 lands. See
`docs/build-plan.md` §5.
