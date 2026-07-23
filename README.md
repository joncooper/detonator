# Detonator

A local registry proxy that refuses to serve an npm or PyPI package version to your
machine until it has been statically scanned, **detonated** in a gVisor sandbox on a
disposable host, behaviorally judged, and diffed against the last known-good version.
Nothing installs until it earns a signed verdict.

## The problem

`npm install` and `pip install` run arbitrary code from strangers on your laptop.
Install hooks, `setup.py`, and import-time module code all execute during a normal
install, with your credentials and network in reach. Supply-chain malware exploits
exactly this: a typosquat or a compromised version ships a postinstall script that
reads `~/.npmrc`, `~/.aws/credentials`, or `~/.ssh/`, and posts them to a C2.

The registry is a pull-through choke point. Detonator puts analysis *in front of the
install*: a package version is quarantined until it has been observed — statically and
by actually running it in a sandbox — and cleared.

## How it works

```
install request ─▶ proxy ─▶ cache hit? ──▶ serve
                             │ miss
                             ▼
                     fetch artifact (never executed on host)
                             │
             ┌───────────────┼───────────────────────┐
          static           detonate               version diff
      (hooks, setup.py,   (gVisor sandbox on      (new hooks vs last
       obfuscation,        a disposable burner,    known-good)
       secrets, OSV)       CI-env spoofed,
                           egress-recorded)
             └───────────────┼───────────────────────┘
                             ▼
                    signal → verdict (policy: fail-to-review)
                             │
                       sign + cache ─▶ allow / quarantine / block
```

Static rules and the behavioral trace both feed one scorer. The same scorer runs
offline as `dscore` (score a saved trace + tarball from the command line) and as the
proxy's admission gate. Verdicts are signed so a tampered cache entry is re-analyzed,
not trusted.

Design borrows Ant Group's **OSCAR** dynamic-analysis approach, reuses **OpenSSF**
sandbox + data assets (`package-analysis` on gVisor/runsc, `malicious-packages`, OSV,
Sigstore), and uses an LLM (Codex) as the triage brain behind a pluggable interface.

## Layout

```
docs/build-plan.md      Full design + phased build plan (start here)
docs/eval/              Blind evals against real malware — methodology, results, caveats
cmd/detonator/          The proxy binary
cmd/dscore/             Offline scorer: score a trace + tarball from the CLI
internal/
  proxy/                npm + PyPI pull-through registry (the enforcement point)
  cache/                content-addressed artifacts + verdicts, TTL'd metadata, history
  gate/                 admission gate: allow-all stub + analysis pipeline
  artifact/             bounded npm/PyPI unpacking (inspection only, never executes)
  analyze/static/       install-hook / setup.py / obfuscation / encoded-payload / secret rules
  analyze/behavior/     rules over the detonation trace (cred reads, exfil, persistence, …)
  analyze/osv/          OSV.dev known-vuln lookup
  analyze/differ/       version-over-version diff (surfaces new install hooks)
  score/                compose static + behavioral + engine into one verdict
  engine/               signal → verdict, with policy (fail-to-review default)
  triage/               pluggable LLM triage: Model interface + mock + Codex
  sign/                 verdict signing (ed25519 default; cosign backend seam)
  verdict/              shared verdict / artifact / signal types
phase0/                 Turnkey burner: launch a hardened, credential-free EC2 host
phase3/                 Detonation network (recording sinkhole + fake resolver) + simulators
```

## Run the proxy

```
go build ./cmd/detonator && ./detonator            # listens on 127.0.0.1:8080

npm install --registry http://127.0.0.1:8080/npm/ <pkg>
pip install --index-url http://127.0.0.1:8080/pypi/simple/ <pkg>
```

Every artifact download is routed through the admission gate and cached by digest.
`--gate static` runs the pipeline (static rules + OSV + version diff) and blocks on
known-critical vulns or obvious install-script malware; `--gate allow-all` is the
transparent stub.

Flags: `--osv` (known-vuln lookup) · `--fail-closed` (block, don't quarantine, on
uncertainty) · `--triage off|mock|codex` (`codex` **sends package source to OpenAI**;
opt-in, warns on start) · `--sign`/`--signing-key` (sign cached verdicts).

Score a trace offline:

```
go build ./cmd/dscore && ./dscore -trace t.json -tarball pkg.tgz -ecosystem npm -name <pkg>
```

## Status

Phases 1–5 are in: the proxy + gate, static and behavioral analyzers, the offline
scorer, verdict signing, the pluggable triage interface (mock local; live Codex
opt-in), and a contained detonation network (a recording sinkhole that decrypts and
logs exfil while denying real egress). The rules have been run blind against real
npm/PyPI malware on a disposable burner.

What the evals show — and where they don't ([`docs/eval/`](docs/eval/)):

- On a **curated** real-malware cohort, ~70% of samples that detonate are caught,
  with **0 false positives** on a benign baseline. Precision came first: a benign
  `.npmrc` / `.netrc` / `/etc/passwd` read is info-tier, because package managers read
  those on every install — flagging them fails on legitimate packages.
- The public "malicious" datasets are labeled by upload *intent*, not behavior: ~28%
  of a random draw were CTF flag-hunters or dependency-confusion PoCs that post to a
  research beacon and steal nothing. Recall over that mix measures the wrong thing.
- The real detection gap is not missing malware *classes* (miners/wipers/reverse-
  shells barely exist in this ecosystem) but **import-time payloads** — malicious code
  in a package's main module that only runs when something requires it, which the
  install-phase detonation doesn't trigger. Import-time trigger coverage and
  obfuscation-severity tuning are the next work.

## Safety

This repo contains **no malware** and no captured exfil. Live samples run **only** on
the disposable, egress-denied burner — never on a laptop, never in a general-purpose
environment. The burner mints its own throwaway SSH key, holds no cloud credentials,
and is torn down after each run. Sample archives stay password-protected until they
are staged inside the sandbox.
