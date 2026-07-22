# Plan: expand the real-malware corpus (Plan 2) + add behavioral traits (Plan 3)

## Context

The eval reached 90% recall / 0% FP, but on a **narrow, skewed corpus**: of the 11
real samples, **10/11 are credential/env stealers and 11/11 exfil over HTTPS**.
Coverage of `behavior_labels`: `credential_env_access` 10, `https_exfil` 11, then
a long tail of 1–5 each (second_stage 5, process_spawn 2, obfuscation 1,
dependency_confusion 1, ci_gated 1). Whole malware classes are absent:
droppers, reverse shells/RATs, cryptominers, wipers, persistence, worming, DNS
exfil. And ecosystems skew npm (8) over PyPI (3).

So the 90% is really "90% at catching HTTPS credential stealers." To trust the
detector against what's actually in the wild — and to harden it beyond one class
— we need (2) a **diverse real corpus** and (3) **behavioral traits for the
missing classes**, both validated against a benign behavioral cohort so precision
holds. This is exactly the "don't overfit / broaden the set" direction.

The recording-sinkhole burner is up (`i-0a388eb65193d8354`), and
`phase3/recording-net/setup.sh` now brings the contained network up in one
command.

---

## Plan 2 — diverse real-malware corpus

Target the **class gaps**, not more of the same. Acquire ~20–30 npm/PyPI samples,
balanced across ecosystems, with ≥2 per class and deliberately including
hard/obfuscated cases (the `matrix-ai` class we missed):

| Class | Why (gap) | What it exercises |
|---|---|---|
| Second-stage dropper (fetch→chmod +x→exec) | only 5, none isolated | download-and-execute trait |
| Reverse shell / RAT | 1 tag only | reverse-shell trait |
| Cryptominer | absent | mining-pool egress trait |
| Wiper / destructive | absent | data-destruction trait |
| Persistence (cron/systemd/rc/ssh keys) | absent | persistence-write trait |
| Worming / package tampering | absent | package-tampering trait |
| Obfuscated / gated loader | only 1 (our miss) | static+trigger coverage |
| Dependency-confusion | only 1 | metadata + high-version signal |
| Non-HTTPS exfil (DNS / Telegram / Discord) | none | dns-exfil / webhook traits |
| More PyPI (sdist setup.py + wheel import) | 3/11 | pypi import/execute paths |

**Sources (decided): MalwareBazaar + Datadog dataset.**
- **MalwareBazaar** via `MALWAREBAZAAR_AUTH_KEY` (on the burner), query by tag:
  `npm`, `pypi`, `supply-chain`, plus class tags (`RAT`, `miner`, `stealer`).
  Reuses the existing custody/acquisition workflow.
- **Datadog `malicious-software-packages-dataset`** — large npm/PyPI set, same
  password-zip convention (`infected`); the richest source for class diversity,
  and the primary source for filling the dropper/miner/wiper/persistence gaps.
- Use `ossf/malicious-packages` (OSV) labels only as a **selection/cross-check
  reference** (not a sample source) to pick representative families per class.

**Discipline (unchanged):** exact-hash acquisition into custody, archives stay
password-protected until staging, detonate only in the contained sinkhole burner,
egress-denied, per-run teardown, export sanitized digest-bound traces only.

**Deliverable:** an expanded, technique-labeled corpus + a fresh blind eval
(recall by class, precision on benign) written to `docs/eval/<date>/`.

---

## Plan 3 — behavioral traits + benign cohort

### New behavioral rules → `internal/analyze/behavior/behavior.go`

Add these blacklist classes (each a general threat CLASS, not a sample IOC),
composed by the existing engine. Current rules: `sensitive-read`, `process-spawn`,
`cloud-metadata-access`, `unknown-domain`, `exfil-chain`.

1. **persistence-write** (critical): file WRITE to cron (`/etc/cron*`,
   `crontab`), systemd unit dirs, shell rc (`~/.bashrc`/`.profile`/`.zshrc`), 
   `~/.ssh/authorized_keys`, git hooks, `~/.config/autostart`.
2. **download-and-execute** (critical): correlate a file WRITE to a temp/exec
   path with a later Command spawning that path, or `chmod +x` + exec (dropper).
3. **reverse-shell** (critical): Command argv matching `sh -i`/`bash -i`,
   `/dev/tcp/`, `nc -e`/`ncat -e`, `mkfifo`+`sh` shells.
4. **mining-pool-egress** (high): socket/DNS to `stratum+tcp`, pool ports
   (3333/5555/7777/14444), or miner binary names (`xmrig`, `minerd`) in Commands.
5. **recon-burst** (medium, corroborating): system-profiling commands
   (`id`/`uname`/`whoami`/`hostname`) + home/root dir listings in one phase.
6. **data-destruction** (critical): Files.Delete count spike, or `rm -rf` of
   home/root, or overwriting existing binaries.
7. **package-tampering** (critical): WRITE into *other* packages'
   `node_modules`/`site-packages`, or modifying a sibling `package.json`.
8. **dns-exfil** (high): many DNS queries under one parent domain with
   long/high-entropy subdomains (encoded-data pattern).

### Precision / whitelist additions (validated against the benign cohort)

- **Native-build spawns are benign**: whitelist `gcc`/`cc1`/`make`/`node-gyp`/
  `python setup.py build_ext` during install (bcrypt/sharp/numpy do this).
- **Self-package writes are benign**: WRITE within the package's own install dir.
- Keep the Tier-3 drops already in place (`~/.npmrc`, `/etc/passwd`, `sh -c`).

### Trigger coverage (so the traits actually fire)

- **Spoof CI env (decided: on)** — inject `CI=true`, `GITHUB_ACTIONS=true`,
  `GITLAB_CI=true` into the sandbox to trip CI-gated payloads like `sbx`.
  Realistic (installs often run in CI) and flagged as a deliberate behavior
  change in the eval writeup. Via package-analysis's env injection.
- Note (not fix now): function-gated payloads need export fuzzing (OSCAR's 3rd
  activation point); record as a known coverage gap.

### Benign behavioral cohort (the precision gate)

Detonate ~15–20 popular packages **through the sinkhole** — including native-build
(`bcrypt`, `sharp`, `numpy`), postinstall (`esbuild`, `core-js`), and networking
libs — and require 0 behavioral FPs. This is the runtime analogue of the
20-package static cohort we just validated (which is now 0/20).

### Lock it in

Add one synthetic case per new trait to `internal/eval/corpus_test.go` (harmless
traces), so coverage is regression-guarded deterministically — same pattern as
the existing 14 cases.

---

## Files

- `internal/analyze/behavior/behavior.go` — new rule functions + whitelist helpers.
- `internal/analyze/behavior/behavior_test.go` — unit tests per new rule.
- `internal/eval/corpus_test.go` — synthetic cases for each new trait.
- `phase3/` — acquisition + benign-cohort scripts (burner-side), and the eval
  runner (reuse `orchestrate-net.sh` shape).
- `docs/eval/<date>/` — expanded results, IOCs, methodology.

## Verification

1. `go test ./...` green (unit + synthetic corpus incl. new traits).
2. Benign behavioral cohort: 0/‹N› FP through the sinkhole.
3. Expanded real corpus: blind detonate + score; report recall **per class** and
   precision, with any misses diagnosed (as we did for telnyx/strapi/matrix-ai).
4. Detection unchanged on the existing corpus (no regression).

## Execution order

1. **Behavioral traits first** (Plan 3 rules + synthetic corpus cases) — pure
   local code, testable immediately, no burner dependency.
2. **Benign behavioral cohort** through the sinkhole (precision gate) — needs the
   burner, which is already up with `setup.sh`.
3. **Corpus expansion** (Plan 2) — acquire from MalwareBazaar + Datadog into
   custody, detonate with CI-env spoof through the sinkhole, blind-score.
4. **Writeup**: per-class recall + precision to `docs/eval/<date>/`.
