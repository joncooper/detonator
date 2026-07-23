# Phase-1 static hardening: obfuscator + host-recon rules, and a precision gate

**Date:** 2026-07-23
**Scope:** close two static gaps the phase-3 curated eval diagnosed, add a local
precision gate, and fix the pre-existing false positives that gate exposed. Validated
by re-scoring the 42-sample phase-3 cohort on the burner (static path only — no
re-detonation) and by a benign-package precision cohort run locally.

## Two new detection rules

- **`obfuscated-code`** (`SevHigh` → quarantine): the javascript-obfuscator (`obfuscator.io`)
  fingerprint — a dense cluster of distinct `_0x`-hex identifiers. Benign minifiers
  (terser/esbuild) rename to short alphanumerics, never `_0x`-hex, so this is precise and
  distinct from ordinary minification (which stays informational). It is strong-suspicious,
  not proof, so it reviews rather than hard-blocks.
- **`host-recon-exfil`** (`SevMedium`, `SevHigh` at install time): a file that reads ≥2
  distinct host/identity primitives (`os.hostname`, `os.userInfo`, `process.env.USER`, …)
  and has a network sink. Deliberately excludes the ubiquitous `process.platform` /
  `HOME`, and requires the distinct-count + a sink, so a lone hostname read never fires.

## Cohort re-score delta (25 → 31 caught, of 40 scorable)

New rules caught 5 former misses, and a static-fallback (score the source when a
detonation produced no trace) caught 2 more:

| Sample | Before | After | Why |
|---|---|---|---|
| `lodash-twist` | allow | **quarantine** | `obfuscated-code` (the primary target) |
| `login-paypal` | allow | **quarantine** | `host-recon-exfil` |
| `paypal-product-picker` | allow | **quarantine** | `host-recon-exfil` |
| `e-voting-libraries-ui-kit` | allow | **quarantine** | `host-recon-exfil` |
| `marketing-content-podlet` | allow | **quarantine** | `host-recon-exfil` |
| `healcode-client` | NO_TRACE | **quarantine** | `obfuscated-code` (static-fallback) |
| `jwt-pack` | NO_TRACE | **quarantine** | `install-env-exfil` (static-fallback) |
| `pycalculate` | block | *allow* | `py-setup-execution` tightened (see below) |

`host-recon-exfil` — added as exploratory, to be dropped if it false-positived — caught
4 real stealers at **0 benign FP**, so it stays. The remaining allows are import-time /
no-trace samples (Phase 2 territory: `core-pino`, `bingo-logger`, `morgan-logger`,
`openclaw-droid`) and screen over-inclusions / CTF handles (`tailwindcss-*`, `ctfvamp`,
`test-thegenetic-module`).

## The precision gate paid for itself immediately

`phase3/benign-static-cohort.sh` fetches ~30 popular, legitimate npm/PyPI packages and
runs `dscore` static-only (a new capability — `dscore` no longer requires `-trace`),
requiring 0 block/quarantine. On first run it flagged **5 pre-existing pypi FPs** that
would have quarantined or blocked the most-installed packages in the ecosystem. All fixed:

| Package | Rule | Root cause | Fix |
|---|---|---|---|
| urllib3, flask | `hardcoded-ip-endpoint` | version strings / OIDs (`"3.5.0.1"`, `ObjectIdentifier("1.2.3.4")`) parse as public IPs | require the IP to sit in a host/connect position, not merely near network code |
| numpy | `destructive-payload` | shipped CI/build tooling (`.github/workflows`, `vendored-meson/packaging`) doing `rm -rf`/`rmtree` | exclude build/CI/vendored paths from the wiper rule |
| boto3 | `embedded-aws-key` | AWS's own doc placeholder `AKIA…EXAMPLE` in a `.rst` | skip test/doc paths and `EXAMPLE`-suffixed keys for secret scans |
| setuptools, numpy, boto3 | `py-setup-execution` | fired on any benign `setup.py` that runs build code or has a homepage `url=` | require a genuine network CALL, shell danger token, or exec-of-decoded — not bare build code |

After the fixes the cohort is **0/30 flagged**. The `py-setup-execution` change is the
only one with a recall cost: it moved `pycalculate` (block → allow) because its `setup.py`
takes no network/danger action — while the real pypi stealers (`zorosnitro`, `captcha-py`,
`install-crypto`, …) still block, because theirs do. Fixing FPs on numpy/setuptools/flask/
urllib3/boto3 for the cost of one dataset sample is a clear trade.

## Verification

- `go test ./...` green (unit tests per new rule and per precision fix; synthetic corpus
  cases for the two techniques + benign fixtures).
- `phase3/benign-static-cohort.sh`: 0/30 benign packages flagged.
- Burner re-score of the 42 phase-3 tarballs: deltas above; no regression beyond the one
  documented `py-setup-execution` trade.
