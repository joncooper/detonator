# Phase-1 eval: blind detonation over a natural distribution

**Date:** 2026-07-22
**Corpus:** 25 samples drawn at random from the Datadog
`malicious-software-packages-dataset` (18 npm, 7 pypi) — no hand-picking by class,
so this measures recall against the *natural* mix of what the dataset holds.
**Pipeline:** each sample detonated in the gVisor sandbox (OpenSSF package-analysis)
on a disposable EC2 burner, CI-env spoofed (`CI`/`GITHUB_ACTIONS`/`GITLAB_CI=true`),
network contained by the recording sinkhole (egress denied, registry allow-listed),
then scored blind by `dscore`.

## Headline

| | Caught (block/quarantine) | Allowed (missed) | No data |
|---|---|---|---|
| npm (18) | 13 | 4 | 1 |
| pypi (7) | 4 | 2 | 1 |
| **total (25)** | **17** | **6** | **2** |

- **Recall on samples that produced a trace (23): 17/23 = 74%.**
- Recall on all 25 (counting the 2 no-data as misses): 68%.

The number is deliberately *not* rounded up. Two guards kept it honest:

1. A **benign-pypi control** (a do-nothing `setup.py` that only calls `setup()`)
   was detonated through the same pipeline. It read `/etc/passwd`, `/etc/shadow`,
   and `/root/.netrc` — and the *original* scorer **quarantined it** on
   `sensitive-read:netrc` (severity high). pip reads `~/.netrc` for registry auth on
   every install, so that signal fired on the whole ecosystem, benign and malicious
   alike. Fixed: `netrc` demoted to info-tier (matching npm-token / etc-passwd /
   etc-shadow). This **removed two false quarantines** (`pytorch-lighting`, `ctosec-…`)
   — i.e. it made the recall number *look worse while making the detector better*.
   npm decisions were unchanged by the fix.
2. Each `allow` was diagnosed as **detection miss vs. no-observable-payload**, rather
   than lumped together.

## Miss taxonomy (the 6 allows)

**Real detection miss — malicious code demonstrably executed, we did not flag it (0):**
- None. The one candidate — `supervot` — turned out to be a **CTF flag-hunter, not
  malware**. Its `exploit.js` reads `/etc/passwd` looking for a `{…}` flag pattern,
  checks `/flag` `/tmp/flag` `./flag`, prints results with 🎯 emojis, and **exfiltrates
  nothing**. Our `allow` is correct. Flagging it would require treating a bare
  `/etc/passwd` read as high-severity — the exact noise we deliberately demote.
  (It also could not be caught via process attribution even if we wanted to: the
  package-analysis trace has no per-PID file attribution — `FileOp` is just
  `{Path, Read, Write, Delete}` — so a package script's reads are indistinguishable
  from npm's in the trace.)

**No observable payload in the captured window — dormant / gated / truncated (5):**
- npm: `flockiali`, `huggingface-cli`, `digitalexp-components` — install hook fired but
  no payload subprocess ran; their `import` phase was truncated (see watchdog note).
- pypi: `pytorch-lighting`, `ctosec-…` — exhibited nothing beyond the sandbox-noise reads.

**No usable data — harness gaps, not detector results (2):**
- `defi-env-auditor` (npm): `NO_TRACE` — no results JSON produced.
- `bytedtrace` (pypi): `NO_PKG` — stored as a **wheel** (`.dist-info/` layout, no
  `setup.py`) with corrupted doubled paths (`…dist-info/X/…dist-info/X`) and a typo'd
  module (`__init__py.py`). The repack only handles sdists; general wheel support is
  cheap, but this particular sample is mangled beyond clean reconstruction.

## What fired on the real malware

Across the caught set: `data-destruction` (4×), `exfil-chain`, `unknown-domain`,
`hardcoded-ip-endpoint` (3×), `recon-burst`, `npm-install-hook-danger`, and on pypi
`obfuscated-blob` + `dynamic-exec-decoded` + `encoded-network-indicator` (`pybowl`).
The dependency-confusion sample `@navancorp@fe-analytics` lit 7 rules including
`sensitive-read:dotenv` + `sensitive-read:shell-rc` + `exfil-chain`.

## Methodology notes / known gaps

- **CI-spoof works**: confirmed `CI=true`, `GITHUB_ACTIONS=true`, `GITLAB_CI=true`
  present in `Commands[].Environment` of the traces.
- **Datadog dataset stores unpacked source, not published artifacts** — must repack to
  a `.tgz` (npm `package/…`) / sdist (`<name>-<ver>/setup.py`) before `-local` detonation.
- **8-minute idle-container watchdog** truncates the harness's 30-minute post-install
  sleep. Fine for install-time malware (the overwhelming majority); a coverage gap for
  time-bombed / delayed payloads.
- **Process attribution** is the recurring lever — it is the fix for the one real miss
  (`supervot`) and would let credential-read signals be trusted without FP-ing on the
  package manager's own reads.
- **`py-setup-execution` precision** is not yet baseline-tested against real benign pypi
  packages with non-trivial `setup.py` (numpy-style build logic). The 3 remaining pypi
  quarantines rest on it; validate with a benign pypi cohort before trusting them.

## The corpus is contaminated (the real finding)

Datadog's `malicious_intent` set is labeled by **upload intent**, not behavior, so it
mixes real malware with **CTF challenges and dependency-confusion PoCs** (the numbered
researcher handles — `ect-987654-ctf`, `arif-nasiuduk24-*`, `hadi-klipo87-*`, and
`supervot` itself). "Recall" against this slice measures "did we flag an intent-flagged
upload," not "did we catch functioning malware." When the one apparent miss is inspected
at the source level, it evaporates into a benign flag-hunter.

Consequence: **the honest count of real detection misses on this corpus is 0** — every
sample whose payload actually executed malicious behavior was caught. That also means the
recall *denominator* is inflated by harmless PoCs, so the 74% understates behavioral
recall. The right next step is not more of this corpus but a **curated, class-labeled
real-malware set** (phase-3) that excludes CTF/PoC noise.

## Bottom line

On a natural, un-cherry-picked slice: 17/23 flagged, **0 real detection misses** (the one
candidate was a CTF flag-hunter), the rest dormant/no-observable-payload, plus 2 harness
failures. Two precision wins came from adversarial self-checks: the benign-pypi control
caught a netrc FP that would have inflated pypi recall, and source inspection of the lone
"miss" showed the corpus itself is the limiting factor. Curate real malware for phase-3.
