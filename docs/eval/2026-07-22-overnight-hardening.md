# Overnight hardening — false positives + gap closure (2026-07-22)

Conservative, precision-first pass over the static analyzer. Two workstreams:
fix a confirmed benign false positive, and close the highest-value static gaps
from the taxonomy audit. Every change is minimal, tested, and leaves the
synthetic detection corpus intact.

Branch: `jon/overnight-hardening` (off `jon/detonator-build`). Not pushed, not
merged. `go test ./...` green at every commit.

## 1. False positives fixed

| Package | Eco | Was | Rule mis-fired | Root cause | Fix | Now |
|---|---|---|---|---|---|---|
| pillow 12.3.0 | pypi | quarantine | `encoded-network-indicator` (high) | The wheel ships a CycloneDX SBOM (`.dist-info/sboms/pillow-12.3.0.cdx.json`, per PEP 770). Its `pedigree/diff` field embeds a **base64-encoded git commit log** that decodes to prose containing a URL. `scanContents` scanned the SBOM as if it were source. | Skip SBOM manifests (`.cdx.json`, `.spdx.json`, `.spdx`, `.cdx.xml`, anything under `/sboms/`) in `scanContents`, mirroring the existing `isBinary` skip. SBOMs are inert provenance metadata, never executed. | **allow** (0 signals) |

Reproduced end-to-end before and after with `dscore` on the real 2.5 MB wheel.
The decoded blob is exactly the audit's evidence string (`commit 782a11d6… Even
Rouault`). The rule itself is unchanged — a regression test asserts the same
base64 blob **still** fires when placed in ordinary `.py` source, so the fix
narrows scope (a non-executable file class) rather than weakening detection.

Code: `internal/analyze/static/static.go` (`isSBOM`), test
`TestSBOMProvenanceNotFlaggedAsC2`.

## 2. Gaps closed (applied)

Four static rules added to `scanContents` / the install-hook + setup.py paths.
All are precision-first: they fire only on a benign-distinguishing structural
trait, dedupe one-per-artifact, skip `isTestOrDoc` paths, and each ships unit
tests (positive + precision guards) plus an end-to-end corpus case. Corpus grew
22 → 31 cases; a new `benign-single-env-var-read` control locks precision.

| Rule | Sev | Fires on | Precision key (why benign code doesn't trip) |
|---|---|---|---|
| `reverse-shell-source` | critical | Tier A: literal idioms (`/dev/tcp/`, `nc -e`, `bash -i` + redirect, `mkfifo\|sh`, `socat exec:`). Tier B: connect-back **and** fd-binding (`dup2`/`stdio:[`) **and** a `/bin/sh` target in one file. | Tier A strings are near-absent in benign source. Tier B requires the socket-fd-to-shell-stdio binding — benign clients open sockets and even spawn shells, but never wire a socket onto a shell's stdio. |
| `cryptominer-artifact` | high | `stratum+tcp://`/`stratum+ssl://` alone, **or** a miner binary name (xmrig, minerd, …) + a config token (`randomx`, `--donate-level`, `--coin`, …). | The stratum scheme cannot appear in benign npm/PyPI code. The binary-name path needs two independent tokens and skips prose, so an incidental "ethminer" mention doesn't fire. |
| `destructive-payload` | critical in install-hook/setup.py; high in source | `rm -rf` of a system root / `--no-preserve-root`, `mkfs`, `dd of=/dev/`, `shred` of a device/home, `rmSync`/`rmdirSync`/`shutil.rmtree` of `~`/`$HOME`/`/`. | Every branch requires a **system root, a device, or a home reference**. Benign build cleanups (`rm -rf dist/build/node_modules`, `rmSync('build')`, `rmtree('build')`) never match. Mirrors behavior.go `destructiveCmd`, lifted to static so a wiper scores even if it never detonates. |
| `install-env-exfil` | high; critical at install time | **Bulk** env serialization (`JSON.stringify(process.env)`, `dict(os.environ)`, `os.environ.copy()`, `{...process.env}`, …) co-located with a network primitive. Escalates when the file is an npm install-hook target or `setup.py`. | Requires the **whole-env** form, never a single named var. Benign code reads `process.env.FOO` pervasively but essentially never ships the entire env next to an egress call. Defeats dotenv / webpack DefinePlugin / config-lib FPs. |

### Coverage impact on the audit families

- **install-hook env stealer** → `install-env-exfil` closes both seams
  (plaintext collector referenced by a hook; harvest in a runtime module).
- **reverse shell / RAT** → `reverse-shell-source` closes the source-resident
  static blind spot (hostname C2, not an install hook, no IP literal).
- **cryptominer** → `cryptominer-artifact` closes the static side (bundled
  config / miner spawn); behavioral `mining-pool-egress` already covered runtime.
- **wiper / destructive** → `destructive-payload` closes the static side
  (`postinstall: rm -rf --no-preserve-root /` was only `npm-install-hook` low;
  a `shutil.rmtree('/')` setup.py matched no token). Behavioral side was covered.

## 3. Deliberately deferred (for human review)

Skipped to hold the precision bar. Each is valuable but could not be made
FP-safe with the confidence a live, precision-first gate demands. Recommend
human review before landing any of these.

| Proposal | Why deferred |
|---|---|
| `dynamic-exec-deobfuscated` (indirect data-flow: `var p = decode(blob); … eval(p)`, plus hex/zlib/marshal codecs) | The value is real (a common two-liner the current inline rule misses), but the proposed matcher binds the **same identifier** across arbitrary distance between the decode and the sink. Go's RE2 has no backreferences, so a regex approximation would either miss the binding or co-fire on an unrelated `eval()` and an unrelated `Buffer.from(longB64,'base64')` in the same large/minified file — a genuine FP risk on benign bundles that embed base64 assets/wasm. Needs a small lexer/data-flow pass, not a regex. Extending the **codec alphabet** on the existing inline rule (hex/zlib/marshal) is a safe subset that could land alone later. |
| `self-propagation-manifest-tampering` (worm core) | The AND-of-two-conjuncts is precise in principle, but distinguishing a worm's *foreign*-manifest enumeration from benign monorepo/release tooling (lerna, changesets, nx) that legitimately reads/writes many `package.json` files needs care. Wrong call blocks a popular release tool. Warrants human-tuned corpus work. |
| `sandbox-evasion-gate` (env/host/date/VM-gated payload) | Discriminator-comparison + payload-primitive in the same file is broad. Config libraries that read `os.hostname()`/env and also carry a `netPrimitive` are common; without tight proximity/branch-scope analysis the FP risk is material. Defer until proximity gating is prototyped against the benign cohort. |
| `persistence-mechanism` (static cron/systemd/authorized_keys) | Good and mostly precise, but overlaps the already-strong behavioral `persistence-write`. Lower marginal value tonight; the tightest sub-rules (`authorized_keys`, `/etc/cron`, systemd + write primitive) are a reasonable follow-up. Held to keep the change set small. |
| `region-gated-sabotage`, `install-hook-identity-beacon`, `chat-webhook-exfil`, `download-chmod-exec` | Each is plausibly precise, but adds surface area beyond tonight's "do less but correct" scope. `chat-webhook-exfil` (endpoint path + embedded token) and `download-chmod-exec` (chmod-to-executable as the load-bearing token) are the strongest next candidates. |

### Behavioral-side notes (not applied)

The audit's secondary behavioral proposals — treat `/proc/self/environ` reads
and `env|printenv`-piped-to-network as credential reads; flag interpreter-run
second stages (`node /tmp/x.js`); name chat-webhook hosts; escalate
`npm publish` co-occurring with an npmrc read — are all reasonable and low-risk,
but none had a failing corpus case tonight and each touches the runtime
classifier. Deferred as a separate behavioral pass so this change stays static
and self-contained.

## Verification

- `go test ./...` — green (run after every edit; nothing committed red).
- Synthetic corpus — 31/31, including all pre-existing detections unchanged
  (never weakened).
- pillow 12.3.0 — `quarantine → allow` via `dscore` on the real wheel.
- Benign controls (existing + new single-env-var) — all `allow`.
