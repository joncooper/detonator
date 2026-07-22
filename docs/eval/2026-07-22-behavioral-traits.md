# Behavioral traits — validation (2026-07-22)

Added behavioral trait rules for the malware classes the July-21 corpus lacked
(it was 10/11 credential stealers): `persistence-write`, `binary-overwrite`,
`download-and-execute`, `reverse-shell`, `mining-pool-egress`, `recon-burst`,
`data-destruction`, `dns-exfil`. See `internal/analyze/behavior/behavior.go`.

## Validation

- **Unit tests** per trait — green.
- **Synthetic corpus** (`internal/eval`) — one harmless case per trait
  (persistence, reverse-shell, dropper, cryptominer, wiper, dns-tunnel) plus a
  native-build benign control — green.
- **Static benign cohort** — 20 popular packages, **0 false positives** (after
  the earlier precision tuning).
- **Behavioral benign cohort** — 10 popular packages detonated `-local` through
  the recording sinkhole; of the 7 that detonated cleanly, **0 behavioral false
  positives**. Key hard cases pass: `bcrypt` (native node-gyp/gcc/make build),
  `core-js` (`node -e` postinstall), `requests`/`six`/`click` (pypi),
  `chalk`/`lodash`. The 3 `NO_TRACE` (`axios`, `esbuild`, `express`) were install
  failures under the sinkhole (dep/postinstall resolution), not detections.

## Precision design

Native-build spawns carry no danger tokens so they never fire; `recon-burst`
counts *distinct* profiling tools (one `uname` is fine); a package's own
install-dir writes don't match persistence paths.

## Still open (next session — Plan 2)

Expand the real corpus beyond credential stealers (MalwareBazaar + Datadog
`malicious-software-packages-dataset`), detonate with CI-env spoofing through the
sinkhole, and score recall **by class**. The recording network comes up in one
command via `phase3/recording-net/setup.sh`.
