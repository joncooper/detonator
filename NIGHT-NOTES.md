# Overnight notes — 2026-07-23 → 24

Morning, Jon. Autonomous run against the "sample effectively from the cross-confirmed
cohort" push. Headline: **a real held-out eval now exists**, static recall went
**45% → 53% and the lift generalizes**, and the detector is precision-hardened at scale.
Everything below is committed to `main`. Burner teardown status at the bottom.

## Morning addendum — export fuzzing (`docs/eval/2026-07-24-export-fuzzing.md`)

You flagged that runtime-fetch and self-de-obfuscating payloads *should* be behaviorally
visible, and that the "misses" smelled like a coverage gap. Tested it: patched the npm
import harness to enumerate + invoke a module's exports (function-gated payloads), rebuilt
the sandbox, and detonated a **205-npm batch** behind the sinkhole, saving every trace.

- **Export fuzzing recovered 1 of 10 residual misses** (`whatsapp-core-auth-drzak`, a
  domain-C2 beacon). Modest — the hypothesis was partly right.
- The other 9 are **rule gaps, not function-gating.** The `elf-stats-*` misses are IIFE
  reverse shells to **raw IPs** — they run on require (fuzzing irrelevant) and the sink
  *captured the connection*, but static's reverse-shell rule only matches `dup2` (not
  `.pipe()`) and behavioral's `unknown-domain` is DNS-shaped, so a hardcoded-IP
  connect-back is invisible. **Two concrete fixes** fall out (static `.pipe()` reverse
  shells; behavioral raw-IP egress) — both testable against the saved corpus offline.
- **Corpus saved**: 195 traces + 206 logs → `eval-captures/2026-07-24-export-fuzzing-corpus.tgz`
  (gitignored). Burner torn down.
- Serial-only (concurrent detonation hit a gVisor container-creation race); pypi still
  dep-undercounted.

**Codex panel (third tier), run over the 9 residual** (`docs/eval/2026-07-24-codex-panel.md`):
behavior-reviewer + source-reviewer + combiner (gpt-5.6-sol medium) over trace+source.
**Caught 6/9** of what static AND behavioral both missed — including the raw-IP `.pipe()`
reverse shell (panel reasoned about the shell wiring directly, conf 1.0) and `plugin-vue`
reading `.npmrc` at install. It also correctly *allowed* `psalm` (postinstall SyntaxError'd,
inert) — it discriminates, not a klaxon. So the layered picture: static 45→53%, +behavioral
npm 84%, +panel recovers ~⅔ of the remaining residual. The panel is the expensive tier
(27 codex calls for 9 pkgs) — gate it to ambiguous cases, which the live gate already does.

## What got done

1. **First real held-out eval** (`docs/eval/2026-07-24-heldout-static-recall.md`).
   Two disjoint deterministic samples of 150, drawn from the 3,372 cross-confirmed
   (Datadog ∩ Backstabber's) pool. Frozen v1 rules on Set 1: **45.3%** static recall.
   Added 3 rules. v2 on fresh disjoint Set 2: **52.7%** — the +7pt lift holds on unseen
   data, so it's not overfit. pypi recall roughly doubled.

2. **3 new detection rules**, each precision-gated + unit-tested:
   - Python string-escape obfuscation (BlankOBF `eval("\145\x61…")`) — the JS `_0x`
     fingerprint was blind to the entire Python stealer family.
   - Shell recon in exec'd install commands (`curl "…$(whoami)…/etc/passwd|base64"`).
   - Hardcoded Discord/Telegram exfil webhooks.

3. **Precision at scale** — top-1500 npm + pypi, static-only. **npm 0 FP / 1500.**
   pypi surfaced ~26 flags, all pre-existing rules except one (passlib, mine — fixed).
   Drove a hardening pass: placeholder IPs (1.2.3.4, repeated-octet), Dockerfiles +
   build/packaging/nix dirs, minified bundles, proximity for shell-recon, package-metadata
   skip, `_0x` word-boundary, `re.compile` exclusion. After fixes the 3 new rules are
   **0 FP across the full top-1500**; pypi residual is **9/1421 (~0.6%), all pre-existing
   rules** (setup.py legitimately fetching; a reverse-shell *example* in pyserial; build/
   test wipers), listed as follow-ups in the eval doc.

4. **Behavioral lift** (detonation of Set 2's static-misses, behind a
   containment-verified recording sinkhole). Detonated the 53 npm static-misses:
   **34/53 (64%) now caught behaviorally** — so combined npm recall goes **56% static
   → 84% static+behavioral (101/120)**. Signals were diverse: unknown-domain (29),
   process-spawn (4), data-destruction (3), dns-exfil (2), an ssh-key read (1),
   exfil-chain (1). pypi (17) is dep-undercounted (the sinkhole registry allowlist is
   broken, so pip can't fetch build deps → 0 caught); the npm number is the clean one.

## Commits (all on `main`, pushed to origin)

- `3ff5785` held-out eval + 3 precision-gated rules (45%→53%)
- `a22881d` exclude 1.2.3.4 placeholder IP
- `b96834e` Dockerfiles + container-build dirs as build tooling
- `854accf` precision-at-scale FP fixes (passlib proximity, repeated-octet IP, minified
  guard, packaging/nix/docker build-tooling)
- `e22b685` skip package metadata (PKG-INFO/METADATA/egg-info) in code scans
- `106cb81` finalize precision-at-scale writeup
- `cd8bc60` two more new-rule FP fixes from the pypi cohort tail (`_0x` boundary, `re.compile`)
- `dbc54bf` finalize pypi residual + magika note
- (this commit) behavioral-lift results + morning note

## The honest limits (don't oversell these numbers)

- **Static-only recall.** 52.7% is a floor. ~⅓ of the misses are runtime-only beacons —
  the behavioral tier's job (see §4).
- **~7–12% of the "misses" are inert PoC contamination** (dependency-confusion
  hello-worlds, RCE-proof file writes). Static is *correct* to pass them; true recall on
  packages that actually carry a payload is meaningfully higher than the headline.
- **The STAGED_EXEC gap remains** (~25/150): download-then-exec. Largest recoverable
  static cluster still missed; needs its own tuning pass + a third held-out slice.
- **One cross-source pair** (Datadog ∩ Backstabber's). Cleaner than either alone, still
  two curators.

## Follow-ups (my recommendation, in order)

1. A **staged-exec** static rule (`exec(urlopen().read())`, `exec(b64decode(...))`) —
   biggest remaining static gap. Tune on Set 1, eval on slice 3 (`phase3/heldout/split.py 3`).
2. The pypi setup.py-fetch FPs (reportlab/statsmodels/vcrpy): consider py-setup-execution
   network → quarantine (not block) so a legit build-fetch isn't auto-blocked.
3. Fix the sinkhole registry allowlist (FORWARD DROP ordered before the registry ACCEPTs;
   host can't reach the anycast IP) so **pypi** detonation gets real deps — right now the
   pypi behavioral tier is dep-undercounted (§4).

## Reproduce

- Held-out split: `phase3/heldout/split.py xref-npm.txt xref-pypi.txt <1|2|3>` (names only).
- Precision at scale: `phase3/benign-precision-at-scale.sh {npm,pypi} 1500 /tmp/prec`.
