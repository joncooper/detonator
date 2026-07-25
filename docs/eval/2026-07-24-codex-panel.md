# Codex panel: the third tier recovers 6/9 of the two-tier residual (2026-07-24)

Ran the Codex panel — a **behavior reviewer** (judges the detonation trace), a **source
reviewer** (judges the source), and a **combiner** — over the 9 packages that **both**
static and behavioral missed the night before. Model: `gpt-5.6-sol`, medium reasoning.
This is the third tier, and the question is whether an LLM reasoning over trace+source
catches what the rules' *shapes* cannot.

**It caught 6 of 9.** All 6 came with `rules-llm-disagreement` — the panel overrode the
rules' `allow`.

| package | panel | why (combiner) |
|---|---|---|
| elf-stats-midnight-mitten-226 | **block** | reverse shell: spawns `/bin/sh`, connects `161.97.148.123:9000`, pipes socket↔shell |
| sdbao-content-sems | **block** | install-time remote code execution |
| danzoo1-utilss | **block** | install-time remote code execution |
| mailconfirmer | **block** | install-time exfil / RCE |
| rca-overlay-panel | **quarantine** | unexplained postinstall on a trivial package |
| plugin-vue | **quarantine** | reads `/root/.npmrc` + `/app/.npmrc` at install (npm-cred harvest) |
| elf-stats-bright-star-581 | allow | — |
| psalm | allow | postinstall JS threw a SyntaxError immediately — inert |
| elf-stats-silvered-toolkit-914 | allow | — |

## Why this matters

The two headline catches are exactly the rule-gap cases from the export-fuzzing run:

- **`elf-stats-midnight-mitten-226`** — the raw-IP `.pipe()` reverse shell. Static's
  `reverse-shell-source` only matches `dup2`; behavioral's `unknown-domain` is DNS-shaped
  so a hardcoded-IP connect-back is invisible. The panel read the source *and* the trace
  and reasoned about the shell wiring directly — no rule shape required. Confidence 1.0.
- **`plugin-vue`** — reads `.npmrc` (where npm auth tokens live) during install. No
  behavioral rule covers that today; the panel flagged it from the runtime file reads.

And it **discriminates** rather than flag-everything: `psalm`'s postinstall threw a
SyntaxError and did nothing, and the panel correctly returned `allow` at 0.94. The three
`allow`s are plausibly correct (inert name-squats / broken payloads), not misses — which
is the behavior you want from an adjudicator, not a klaxon.

## The layered detector, end to end

| tier | what it adds | measured |
|---|---|---|
| **Static** | source rules, offline, free | 45.3% → 52.7% held-out (after hardening) |
| **+ Behavioral** | detonation trace | recovers 64% of npm static-misses → **npm 84%** (101/120) |
| **+ Codex panel** | LLM over trace+source | recovers **6/9** of what both prior tiers missed |

Each tier catches what the others' shapes miss: static sees source patterns, behavioral
sees runtime, the panel *reasons about intent* over both. Folding the panel's ~⅔
recovery into the npm residual points toward ~90%+ combined — but that's an estimate off
a 9-sample panel, not a measurement.

## Cost and how to deploy it

- **27 codex calls** (3 × 9), Sol medium. The panel is the **expensive** tier — in
  production, gate it to the **ambiguous** cases (rules `allow`/`quarantine` with low
  confidence), not every package. That is exactly what `internal/gate/pipeline.go`
  already does with `rules-llm-disagreement`.
- The panel independently flagged the reverse shell and the `.npmrc` reads — corroborating
  that the two rule-gap fixes from the export-fuzzing run (`.pipe()` reverse shells;
  raw-IP egress; and a new `.npmrc`-read behavioral signal) are worth building. The cheap
  rules should catch these; the panel is the backstop, not the front line.

## Method notes / limits

- 9-sample panel — directional, not a recall figure.
- Inputs were the **saved corpus traces** (`eval-captures/`) + re-fetched source; no
  re-detonation. This is the raw-capture path working as intended — the panel is redone
  offline for free.
- Gotcha: `-triage-schema` must be an **absolute** path — codex resolves it relative to
  its own CWD, so a relative path silently fails (empty verdict → `allow`).
