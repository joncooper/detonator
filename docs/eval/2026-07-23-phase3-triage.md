# Phase-3: LLM triage in the offline scorer

**Date:** 2026-07-23
**Status:** wiring built and validated with the mock backend; the live-Codex measurement
is deferred (see "Open item"). Autonomous decision recorded below.

## What this adds

Triage was already wired into the *live gate* (`internal/gate/pipeline.go`), but not the
*offline scorer* the eval uses, and it never saw the detonation trace. Phase-3 closes
that so the model can adjudicate the rules' ambiguous cases over source **and** runtime.

- **`score.ScoreTriage(ctx, in, policy, model)`** — `Score` plus an LLM stage. It runs
  the deterministic rules, then hands the model the signals, bounded source excerpts,
  and the **behavior log** (`triage.Input.BehaviorLog`, previously unused). The model's
  judgment is composed as signals — `llm-<decision>` plus a `rules-llm-disagreement`
  signal when the model and the rules diverge on clearing the package — and the engine,
  not the model, makes the final call. An LLM "block" only quarantines (never auto
  hard-blocks); disagreement is Medium.
- **`dscore -triage mock|codex`** — opt-in triage on the offline scorer. `-triage-model`
  (default `gpt-5.6-sol-medium`, per build-plan §7) and `-triage-schema` configure Codex.
- **`triage.SelectExcerpts`** — the bounded excerpt picker was moved from the gate into
  the triage package so the gate and the scorer feed the model identical evidence (DRY).

Unit tests (`internal/score/score_test.go`): the benign path stays `allow` with an
`llm-allow` signal; a lone `/etc/passwd` read that the rules allow gets escalated off
`allow` via the `rules-llm-disagreement` path (the adjudication the eval targets); and
`ScoreTriage(nil model)` equals `Score` (triage is strictly additive).

## Validated end-to-end on real data (mock)

`dscore -triage mock` over the phase-3 samples composes the model judgment alongside the
rules — e.g. `lodash-twist` → `quarantine` with `[obfuscated-code, llm-quarantine,
sensitive-read:npm-token]`, `login-paypal` → `quarantine` with `[host-recon-exfil,
llm-quarantine, …]`. The mock is a deterministic heuristic that escalates on the same
high signals, so it mostly mirrors the rules — it proves the plumbing, not adjudication
quality. That is a real-LLM (Codex) question.

## The Codex backend

`internal/triage/codex.go` runs `codex exec --output-schema … --sandbox read-only
--model <name>`, reading the evidence prompt (source excerpts + behavior log + signals)
from stdin and parsing the schema-conforming verdict. It targets GPT-5.6 Sol Medium and
`phase0/verdict-schema.json`. It is ready; it just needs a key and a codex binary in a
place where sending the source out is authorized.

## Open item: the live-Codex measurement (deferred, deliberately)

The Phase-3 eval question — *does the LLM catch the rules' residual misses (the
obfuscated / host-recon cases) without false-positiving on benign packages?* — needs the
**real model**, not the mock. It was not run this session, by an explicit choice:

- **codex is not on the burner** (where the malware source lives), and there is **no
  `OPENAI_API_KEY`** available.
- Running it would mean either pulling malware source to a laptop (violates the custody
  discipline) or installing codex + a key on the burner and **sending malware source to
  OpenAI** — the checkpoint the approved plan flagged for explicit confirmation.

Given "the model is opt-in and sends source to a third party," the correct autonomous
choice is to build + validate the wiring and **not** send malware to OpenAI unilaterally.

**To run it** (on a host authorized to send the cohort source out):
```
# install codex + set OPENAI_API_KEY there, then, per ambiguous sample:
dscore -trace <trace>.json -tarball <pkg> -ecosystem <eco> -name <pkg> \
       -triage codex -triage-model gpt-5.6-sol-medium -triage-schema phase0/verdict-schema.json
```
Score the phase-3 allows + quarantines and measure recall on the rules' misses
(`lodash-twist`, `login-paypal`, …) against precision on the benign static cohort. The
harness, flags, and composition are all in place; only the authorized live invocation
remains.
