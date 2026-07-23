# Phase-3 triage: live codex validation on the synthetic corpus

**Date:** 2026-07-23
**Model:** `codex exec` (codex-cli 0.145) → `gpt-5.6-sol`, reasoning effort `medium`
(build-plan §7), your subscription auth.

This is the live-model validation the earlier Phase-3 writeup deferred — run against
the **harmless synthetic corpus** (fake C2s, no real payloads), so it's a real-LLM run
with zero malware egress. It found and fixed three integration defects and one prompt
defect before any real-malware run.

## Integration defects found and fixed

1. **Invalid CLI flag.** `codex.go` passed `--ask-for-approval never`, removed in
   codex-cli 0.145 — every codex call errored to usage. Dropped it (`codex exec` is
   non-interactive); added `--skip-git-repo-check`.
2. **Wrong model id.** The config's model is `gpt-5.6-sol`; the "Medium" in "GPT-5.6
   Sol Medium" is the *reasoning effort*, a separate setting. Fixed the default and
   threaded `-triage-effort` (default `medium`, set via `-c model_reasoning_effort`).
3. **Fragile JSON extraction.** `extractJSONObject` took last-`{`-to-last-`}`, which
   broke when codex's rationale quoted JSON like `{"name":"r"}` (a brace inside a
   string) — one malicious case failed to parse. Replaced with a balanced-brace scan
   that respects string literals + escapes; regression-tested.

## Prompt defect: "thin evidence → quarantine" was a precision catastrophe

The original prompt said *"when rules and behavior disagree or evidence is thin, choose
quarantine, not allow."* On the synthetic benign controls, codex quarantined **3/3** —
including a package whose only source is `module.exports = (a,b) => a+b`. Its own
rationale: *"the available evidence is too thin to establish that the published package
performs only this benign behavior; under the stated precision policy, quarantine is
appropriate."* The model was correct to the instruction; the instruction was wrong.

Rewrote the decision policy: **allow** when no malice indicator is present (absence of
exhaustive proof is not grounds to escalate); **quarantine** only on a concrete
suspicious indicator or a clear rules/behavior disagreement; **block** on clear
malicious capability. Explicitly: *"Do NOT escalate merely because evidence is thin."*

## Result (tuned prompt)

| case | class | rules | LLM | composed |
|---|---|---|---|---|
| curl\|bash postinstall | mal | block | block | block |
| `_0x` obfuscator | mal | quarantine | quarantine | quarantine |
| reverse-shell source | mal | block | block | block |
| env-stealer postinstall | mal | block | block | block |
| pure `add()` function | benign | allow | **allow** | allow |
| minified terser bundle | benign | allow | **allow** | allow |
| reads `NODE_ENV` + fetch | benign | allow | *quarantine* | quarantine |

- **Malice recall: 4/4.** **Benign precision: 2/3** (0/3 before tuning).
- The remaining benign disagreement (`NODE_ENV` in a request URL at import) is a genuine
  borderline — an import-time env-influenced network call is worth a human look — not an
  obviously wrong call. Not tuned further, to avoid overfitting the prompt to one case.

## Raw capture (for offline refinement)

`dscore -triage-raw <file>` and `triage.CodexModel.RawSink` capture, per package, the
**exact prompt sent and the exact bytes codex returned** plus the parsed output, as
JSONL. So an eval can be re-scored/re-analyzed without re-invoking the slow, paid model —
the property we want before spending a real-malware run.

## Open item: the real-malware eval

Not yet run — it needs the phase-3 cohort, which lived on the (now torn-down) burner. It
requires either re-standing-up a burner to re-acquire + re-detonate (hours), and a
decision on custody (codex runs locally on your subscription, so the cohort source would
have to reach this machine to be triaged). The harness, raw capture, tuned prompt, and
model config are all in place; only the authorized cohort run remains.
