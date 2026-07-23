package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// PanelModel is a triage panel: two focused codex reviewers — one over the runtime
// behavior trace, one over the package source — whose independent judgments a third
// codex call synthesizes into the final verdict. Two single-modality reviews cover
// the two ways malice hides (in what the code says, and in what it did when run) and
// reduce the single-prompt bias a one-shot review is prone to. It implements Model,
// so it drops into the gate and the offline scorer unchanged.
type PanelModel struct {
	codex *CodexModel
}

// NewPanel builds a codex-backed triage panel.
func NewPanel(schemaPath, modelName, effort string) *PanelModel {
	return &PanelModel{codex: NewCodex(schemaPath, modelName, effort)}
}

// Name identifies the panel for the audit trail.
func (p *PanelModel) Name() string {
	return "codex-panel/" + strings.TrimPrefix(p.codex.Name(), "codex/")
}

// SetRawSink wires raw capture through to every reviewer and the combiner, so all
// three interactions per package are recorded.
func (p *PanelModel) SetRawSink(f func(RawRecord)) { p.codex.RawSink = f }

// Classify runs the two reviewers, then the combiner, and returns the combiner's
// verdict. A reviewer error does not abort — the combiner is told that review is
// unavailable and weighs the other modality — but a combiner error is returned.
func (p *PanelModel) Classify(ctx context.Context, in Input) (Output, error) {
	behavior, bErr := p.codex.runPrompt(ctx, in.Artifact, "behavior-review", behaviorPrompt(in))
	source, sErr := p.codex.runPrompt(ctx, in.Artifact, "source-review", sourcePrompt(in))
	final, cErr := p.codex.runPrompt(ctx, in.Artifact, "combiner", combinerPrompt(in, behavior, bErr, source, sErr))
	if cErr != nil {
		return Output{}, fmt.Errorf("panel combiner: %w", cErr)
	}
	return final, nil
}

var _ Model = (*PanelModel)(nil)

// behaviorPrompt asks a reviewer to judge ONLY the runtime trace — what the package
// actually did when detonated — deliberately blind to source (the other reviewer).
func behaviorPrompt(in Input) string {
	var b strings.Builder
	b.WriteString("You are the BEHAVIOR reviewer on a supply-chain malware triage panel. Judge ONLY the runtime behavior of this package, observed when it was detonated in a sandbox: what it actually DID — files read/written, network endpoints contacted, processes spawned. Do NOT infer from source; a separate reviewer covers that.\n\n")
	b.WriteString(decisionPolicy())
	b.WriteString("\nIf no behavior log is present, say so and return allow at low confidence — absence of captured behavior is not evidence of malice (the payload may be dormant or gated; the source reviewer will judge that).\n\nEvidence:\n")
	b.Write(evidenceJSON(map[string]any{
		"artifact":       in.Artifact,
		"static_signals": in.StaticSignals,
		"behavior_log":   rawOrNil(in.BehaviorLog),
	}))
	return b.String()
}

// sourcePrompt asks a reviewer to judge ONLY the package source — what the code says
// it will do — deliberately blind to runtime (the other reviewer).
func sourcePrompt(in Input) string {
	var b strings.Builder
	b.WriteString("You are the SOURCE reviewer on a supply-chain malware triage panel. Judge ONLY the package source: what the code says it will do — install hooks, obfuscation, credential/network access, dangerous commands. Do NOT infer from runtime behavior; a separate reviewer covers that.\n\n")
	b.WriteString(decisionPolicy())
	b.WriteString("\nEvidence:\n")
	b.Write(evidenceJSON(map[string]any{
		"artifact":        in.Artifact,
		"static_signals":  in.StaticSignals,
		"diff":            in.Diff,
		"source_excerpts": in.SourceExcerpts,
	}))
	return b.String()
}

// combinerPrompt hands both reviewers' judgments to a third call for synthesis.
func combinerPrompt(in Input, behavior Output, bErr error, source Output, sErr error) string {
	var b strings.Builder
	b.WriteString("You are the COMBINER on a supply-chain malware triage panel. Two reviewers examined this package independently — one the runtime behavior, one the source. Synthesize their findings into one final verdict and a concise readout. A concrete malicious finding from EITHER reviewer weighs heavily: a package can be clean at runtime yet malicious in source (a dormant or gated payload), or benign in source yet caught misbehaving at runtime. Do not average the verdicts — reason about why they agree or differ.\n\n")
	b.WriteString(decisionPolicy())
	b.WriteString("\nReviewer findings:\n")
	b.WriteString(reviewerBlock("BEHAVIOR (runtime)", behavior, bErr))
	b.WriteString(reviewerBlock("SOURCE (code)", source, sErr))
	b.WriteString("\nArtifact:\n")
	b.Write(evidenceJSON(in.Artifact))
	return b.String()
}

func reviewerBlock(name string, o Output, err error) string {
	if err != nil {
		return fmt.Sprintf("- %s: REVIEW UNAVAILABLE (%v)\n", name, err)
	}
	return fmt.Sprintf("- %s: verdict=%s confidence=%.2f\n    rationale: %s\n    signals: %s\n",
		name, o.Decision, o.Confidence, o.Rationale, strings.Join(o.Signals, "; "))
}

func evidenceJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

func rawOrNil(b []byte) any {
	if b == nil {
		return nil
	}
	return json.RawMessage(b)
}
