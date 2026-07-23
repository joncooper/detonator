// Package triage is the LLM reasoning stage: given the source, the static
// signals, the version diff, and (from Phase 3) the detonation behavior log, a
// model returns a structured judgment. The Model interface is pluggable so the
// hosted Codex path, a self-hosted open model, or a local mock can be swapped
// without touching the pipeline — the build-plan §7 decision that source needn't
// always travel to a third party.
package triage

import (
	"context"

	"github.com/joncooper/detonator/internal/artifact"
	"github.com/joncooper/detonator/internal/verdict"
)

// Input is the evidence handed to a model. BehaviorLog is nil until detonation
// (Phase 3) exists; the rest is available from the static pipeline.
type Input struct {
	Artifact      verdict.Artifact
	StaticSignals []verdict.Signal
	Diff          *verdict.DiffSummary
	// SourceExcerpts is a bounded map of path -> content for the files most
	// worth reading (install scripts, entry points), not the whole package.
	SourceExcerpts map[string]string
	// BehaviorLog is the raw detonation log JSON, or nil if not detonated.
	BehaviorLog []byte
}

// Output is the model's structured judgment. It mirrors phase0/verdict-schema.json.
type Output struct {
	Decision   verdict.Decision `json:"verdict"`
	Confidence float64          `json:"confidence"`
	Rationale  string           `json:"rationale"`
	Signals    []string         `json:"signals"`
}

// Model classifies a package from its evidence.
type Model interface {
	// Name identifies the backing model, for the verdict's audit trail.
	Name() string
	// Classify returns a structured judgment or an error (unavailable, timeout).
	Classify(ctx context.Context, in Input) (Output, error)
}

// ToSignal renders a model output as a pipeline signal so the engine can weigh
// it alongside deterministic rules. The severity reflects the model's decision;
// the engine, not the model, makes the final call.
func (o Output) ToSignal(modelName string) verdict.Signal {
	sev := verdict.SevInfo
	switch o.Decision {
	case verdict.Block:
		sev = verdict.SevHigh // an LLM "block" quarantines for review, not an auto hard-block
	case verdict.Quarantine:
		sev = verdict.SevMedium
	}
	return verdict.Signal{
		Stage:       "triage",
		Rule:        "llm-" + string(o.Decision),
		Severity:    sev,
		Description: modelName + " triage: " + o.Rationale,
		Evidence:    joinSignals(o.Signals),
	}
}

// SelectExcerpts returns a small, bounded set of the files most worth a model's
// attention — install/build scripts and entry points — never the whole package.
// Shared by the live gate and the offline scorer so both feed the model the same
// evidence.
func SelectExcerpts(u *artifact.Unpacked) map[string]string {
	if u == nil {
		return nil
	}
	const maxFiles, maxBytes = 6, 8 << 10
	interesting := []string{
		"package.json", "setup.py", "setup.cfg", "pyproject.toml",
		"index.js", "main.js", "__init__.py",
	}
	out := map[string]string{}
	for _, name := range interesting {
		if len(out) >= maxFiles {
			break
		}
		if f := u.Lookup(name); f != nil {
			c := f.Content
			if len(c) > maxBytes {
				c = c[:maxBytes]
			}
			out[name] = string(c)
		}
	}
	return out
}

func joinSignals(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}
