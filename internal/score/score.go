// Package score composes the offline signals — static rules over the package
// source and behavioral rules over a detonation trace — into a verdict, using
// the same engine as the live gate. It is the shared core of the dscore CLI and
// the synthetic-technique corpus, so both exercise identical logic.
package score

import (
	"context"

	"github.com/joncooper/detonator/internal/analyze/behavior"
	"github.com/joncooper/detonator/internal/analyze/static"
	"github.com/joncooper/detonator/internal/artifact"
	"github.com/joncooper/detonator/internal/cache"
	"github.com/joncooper/detonator/internal/engine"
	"github.com/joncooper/detonator/internal/triage"
	"github.com/joncooper/detonator/internal/verdict"
)

// Input is the evidence for one scoring. Either or both of Tarball and Trace may
// be present; the package identity is always known.
type Input struct {
	Artifact verdict.Artifact
	Tarball  []byte // package source; nil to skip static rules
	Trace    []byte // detonation behavior log JSON; nil to skip behavioral rules
}

// Score runs the static and behavioral rules present for the input and returns
// the composed verdict under the given policy.
func Score(in Input, pol engine.Policy) verdict.Verdict {
	v, _ := analyze(in)
	return engine.Decide(v.art, v.signals, pol, "score")
}

// ScoreTriage is Score plus an LLM adjudication stage: the model sees the
// deterministic signals, bounded source excerpts, and the behavior log, and its
// judgment is composed alongside the rules (a rules/LLM disagreement on whether to
// clear the package is itself a signal). Used by the offline eval to measure
// rules+LLM on the corpus. The engine, not the model, makes the final call.
func ScoreTriage(ctx context.Context, in Input, pol engine.Policy, model triage.Model) verdict.Verdict {
	v, u := analyze(in)
	signals := v.signals
	if model != nil {
		signals = append(signals, triageStep(ctx, model, v.art, signals, u, in.Trace, pol)...)
	}
	return engine.Decide(v.art, signals, pol, "score+triage")
}

type analyzed struct {
	art     verdict.Artifact
	signals []verdict.Signal
}

// analyze runs the deterministic rules and returns the signals plus the unpacked
// source (nil if no tarball), so the triage stage can reuse the same unpacking.
func analyze(in Input) (analyzed, *artifact.Unpacked) {
	art := in.Artifact
	var signals []verdict.Signal
	var u *artifact.Unpacked
	if in.Trace != nil {
		if tr, err := behavior.ParseTrace(in.Trace); err == nil {
			signals = append(signals, behavior.Analyze(art.Ecosystem, tr)...)
		}
	}
	if in.Tarball != nil {
		art.Digest = cache.Digest(in.Tarball)
		if uu, err := artifact.UnpackAuto(art.Ecosystem, in.Tarball); err == nil {
			u = uu
			signals = append(signals, static.Analyze(art, u)...)
		}
	}
	return analyzed{art: art, signals: signals}, u
}

// triageStep runs the model over the evidence (deterministic signals + bounded
// source excerpts + the behavior log) and returns its judgment as signals, plus a
// disagreement signal when the model and the rules diverge on clearing the package.
func triageStep(ctx context.Context, model triage.Model, art verdict.Artifact, detSignals []verdict.Signal, u *artifact.Unpacked, trace []byte, pol engine.Policy) []verdict.Signal {
	out, err := model.Classify(ctx, triage.Input{
		Artifact:       art,
		StaticSignals:  detSignals,
		SourceExcerpts: triage.SelectExcerpts(u),
		BehaviorLog:    trace,
	})
	if err != nil {
		return []verdict.Signal{{
			Stage: "triage", Rule: "triage-unavailable", Severity: verdict.SevInfo,
			Description: "LLM triage unavailable", Evidence: err.Error(),
		}}
	}
	sigs := []verdict.Signal{out.ToSignal(model.Name())}
	rulesDecision := engine.Decide(art, detSignals, pol, "rules-only").Decision
	if clears(rulesDecision) != clears(out.Decision) {
		sigs = append(sigs, verdict.Signal{
			Stage: "triage", Rule: "rules-llm-disagreement", Severity: verdict.SevMedium,
			Description: "deterministic rules and LLM triage disagree on clearing this package",
			Evidence:    "rules=" + string(rulesDecision) + " " + model.Name() + "=" + string(out.Decision),
		})
	}
	return sigs
}

func clears(d verdict.Decision) bool { return d == verdict.Allow }
