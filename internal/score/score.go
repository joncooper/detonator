// Package score composes the offline signals — static rules over the package
// source and behavioral rules over a detonation trace — into a verdict, using
// the same engine as the live gate. It is the shared core of the dscore CLI and
// the synthetic-technique corpus, so both exercise identical logic.
package score

import (
	"github.com/joncooper/detonator/internal/analyze/behavior"
	"github.com/joncooper/detonator/internal/analyze/static"
	"github.com/joncooper/detonator/internal/artifact"
	"github.com/joncooper/detonator/internal/cache"
	"github.com/joncooper/detonator/internal/engine"
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
	art := in.Artifact
	var signals []verdict.Signal

	if in.Trace != nil {
		if tr, err := behavior.ParseTrace(in.Trace); err == nil {
			signals = append(signals, behavior.Analyze(art.Ecosystem, tr)...)
		}
	}
	if in.Tarball != nil {
		art.Digest = cache.Digest(in.Tarball)
		if u, err := artifact.UnpackAuto(art.Ecosystem, in.Tarball); err == nil {
			signals = append(signals, static.Analyze(art, u)...)
		}
	}
	return engine.Decide(art, signals, pol, "score")
}
