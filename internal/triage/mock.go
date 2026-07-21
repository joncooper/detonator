package triage

import (
	"bytes"
	"context"
	"fmt"

	"github.com/joncooper/detonator/internal/verdict"
)

// MockModel is a deterministic stand-in for a real LLM. It lets the triage stage
// and the rules+LLM blend be developed and tested without any network call or
// source ever leaving the machine. It is not a substitute for a real model.
type MockModel struct{}

// Name identifies the model.
func (MockModel) Name() string { return "mock" }

// Classify applies a transparent heuristic: escalate on high/critical static
// signals or on sensitive markers in the behavior log, otherwise allow.
func (MockModel) Classify(_ context.Context, in Input) (Output, error) {
	var worst verdict.Severity = verdict.SevInfo
	rank := map[verdict.Severity]int{
		verdict.SevInfo: 0, verdict.SevLow: 1, verdict.SevMedium: 2, verdict.SevHigh: 3, verdict.SevCritical: 4,
	}
	var reasons []string
	for _, s := range in.StaticSignals {
		if rank[s.Severity] > rank[worst] {
			worst = s.Severity
		}
		if rank[s.Severity] >= rank[verdict.SevHigh] {
			reasons = append(reasons, s.Description)
		}
	}

	// Behavior-log markers (Phase 3 input). Cheap substring checks; a real model
	// reasons over the full log.
	for _, marker := range [][]byte{[]byte("/etc/passwd"), []byte("/etc/shadow"), []byte("reverse"), []byte("exfil")} {
		if in.BehaviorLog != nil && bytes.Contains(in.BehaviorLog, marker) {
			if rank[verdict.SevHigh] > rank[worst] {
				worst = verdict.SevHigh
			}
			reasons = append(reasons, "behavior log contains "+string(marker))
		}
	}

	out := Output{Signals: reasons}
	switch worst {
	case verdict.SevCritical:
		out.Decision, out.Confidence = verdict.Block, 0.9
	case verdict.SevHigh:
		out.Decision, out.Confidence = verdict.Quarantine, 0.7
	default:
		out.Decision, out.Confidence = verdict.Allow, 0.6
	}
	out.Rationale = fmt.Sprintf("mock heuristic over %d static signal(s); worst severity %s",
		len(in.StaticSignals), worst)
	return out, nil
}

var _ Model = MockModel{}
