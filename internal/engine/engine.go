// Package engine turns a pile of signals into a single admission decision under
// policy. It encodes the build-plan §4 verdict model and its two biases: favor
// precision (a false block stalls a build and burns trust), and treat
// uncertainty as review, not silent allow.
package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/joncooper/detonator/internal/verdict"
)

// Policy tunes how signals map to decisions.
type Policy struct {
	// FailClosed flips the §7 default. Off (the default) means uncertainty
	// quarantines for human review; on means it blocks. Exposed so a
	// high-security org can choose fail-closed.
	FailClosed bool
}

// DefaultPolicy is fail-to-review (build-plan §7 decision 4).
func DefaultPolicy() Policy { return Policy{FailClosed: false} }

// Decide composes signals into a verdict for art.
func Decide(art verdict.Artifact, signals []verdict.Signal, pol Policy, engineName string) verdict.Verdict {
	counts := map[verdict.Severity]int{}
	for _, s := range signals {
		counts[s.Severity]++
	}

	decision := verdict.Allow
	switch {
	case counts[verdict.SevCritical] > 0:
		decision = verdict.Block
	case counts[verdict.SevHigh] > 0:
		decision = verdict.Quarantine
	case counts[verdict.SevMedium] >= 2:
		// A lone medium (a test key, one minified vendor blob) is common in
		// benign packages; two independent mediums is worth a human look.
		decision = verdict.Quarantine
	}

	if pol.FailClosed && decision == verdict.Quarantine {
		decision = verdict.Block
	}

	return verdict.Verdict{
		Artifact:  art,
		Decision:  decision,
		Reason:    reason(decision, signals, counts),
		Signals:   sortSignals(signals),
		DecidedAt: time.Now().UTC(),
		Engine:    engineName,
	}
}

func reason(d verdict.Decision, signals []verdict.Signal, counts map[verdict.Severity]int) string {
	switch d {
	case verdict.Block:
		if top := highestSignal(signals); top != nil {
			return fmt.Sprintf("blocked on %s signal: %s", top.Severity, top.Description)
		}
		return "blocked"
	case verdict.Quarantine:
		return fmt.Sprintf("quarantined for review: %d high, %d medium signal(s)",
			counts[verdict.SevHigh], counts[verdict.SevMedium])
	default:
		n := len(signals)
		if n == 0 {
			return "allowed: no signals"
		}
		return fmt.Sprintf("allowed: %d informational signal(s), none blocking", n)
	}
}

func highestSignal(signals []verdict.Signal) *verdict.Signal {
	sorted := sortSignals(signals)
	if len(sorted) == 0 {
		return nil
	}
	return &sorted[0]
}

var sevRank = map[verdict.Severity]int{
	verdict.SevCritical: 5, verdict.SevHigh: 4, verdict.SevMedium: 3,
	verdict.SevLow: 2, verdict.SevInfo: 1,
}

// sortSignals returns a copy ordered most-severe first, stable within a
// severity by stage then rule, so verdicts are deterministic.
func sortSignals(in []verdict.Signal) []verdict.Signal {
	out := append([]verdict.Signal(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		if sevRank[out[i].Severity] != sevRank[out[j].Severity] {
			return sevRank[out[i].Severity] > sevRank[out[j].Severity]
		}
		if out[i].Stage != out[j].Stage {
			return out[i].Stage < out[j].Stage
		}
		return strings.Compare(out[i].Rule, out[j].Rule) < 0
	})
	return out
}
