package triage

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/joncooper/detonator/internal/verdict"
)

// TestPanelDormantPayload is the case the panel exists for: the runtime behavior is
// clean (a dormant/gated payload did nothing when detonated), but the source shows an
// obfuscated loader. A single behavior review would allow it; the source reviewer
// catches it and the combiner escalates.
func TestPanelDormantPayload(t *testing.T) {
	p := NewPanel("s.json", "gpt-5.6-sol", "medium")
	var roles []string
	var combinerSaw string
	p.codex.run = func(_ context.Context, _ string, _ []string, stdin string) ([]byte, error) {
		switch {
		case strings.Contains(stdin, "BEHAVIOR reviewer"):
			roles = append(roles, "behavior")
			return []byte(`{"verdict":"allow","confidence":0.6,"rationale":"no observable runtime behavior","signals":[]}`), nil
		case strings.Contains(stdin, "SOURCE reviewer"):
			roles = append(roles, "source")
			return []byte(`{"verdict":"block","confidence":0.9,"rationale":"obfuscated loader in entry module","signals":["_0x obfuscation"]}`), nil
		case strings.Contains(stdin, "COMBINER"):
			roles = append(roles, "combiner")
			combinerSaw = stdin
			return []byte(`{"verdict":"block","confidence":0.85,"rationale":"source shows an obfuscated loader; runtime was dormant","signals":["obfuscation; dormant payload"]}`), nil
		}
		return nil, fmt.Errorf("unexpected panel stage")
	}
	var raws []RawRecord
	p.SetRawSink(func(r RawRecord) { raws = append(raws, r) })

	out, err := p.Classify(context.Background(), Input{
		Artifact:       verdict.Artifact{Ecosystem: verdict.NPM, Name: "lodash-twist"},
		SourceExcerpts: map[string]string{"index.js": "var _0x1234=..."},
		BehaviorLog:    []byte(`{"Analysis":{"import":{"Status":"completed"}}}`),
	})
	if err != nil {
		t.Fatalf("panel Classify: %v", err)
	}
	if out.Decision != verdict.Block {
		t.Fatalf("panel verdict = %s, want block (source caught the dormant payload)", out.Decision)
	}
	if got := strings.Join(roles, ","); got != "behavior,source,combiner" {
		t.Fatalf("stage order = %q, want behavior,source,combiner", got)
	}
	if len(raws) != 3 {
		t.Fatalf("raw records = %d, want 3 (each stage captured)", len(raws))
	}
	// The combiner must actually see both reviewers' verdicts.
	if !strings.Contains(combinerSaw, "verdict=allow") || !strings.Contains(combinerSaw, "verdict=block") {
		t.Fatalf("combiner prompt did not carry both reviewer verdicts")
	}
	// Raw records are role-labeled for offline analysis.
	roleSet := map[string]bool{}
	for _, r := range raws {
		roleSet[r.Model] = true
	}
	for _, want := range []string{"codex/gpt-5.6-sol/behavior-review", "codex/gpt-5.6-sol/source-review", "codex/gpt-5.6-sol/combiner"} {
		if !roleSet[want] {
			t.Errorf("missing raw record for %q; got %v", want, roleSet)
		}
	}
}

// TestPanelSurvivesReviewerError: a reviewer failure doesn't abort the panel — the
// combiner is told the review is unavailable and still produces a verdict.
func TestPanelSurvivesReviewerError(t *testing.T) {
	p := NewPanel("s.json", "gpt-5.6-sol", "medium")
	p.codex.run = func(_ context.Context, _ string, _ []string, stdin string) ([]byte, error) {
		switch {
		case strings.Contains(stdin, "BEHAVIOR reviewer"):
			return nil, fmt.Errorf("codex timeout")
		case strings.Contains(stdin, "SOURCE reviewer"):
			return []byte(`{"verdict":"allow","confidence":0.7,"rationale":"benign","signals":[]}`), nil
		case strings.Contains(stdin, "COMBINER"):
			if !strings.Contains(stdin, "REVIEW UNAVAILABLE") {
				return nil, fmt.Errorf("combiner not told of reviewer failure")
			}
			return []byte(`{"verdict":"allow","confidence":0.65,"rationale":"source benign; behavior review unavailable","signals":[]}`), nil
		}
		return nil, fmt.Errorf("unexpected stage")
	}
	out, err := p.Classify(context.Background(), Input{Artifact: verdict.Artifact{Ecosystem: verdict.NPM, Name: "ok"}})
	if err != nil {
		t.Fatalf("panel should survive a reviewer error: %v", err)
	}
	if out.Decision != verdict.Allow {
		t.Fatalf("verdict = %s, want allow", out.Decision)
	}
}
