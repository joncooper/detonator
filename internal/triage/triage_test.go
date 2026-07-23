package triage

import (
	"context"
	"strings"
	"testing"

	"github.com/joncooper/detonator/internal/verdict"
)

func TestMockModelEscalatesOnCritical(t *testing.T) {
	in := Input{StaticSignals: []verdict.Signal{{Severity: verdict.SevCritical, Description: "install hook danger"}}}
	out, err := MockModel{}.Classify(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Decision != verdict.Block {
		t.Fatalf("want block, got %s", out.Decision)
	}
}

func TestMockModelAllowsClean(t *testing.T) {
	out, _ := MockModel{}.Classify(context.Background(), Input{})
	if out.Decision != verdict.Allow {
		t.Fatalf("want allow, got %s", out.Decision)
	}
}

func TestMockModelReactsToBehaviorLog(t *testing.T) {
	in := Input{BehaviorLog: []byte(`{"files":[{"read":"/etc/passwd"}]}`)}
	out, _ := MockModel{}.Classify(context.Background(), in)
	if out.Decision != verdict.Quarantine {
		t.Fatalf("want quarantine on /etc/passwd read, got %s", out.Decision)
	}
}

func TestCodexArgsAndParsing(t *testing.T) {
	m := NewCodex("phase0/verdict-schema.json", "gpt-5.6-sol", "medium")
	var gotArgs []string
	var gotStdin string
	// Inject a fake runner: no codex process, no network.
	m.run = func(_ context.Context, _ string, args []string, stdin string) ([]byte, error) {
		gotArgs, gotStdin = args, stdin
		return []byte("some log line\nfinal: {\"verdict\":\"quarantine\",\"confidence\":0.8,\"rationale\":\"reads /etc/passwd\",\"signals\":[\"read /etc/passwd\"]}\n"), nil
	}

	out, err := m.Classify(context.Background(), Input{
		Artifact:      verdict.Artifact{Ecosystem: verdict.PyPI, Name: "x", Version: "1.0"},
		StaticSignals: []verdict.Signal{{Severity: verdict.SevHigh, Description: "setup exec"}},
	})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if out.Decision != verdict.Quarantine || out.Confidence != 0.8 {
		t.Fatalf("parsed output wrong: %+v", out)
	}

	joined := strings.Join(gotArgs, " ")
	for _, want := range []string{"exec", "--output-schema phase0/verdict-schema.json", "--sandbox read-only", "--skip-git-repo-check", "--model gpt-5.6-sol", `-c model_reasoning_effort="medium"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("codex args missing %q: %v", want, gotArgs)
		}
	}
	if gotArgs[len(gotArgs)-1] != "-" {
		t.Errorf("expected trailing '-' for stdin prompt, got %v", gotArgs)
	}
	if !strings.Contains(gotStdin, "supply-chain malware triage") {
		t.Errorf("prompt missing instruction: %q", gotStdin)
	}
}

func TestCodexRejectsInvalidVerdict(t *testing.T) {
	m := NewCodex("s.json", "", "")
	m.run = func(_ context.Context, _ string, _ []string, _ string) ([]byte, error) {
		return []byte(`{"verdict":"maybe","confidence":0.5,"rationale":"x","signals":[]}`), nil
	}
	if _, err := m.Classify(context.Background(), Input{}); err == nil {
		t.Fatal("expected error on invalid verdict value")
	}
}
