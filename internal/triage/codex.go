package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/joncooper/detonator/internal/verdict"
)

// CodexModel runs OpenAI Codex headless (`codex exec`) to classify a package.
// Per build-plan §7 the default tier is GPT-5.6 Sol Medium, run read-only and
// unattended, with an output schema so the reply is machine-readable.
//
// IMPORTANT: Classify sends package source and behavior data to a third party.
// The pipeline must only invoke this model when policy allows source egress; the
// mock or a self-hosted model covers sensitive contexts.
type CodexModel struct {
	Bin        string // codex binary, default "codex"
	SchemaPath string // path to phase0/verdict-schema.json
	ModelName  string // codex model id, e.g. "gpt-5.6-sol"
	Effort     string // reasoning effort: "minimal"|"low"|"medium"|"high"|"xhigh" ("" = codex config default)
	// RawSink, if set, receives the complete unparsed interaction for every
	// Classify call — the exact prompt sent and the exact bytes codex returned —
	// so an eval run can be refined offline without re-invoking the model.
	RawSink func(RawRecord)
	// run executes the command and returns stdout. Injectable for tests so the
	// prompt/args are exercised without invoking codex or making a network call.
	run runner
}

// RawRecord is the complete, unparsed triage interaction for one package: the
// prompt sent to the model and the raw bytes it returned, plus the parsed result.
// Captured so an eval can be re-analyzed without re-running the (slow, paid) model.
type RawRecord struct {
	Model     string `json:"model"`
	Package   string `json:"package"`
	Ecosystem string `json:"ecosystem"`
	Prompt    string `json:"prompt"`
	RawStdout string `json:"raw_stdout"`
	Output    Output `json:"output"`
	Err       string `json:"err,omitempty"`
}

type runner func(ctx context.Context, bin string, args []string, stdin string) ([]byte, error)

// NewCodex builds a Codex-backed model. schemaPath points at the verdict schema.
// effort is the reasoning effort (build-plan §7 default: "medium" for GPT-5.6 Sol);
// "" leaves codex's configured default.
func NewCodex(schemaPath, modelName, effort string) *CodexModel {
	return &CodexModel{
		Bin:        "codex",
		SchemaPath: schemaPath,
		ModelName:  modelName,
		Effort:     effort,
		run:        execCodex,
	}
}

// Name identifies the model for the audit trail.
func (m *CodexModel) Name() string {
	if m.ModelName != "" {
		return "codex/" + m.ModelName
	}
	return "codex"
}

// Classify builds the triage prompt from the evidence, runs codex with the
// output schema, and parses the structured verdict.
func (m *CodexModel) Classify(ctx context.Context, in Input) (Output, error) {
	prompt, err := buildPrompt(in)
	if err != nil {
		return Output{}, err
	}
	args := m.args()
	raw, runErr := m.run(ctx, m.Bin, args, prompt)
	out, parseErr := parseOutput(raw)
	if m.RawSink != nil {
		rec := RawRecord{
			Model: m.Name(), Package: in.Artifact.Name, Ecosystem: string(in.Artifact.Ecosystem),
			Prompt: prompt, RawStdout: string(raw), Output: out,
		}
		if runErr != nil {
			rec.Err = runErr.Error()
		} else if parseErr != nil {
			rec.Err = parseErr.Error()
		}
		m.RawSink(rec)
	}
	if runErr != nil {
		return Output{}, fmt.Errorf("codex: %w", runErr)
	}
	return out, parseErr
}

// args returns the codex CLI arguments: headless exec, read-only sandbox,
// machine-readable schema, chosen model and reasoning effort. `codex exec` is
// non-interactive so it never prompts for approval; read-only sandbox bounds any
// tool use. --skip-git-repo-check lets it run from any working directory. The
// trailing "-" tells codex to read the prompt from stdin, so large evidence never
// hits the argv length limit.
func (m *CodexModel) args() []string {
	args := []string{
		"exec",
		"--output-schema", m.SchemaPath,
		"--sandbox", "read-only",
		"--skip-git-repo-check",
	}
	if m.ModelName != "" {
		args = append(args, "--model", m.ModelName)
	}
	if m.Effort != "" {
		args = append(args, "-c", "model_reasoning_effort=\""+m.Effort+"\"")
	}
	return append(args, "-")
}

// buildPrompt assembles the evidence into a single instruction. The model must
// judge only from what it is given.
func buildPrompt(in Input) (string, error) {
	evidence := map[string]any{
		"artifact":        in.Artifact,
		"static_signals":  in.StaticSignals,
		"diff":            in.Diff,
		"source_excerpts": in.SourceExcerpts,
	}
	if in.BehaviorLog != nil {
		evidence["behavior_log"] = json.RawMessage(in.BehaviorLog)
	}
	blob, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("You are a software supply-chain malware triage system. Judge ONLY from the evidence below and return the schema.\n\n")
	b.WriteString("Decision policy:\n")
	b.WriteString("- allow: the evidence shows no indicator of malicious behavior. A small, simple, or unremarkable package — no suspicious install hooks, no obfuscation, no credential/network access, no dangerous commands — is ALLOW. Absence of exhaustive proof of benignity is NOT a reason to escalate.\n")
	b.WriteString("- quarantine: a concrete suspicious indicator is present but not conclusive on its own (obfuscated code, an install hook doing something unusual, credential/dotfile reads, an unexpected network endpoint), OR the deterministic rules and the observed behavior clearly disagree.\n")
	b.WriteString("- block: the evidence shows a clear malicious capability — install-time remote code execution, credential/environment exfiltration, a reverse shell, a destructive command, or a hidden C2.\n\n")
	b.WriteString("Bias toward precision: a false block or a false quarantine stalls builds and erodes trust. Do NOT escalate merely because evidence is thin or incomplete — escalate only on a positive indicator of malice.\n\nEvidence:\n")
	b.Write([]byte(blob))
	return b.String(), nil
}

// parseOutput extracts the schema-conforming JSON object from codex stdout.
func parseOutput(stdout []byte) (Output, error) {
	obj := extractJSONObject(stdout)
	if obj == nil {
		return Output{}, fmt.Errorf("codex: no JSON object in output")
	}
	var o Output
	if err := json.Unmarshal(obj, &o); err != nil {
		return Output{}, fmt.Errorf("codex: parse output: %w", err)
	}
	if !validDecision(o.Decision) {
		return Output{}, fmt.Errorf("codex: invalid verdict %q", o.Decision)
	}
	return o, nil
}

func validDecision(d verdict.Decision) bool {
	return d == verdict.Allow || d == verdict.Block || d == verdict.Quarantine
}

// extractJSONObject returns the last balanced top-level {...} in b, tolerating any
// log lines codex emits around the final structured message. It tracks string
// literals and escapes so braces inside string values (e.g. a rationale quoting
// `{"name":"r"}`) do not break the match — the naive last-brace approach did.
func extractJSONObject(b []byte) []byte {
	var last []byte
	for i := 0; i < len(b); {
		if b[i] != '{' {
			i++
			continue
		}
		depth, inStr, esc := 0, false, false
		j := i
		for ; j < len(b); j++ {
			c := b[j]
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = !inStr
			case inStr:
			case c == '{':
				depth++
			case c == '}':
				depth--
			}
			if !inStr && !esc && c == '}' && depth == 0 {
				break
			}
		}
		if depth == 0 && j < len(b) {
			last = b[i : j+1]
			i = j + 1
		} else {
			i++
		}
	}
	return last
}

func execCodex(ctx context.Context, bin string, args []string, stdin string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

var _ Model = (*CodexModel)(nil)
