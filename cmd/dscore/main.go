// Command dscore scores a detonation behavior log (and optionally the package
// source) into an admission verdict, using the same behavioral + static rules
// and verdict engine as the live gate. It is the offline evaluation harness for
// the detonation corpus.
//
// It is deliberately BLIND: it receives only the trace, the source, and the
// package identity — never any ground-truth label — so its verdicts reflect what
// Detonator would decide for an unknown package, including a 0-day.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joncooper/detonator/internal/engine"
	"github.com/joncooper/detonator/internal/score"
	"github.com/joncooper/detonator/internal/triage"
	"github.com/joncooper/detonator/internal/verdict"
)

func main() {
	tracePath := flag.String("trace", "", "path to the detonation behavior log JSON (enables behavioral rules)")
	tarball := flag.String("tarball", "", "path to the package artifact (enables static rules)")
	eco := flag.String("ecosystem", "npm", "ecosystem: npm or pypi")
	name := flag.String("name", "", "package name")
	version := flag.String("version", "", "package version")
	triageMode := flag.String("triage", "", "LLM triage stage: '' (off), 'mock' (local, deterministic), or 'codex' (SENDS SOURCE TO OPENAI)")
	triageModel := flag.String("triage-model", "gpt-5.6-sol-medium", "codex model name (with -triage codex)")
	triageSchema := flag.String("triage-schema", "phase0/verdict-schema.json", "path to the triage output schema (with -triage codex)")
	flag.Parse()

	// At least one evidence source is required; either may stand alone. Static-only
	// (-tarball, no -trace) is the offline precision-gate path; trace-only is the
	// detonation path.
	if *tracePath == "" && *tarball == "" {
		fmt.Fprintln(os.Stderr, "dscore: need -trace and/or -tarball")
		os.Exit(2)
	}

	in := score.Input{
		Artifact: verdict.Artifact{Ecosystem: verdict.Ecosystem(*eco), Name: *name, Version: *version},
	}
	if *tracePath != "" {
		data, err := os.ReadFile(*tracePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dscore: read trace: %v\n", err)
			os.Exit(1)
		}
		in.Trace = data
	}
	if *tarball != "" {
		data, err := os.ReadFile(*tarball)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dscore: read tarball: %v\n", err)
			os.Exit(1)
		}
		in.Tarball = data
	}

	var model triage.Model
	switch *triageMode {
	case "", "off":
	case "mock":
		model = triage.MockModel{}
	case "codex":
		model = triage.NewCodex(*triageSchema, *triageModel)
	default:
		fmt.Fprintf(os.Stderr, "dscore: unknown -triage %q (want mock|codex)\n", *triageMode)
		os.Exit(2)
	}

	var v verdict.Verdict
	if model != nil {
		v = score.ScoreTriage(context.Background(), in, engine.DefaultPolicy(), model)
	} else {
		v = score.Score(in, engine.DefaultPolicy())
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))

	// Exit code encodes the decision for scripting: 0 allow, 3 quarantine, 4 block.
	switch v.Decision {
	case verdict.Block:
		os.Exit(4)
	case verdict.Quarantine:
		os.Exit(3)
	}
}
