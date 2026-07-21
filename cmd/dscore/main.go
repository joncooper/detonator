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
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joncooper/detonator/internal/analyze/behavior"
	"github.com/joncooper/detonator/internal/analyze/static"
	"github.com/joncooper/detonator/internal/artifact"
	"github.com/joncooper/detonator/internal/cache"
	"github.com/joncooper/detonator/internal/engine"
	"github.com/joncooper/detonator/internal/verdict"
)

func main() {
	tracePath := flag.String("trace", "", "path to the detonation behavior log JSON (required)")
	tarball := flag.String("tarball", "", "path to the package artifact (optional; enables static rules)")
	eco := flag.String("ecosystem", "npm", "ecosystem: npm or pypi")
	name := flag.String("name", "", "package name")
	version := flag.String("version", "", "package version")
	flag.Parse()

	if *tracePath == "" {
		fmt.Fprintln(os.Stderr, "dscore: -trace is required")
		os.Exit(2)
	}

	traceData, err := os.ReadFile(*tracePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dscore: read trace: %v\n", err)
		os.Exit(1)
	}
	tr, err := behavior.ParseTrace(traceData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dscore: %v\n", err)
		os.Exit(1)
	}

	ecosystem := verdict.Ecosystem(*eco)
	art := verdict.Artifact{Ecosystem: ecosystem, Name: *name, Version: *version}

	var signals []verdict.Signal
	signals = append(signals, behavior.Analyze(ecosystem, tr)...)

	if *tarball != "" {
		data, err := os.ReadFile(*tarball)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dscore: read tarball: %v\n", err)
			os.Exit(1)
		}
		art.Digest = cache.Digest(data)
		if u, err := artifact.UnpackAuto(ecosystem, data); err == nil {
			signals = append(signals, static.Analyze(art, u)...)
		} else {
			fmt.Fprintf(os.Stderr, "dscore: warn: unpack failed: %v\n", err)
		}
	}

	v := engine.Decide(art, signals, engine.DefaultPolicy(), "detonation-score")
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
