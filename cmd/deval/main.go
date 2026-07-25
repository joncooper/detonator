// Command deval is the manifest-driven evaluation harness: one runner for
// recall, false-positive rate, threshold sweeps, and per-rule ablation, so
// successive evaluations are comparable instead of each being a bespoke script.
//
// It analyzes every sample ONCE (unpack + rules, the expensive part) and caches
// the signals, then replays many policies over that cache with engine.Decide
// (cheap). A full 32-rule ablation therefore costs one analysis pass, not 32.
//
// Manifest is TSV, '-' for an absent path:
//
//	ecosystem<TAB>name<TAB>label<TAB>tarball_path<TAB>trace_path
//
// label is "malicious" or "benign". Malicious samples measure recall; benign
// samples measure the false-positive rate that recall must be traded against.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/joncooper/detonator/internal/engine"
	"github.com/joncooper/detonator/internal/score"
	"github.com/joncooper/detonator/internal/verdict"
)

type sample struct {
	eco, name, label string
	tarball, trace   string
}

type scored struct {
	sample
	art     verdict.Artifact
	signals []verdict.Signal
	err     string
}

// tally is the outcome of one policy over the whole corpus.
type tally struct {
	malicious, caught int // recall numerator/denominator
	benign, flagged   int // FP numerator/denominator
	benignBlocked     int // hard blocks on benign — the expensive failure
	errs              int
}

func (t tally) recall() float64 {
	if t.malicious == 0 {
		return 0
	}
	return float64(t.caught) / float64(t.malicious) * 100
}

func (t tally) fpRate() float64 {
	if t.benign == 0 {
		return 0
	}
	return float64(t.flagged) / float64(t.benign) * 100
}

func main() {
	manifest := flag.String("manifest", "", "TSV: eco<TAB>name<TAB>label<TAB>tarball<TAB>trace ('-' if absent)")
	mode := flag.String("mode", "report", "report | sweep | ablate")
	workers := flag.Int("workers", 8, "parallel analysis workers")
	jsonOut := flag.Bool("json", false, "emit JSON instead of a table")
	flag.Parse()

	if *manifest == "" {
		fmt.Fprintln(os.Stderr, "deval: -manifest required")
		os.Exit(2)
	}
	samples, err := readManifest(*manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deval: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "deval: analyzing %d samples (%d workers)…\n", len(samples), *workers)
	all := analyzeAll(samples, *workers)

	// Analysis is the expensive pass and the policy replays are nearly free, so
	// "all" runs every view from the single cache rather than paying for three
	// separate processes.
	switch *mode {
	case "report":
		report(all, engine.DefaultPolicy(), *jsonOut)
	case "sweep":
		sweep(all)
	case "ablate":
		ablate(all)
	case "promote":
		promote(all)
	case "all":
		report(all, engine.DefaultPolicy(), false)
		fmt.Println("\n=== threshold sweep ===")
		sweep(all)
		fmt.Println("\n=== per-rule ablation ===")
		ablate(all)
		fmt.Println("\n=== promotion candidates ===")
		promote(all)
	default:
		fmt.Fprintf(os.Stderr, "deval: unknown -mode %q\n", *mode)
		os.Exit(2)
	}
}

func readManifest(path string) ([]sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []sample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) < 3 {
			continue
		}
		s := sample{eco: p[0], name: p[1], label: p[2], tarball: "-", trace: "-"}
		if len(p) > 3 {
			s.tarball = p[3]
		}
		if len(p) > 4 {
			s.trace = p[4]
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// analyzeAll runs the rules over every sample once, in parallel.
func analyzeAll(samples []sample, workers int) []scored {
	out := make([]scored, len(samples))
	var wg sync.WaitGroup
	ch := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				out[i] = analyzeOne(samples[i])
			}
		}()
	}
	for i := range samples {
		ch <- i
	}
	close(ch)
	wg.Wait()
	return out
}

func analyzeOne(s sample) scored {
	in := score.Input{Artifact: verdict.Artifact{
		Ecosystem: verdict.Ecosystem(s.eco), Name: s.name,
	}}
	if s.tarball != "-" && s.tarball != "" {
		b, err := os.ReadFile(s.tarball)
		if err != nil {
			return scored{sample: s, err: "tarball: " + err.Error()}
		}
		in.Tarball = b
	}
	if s.trace != "-" && s.trace != "" {
		b, err := os.ReadFile(s.trace)
		if err != nil {
			return scored{sample: s, err: "trace: " + err.Error()}
		}
		in.Trace = b
	}
	if in.Tarball == nil && in.Trace == nil {
		return scored{sample: s, err: "no evidence"}
	}
	art, sigs := score.Signals(in)
	return scored{sample: s, art: art, signals: sigs}
}

// apply replays one policy over the cached signals.
func apply(all []scored, pol engine.Policy) tally {
	var t tally
	for _, s := range all {
		if s.err != "" {
			t.errs++
			continue
		}
		d := engine.Decide(s.art, s.signals, pol, "deval").Decision
		flagged := d == verdict.Block || d == verdict.Quarantine
		if s.label == "malicious" {
			t.malicious++
			if flagged {
				t.caught++
			}
		} else {
			t.benign++
			if flagged {
				t.flagged++
			}
			if d == verdict.Block {
				t.benignBlocked++
			}
		}
	}
	return t
}

func report(all []scored, pol engine.Policy, asJSON bool) {
	t := apply(all, pol)
	// per-rule attribution: how often each rule fires, split by label
	type rc struct{ mal, ben int }
	rules := map[string]*rc{}
	for _, s := range all {
		seen := map[string]bool{}
		for _, sig := range s.signals {
			if seen[sig.Rule] {
				continue
			}
			seen[sig.Rule] = true
			if rules[sig.Rule] == nil {
				rules[sig.Rule] = &rc{}
			}
			if s.label == "malicious" {
				rules[sig.Rule].mal++
			} else {
				rules[sig.Rule].ben++
			}
		}
	}
	if asJSON {
		m := map[string]any{
			"malicious": t.malicious, "caught": t.caught, "recall_pct": t.recall(),
			"benign": t.benign, "flagged": t.flagged, "fp_pct": t.fpRate(),
			"benign_blocked": t.benignBlocked, "errors": t.errs,
		}
		b, _ := json.MarshalIndent(m, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("=== deval report ===\n")
	fmt.Printf("recall : %d/%d = %.1f%%\n", t.caught, t.malicious, t.recall())
	fmt.Printf("FP     : %d/%d = %.2f%% benign flagged (%d hard-blocked)\n",
		t.flagged, t.benign, t.fpRate(), t.benignBlocked)
	if t.errs > 0 {
		fmt.Printf("errors : %d\n", t.errs)
	}
	names := make([]string, 0, len(rules))
	for r := range rules {
		names = append(names, r)
	}
	sort.Slice(names, func(i, j int) bool { return rules[names[i]].mal > rules[names[j]].mal })
	fmt.Printf("\n%-34s %8s %8s\n", "rule", "malware", "benign")
	for _, r := range names {
		fmt.Printf("%-34s %8d %8d\n", r, rules[r].mal, rules[r].ben)
	}
	missAnalysis(all, pol)
}

// promote measures what re-grading each sub-threshold rule would cost and buy.
// A rule's severity is a judgement about how much evidence it carries; the miss
// analysis says ~half the misses DO emit a sub-threshold signal, so the question
// is which of those judgements is miscalibrated. Both High (fires alone) and
// Medium (needs corroboration under the medium quorum) are measured, because the
// blanket promotion and the corroborated one have very different FP profiles.
func promote(all []scored) {
	base := apply(all, engine.DefaultPolicy())
	// candidates: rules that appear on missed malware below the decision threshold
	cand := map[string]int{}
	for _, s := range all {
		if s.err != "" || s.label != "malicious" {
			continue
		}
		if engine.Decide(s.art, s.signals, engine.DefaultPolicy(), "deval").Decision != verdict.Allow {
			continue
		}
		for _, sig := range s.signals {
			if sig.Severity != verdict.SevHigh && sig.Severity != verdict.SevCritical {
				cand[sig.Rule]++
			}
		}
	}
	names := make([]string, 0, len(cand))
	for r := range cand {
		names = append(names, r)
	}
	sort.Slice(names, func(i, j int) bool { return cand[names[i]] > cand[names[j]] })

	fmt.Printf("baseline: recall %.1f%%  FP %.2f%%\n", base.recall(), base.fpRate())
	fmt.Printf("%-30s %-10s %10s %10s %10s\n", "rule -> severity", "onMissed", "recall%", "benignFP%", "blocked")
	for _, r := range names {
		for _, sev := range []verdict.Severity{verdict.SevMedium, verdict.SevHigh} {
			t := apply(all, engine.Policy{SeverityOverride: map[string]verdict.Severity{r: sev}})
			fmt.Printf("%-30s %-10d %9.1f%% %9.2f%% %10d\n",
				r+" -> "+string(sev), cand[r], t.recall(), t.fpRate(), t.benignBlocked)
		}
	}
}

// missAnalysis asks why the missed malware was missed: did it produce sub-threshold
// signals (so a PROMOTION could catch it) or nothing at all (so only a NEW RULE can)?
// This is the difference between an operating point that is threshold-limited and one
// that is coverage-limited, and it decides where effort should go.
func missAnalysis(all []scored, pol engine.Policy) {
	silent, subThreshold := 0, 0
	subRules := map[string]int{}
	for _, s := range all {
		if s.err != "" || s.label != "malicious" {
			continue
		}
		if d := engine.Decide(s.art, s.signals, pol, "deval").Decision; d != verdict.Allow {
			continue
		}
		if len(s.signals) == 0 {
			silent++
			continue
		}
		subThreshold++
		seen := map[string]bool{}
		for _, sig := range s.signals {
			if !seen[sig.Rule] {
				seen[sig.Rule] = true
				subRules[sig.Rule]++
			}
		}
	}
	total := silent + subThreshold
	if total == 0 {
		return
	}
	fmt.Printf("\n--- why the %d misses were missed ---\n", total)
	fmt.Printf("no signal at all (needs a NEW RULE)          : %d (%.0f%%)\n",
		silent, float64(silent)/float64(total)*100)
	fmt.Printf("sub-threshold signal (a PROMOTION may catch) : %d (%.0f%%)\n",
		subThreshold, float64(subThreshold)/float64(total)*100)
	type kv struct {
		r string
		n int
	}
	var ks []kv
	for r, n := range subRules {
		ks = append(ks, kv{r, n})
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].n > ks[j].n })
	for i, k := range ks {
		if i >= 8 {
			break
		}
		fmt.Printf("   %-32s %d\n", k.r, k.n)
	}
}

// sweep walks the quorum grid and prints the recall/FP trade-off curve.
func sweep(all []scored) {
	fmt.Printf("%-10s %-8s %-8s %10s %10s %8s\n", "critQ", "highQ", "medQ", "recall%", "benignFP%", "blocked")
	// medQ=1 is included deliberately: with FP headroom under budget, the question
	// is whether a LOWER bar buys recall, not only whether a higher one saves FP.
	for _, cq := range []int{1, 2} {
		for _, hq := range []int{1, 2, 3} {
			for _, mq := range []int{1, 2, 3, 4} {
				pol := engine.Policy{CriticalQuorum: cq, HighQuorum: hq, MediumQuorum: mq}
				t := apply(all, pol)
				fmt.Printf("%-10d %-8d %-8d %9.1f%% %9.2f%% %8d\n",
					cq, hq, mq, t.recall(), t.fpRate(), t.benignBlocked)
			}
		}
	}
}

// ablate disables one rule at a time and reports each rule's marginal
// contribution: recall it uniquely provides, and benign FP it uniquely causes.
func ablate(all []scored) {
	base := apply(all, engine.DefaultPolicy())
	fmt.Printf("baseline: recall %.1f%% (%d/%d)  FP %.2f%% (%d/%d)\n\n",
		base.recall(), base.caught, base.malicious, base.fpRate(), base.flagged, base.benign)

	seen := map[string]bool{}
	for _, s := range all {
		for _, sig := range s.signals {
			seen[sig.Rule] = true
		}
	}
	names := make([]string, 0, len(seen))
	for r := range seen {
		names = append(names, r)
	}
	sort.Strings(names)

	type row struct {
		rule            string
		dRecall, dFP    float64
		lostCatch, lost int
	}
	var rows []row
	for _, r := range names {
		t := apply(all, engine.Policy{DisabledRules: map[string]bool{r: true}})
		rows = append(rows, row{
			rule:      r,
			dRecall:   base.recall() - t.recall(),
			dFP:       base.fpRate() - t.fpRate(),
			lostCatch: base.caught - t.caught,
			lost:      base.flagged - t.flagged,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].dRecall > rows[j].dRecall })
	fmt.Printf("%-34s %12s %10s %12s %10s\n", "rule (disabled)", "Δrecall", "catches", "ΔbenignFP", "benignFP")
	for _, r := range rows {
		fmt.Printf("%-34s %11.2f%% %10d %11.2f%% %10d\n", r.rule, r.dRecall, r.lostCatch, r.dFP, r.lost)
	}
	fmt.Println("\nΔrecall 0 with ΔbenignFP > 0 = rule costs precision and buys no recall on this corpus.")
}
