package gate

import (
	"context"
	"log/slog"
	"time"

	"github.com/joncooper/detonator/internal/analyze/differ"
	"github.com/joncooper/detonator/internal/analyze/osv"
	"github.com/joncooper/detonator/internal/analyze/static"
	"github.com/joncooper/detonator/internal/artifact"
	"github.com/joncooper/detonator/internal/cache"
	"github.com/joncooper/detonator/internal/engine"
	"github.com/joncooper/detonator/internal/triage"
	"github.com/joncooper/detonator/internal/verdict"
)

// Pipeline is the Phase 2 admission gate: static analysis, OSV known-vuln
// lookup, and a diff against the previous known-good version, composed into a
// verdict by the engine. Detonation (Phase 3) and LLM triage (Phase 4) add more
// signal stages behind this same interface.
type Pipeline struct {
	cache  *cache.Cache
	osv    *osv.Client  // nil disables OSV lookup
	model  triage.Model // nil disables LLM triage
	policy engine.Policy
	log    *slog.Logger
}

// PipelineOptions configures a Pipeline gate.
type PipelineOptions struct {
	Cache  *cache.Cache
	OSV    *osv.Client
	Model  triage.Model
	Policy engine.Policy
	Logger *slog.Logger
}

// NewPipeline builds a Pipeline gate.
func NewPipeline(o PipelineOptions) *Pipeline {
	return &Pipeline{cache: o.Cache, osv: o.OSV, model: o.Model, policy: o.Policy, log: o.Logger}
}

// Admit runs the static-analysis pipeline and returns a verdict.
func (p *Pipeline) Admit(ctx context.Context, art verdict.Artifact, data []byte) (verdict.Verdict, error) {
	var (
		signals []verdict.Signal
		diff    *verdict.DiffSummary
	)

	u, err := artifact.UnpackAuto(art.Ecosystem, data)
	if err != nil {
		// An artifact we can't even unpack is suspicious, but not proof of
		// malice; surface it for review rather than hard-blocking.
		signals = append(signals, verdict.Signal{
			Stage: "static", Rule: "unpack-failed", Severity: verdict.SevMedium,
			Description: "artifact could not be unpacked for inspection",
			Evidence:    err.Error(),
		})
	} else {
		signals = append(signals, static.Analyze(art, u)...)
		if prev, prevVer, ok := p.previousGood(art); ok {
			summary, diffSigs := differ.Diff(art, prevVer, prev, u)
			signals = append(signals, diffSigs...)
			diff = &summary
		}
	}

	if p.osv != nil {
		osvSigs, err := p.osv.Query(ctx, art)
		if err != nil {
			// OSV unreachable: record uncertainty, don't fail the verdict.
			p.log.Warn("osv lookup failed", "artifact", art.Name, "err", err)
			signals = append(signals, verdict.Signal{
				Stage: "osv", Rule: "osv-unavailable", Severity: verdict.SevInfo,
				Description: "OSV lookup unavailable; known-vuln status unknown",
				Evidence:    err.Error(),
			})
		} else {
			signals = append(signals, osvSigs...)
		}
	}

	// LLM triage sees the deterministic signals and renders its own judgment;
	// the engine, not the model, makes the final call. Rules/LLM disagreement is
	// itself a signal (build-plan §4).
	engineName := "static-pipeline"
	if p.model != nil {
		signals = append(signals, p.triageSignals(ctx, art, signals, diff, u)...)
		engineName = "static+triage-pipeline"
	}

	v := engine.Decide(art, signals, p.policy, engineName)
	v.Diff = diff

	p.recordHistory(art, v.Decision)
	return v, nil
}

// triageSignals runs the LLM triage model and returns its judgment as signals,
// plus a disagreement signal when the model and the deterministic rules diverge
// on whether to clear the package.
func (p *Pipeline) triageSignals(ctx context.Context, art verdict.Artifact, detSignals []verdict.Signal, diff *verdict.DiffSummary, u *artifact.Unpacked) []verdict.Signal {
	in := triage.Input{
		Artifact:       art,
		StaticSignals:  detSignals,
		Diff:           diff,
		SourceExcerpts: selectExcerpts(u),
	}
	out, err := p.model.Classify(ctx, in)
	if err != nil {
		p.log.Warn("triage failed", "artifact", art.Name, "err", err)
		return []verdict.Signal{{
			Stage: "triage", Rule: "triage-unavailable", Severity: verdict.SevInfo,
			Description: "LLM triage unavailable", Evidence: err.Error(),
		}}
	}
	sigs := []verdict.Signal{out.ToSignal(p.model.Name())}

	rulesDecision := engine.Decide(art, detSignals, p.policy, "rules-only").Decision
	if clears(rulesDecision) != clears(out.Decision) {
		sigs = append(sigs, verdict.Signal{
			Stage: "triage", Rule: "rules-llm-disagreement", Severity: verdict.SevMedium,
			Description: "deterministic rules and LLM triage disagree on clearing this package",
			Evidence:    "rules=" + string(rulesDecision) + " " + p.model.Name() + "=" + string(out.Decision),
		})
	}
	return sigs
}

// clears reports whether a decision would admit the package.
func clears(d verdict.Decision) bool { return d == verdict.Allow }

// selectExcerpts returns a small, bounded set of the files most worth a model's
// attention — install/build scripts and entry points — never the whole package.
func selectExcerpts(u *artifact.Unpacked) map[string]string {
	if u == nil {
		return nil
	}
	const maxFiles, maxBytes = 6, 8 << 10
	interesting := []string{
		"package.json", "setup.py", "setup.cfg", "pyproject.toml",
		"index.js", "main.js", "__init__.py",
	}
	out := map[string]string{}
	for _, name := range interesting {
		if len(out) >= maxFiles {
			break
		}
		if f := u.Lookup(name); f != nil {
			c := f.Content
			if len(c) > maxBytes {
				c = c[:maxBytes]
			}
			out[name] = string(c)
		}
	}
	return out
}

// previousGood returns the unpacked bytes of the most recent prior version that
// was allowed, to diff the candidate against. History is appended after each
// decision, so the current artifact isn't yet present here.
func (p *Pipeline) previousGood(art verdict.Artifact) (prev *artifact.Unpacked, version string, ok bool) {
	hist, err := p.cache.GetHistory(string(art.Ecosystem), art.Name)
	if err != nil || len(hist) == 0 {
		return nil, "", false
	}
	for i := len(hist) - 1; i >= 0; i-- {
		e := hist[i]
		if e.Digest == art.Digest || e.Decision != string(verdict.Allow) {
			continue
		}
		data, err := p.cache.GetArtifact(e.Digest)
		if err != nil {
			continue
		}
		u, err := artifact.UnpackAuto(art.Ecosystem, data)
		if err != nil {
			continue
		}
		return u, e.Version, true
	}
	return nil, "", false
}

func (p *Pipeline) recordHistory(art verdict.Artifact, d verdict.Decision) {
	err := p.cache.AppendHistory(string(art.Ecosystem), art.Name, cache.HistoryEntry{
		Version:  art.Version,
		Digest:   art.Digest,
		Decision: string(d),
		SeenAt:   time.Now().UTC(),
	})
	if err != nil {
		p.log.Warn("history append failed", "artifact", art.Name, "err", err)
	}
}

// ensure Pipeline implements Gate.
var _ Gate = (*Pipeline)(nil)
