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
	"github.com/joncooper/detonator/internal/verdict"
)

// Pipeline is the Phase 2 admission gate: static analysis, OSV known-vuln
// lookup, and a diff against the previous known-good version, composed into a
// verdict by the engine. Detonation (Phase 3) and LLM triage (Phase 4) add more
// signal stages behind this same interface.
type Pipeline struct {
	cache  *cache.Cache
	osv    *osv.Client // nil disables OSV lookup
	policy engine.Policy
	log    *slog.Logger
}

// PipelineOptions configures a Pipeline gate.
type PipelineOptions struct {
	Cache  *cache.Cache
	OSV    *osv.Client
	Policy engine.Policy
	Logger *slog.Logger
}

// NewPipeline builds a Pipeline gate.
func NewPipeline(o PipelineOptions) *Pipeline {
	return &Pipeline{cache: o.Cache, osv: o.OSV, policy: o.Policy, log: o.Logger}
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

	v := engine.Decide(art, signals, p.policy, "static-pipeline")
	v.Diff = diff

	p.recordHistory(art, v.Decision)
	return v, nil
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
