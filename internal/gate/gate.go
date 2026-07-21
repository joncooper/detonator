// Package gate is the admission decision point: given an artifact and its bytes,
// it returns a verdict. The proxy consults it on every new artifact and enforces
// the result. The analysis pipeline (static, OSV, detonation, triage) plugs in
// here across later phases; Phase 1 ships an always-allow stub so the proxy's
// registry integration can be proven transparent first (build-plan §5, Phase 1).
package gate

import (
	"context"
	"time"

	"github.com/joncooper/detonator/internal/verdict"
)

// Gate judges whether an artifact may be served to the developer's machine.
type Gate interface {
	// Admit returns a verdict for art. Implementations may inspect the raw
	// bytes; the digest in art is already computed over exactly these bytes.
	Admit(ctx context.Context, art verdict.Artifact, bytes []byte) (verdict.Verdict, error)
}

// AllowAll admits every artifact. It exists so Phase 1 can prove the proxy is a
// transparent pull-through before any real analysis exists. It is never the
// right gate in production.
type AllowAll struct{}

// Admit always allows.
func (AllowAll) Admit(_ context.Context, art verdict.Artifact, _ []byte) (verdict.Verdict, error) {
	return verdict.Verdict{
		Artifact:  art,
		Decision:  verdict.Allow,
		Reason:    "phase-1 stub: analysis not yet wired, admitting all artifacts",
		DecidedAt: time.Now().UTC(),
		Engine:    "allow-all-stub",
	}, nil
}
