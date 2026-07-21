// Package verdict defines the admission decision types shared across the
// pipeline. A verdict is content-addressed by the artifact it judges, so it can
// be cached and (from Phase 4) signed and shared across a team.
package verdict

import (
	"encoding/json"
	"time"
)

// Decision is the admission outcome for one package artifact.
type Decision string

const (
	Allow      Decision = "allow"
	Block      Decision = "block"
	Quarantine Decision = "quarantine"
)

// Ecosystem identifies the package registry an artifact came from.
type Ecosystem string

const (
	NPM  Ecosystem = "npm"
	PyPI Ecosystem = "pypi"
)

// Artifact identifies exactly one package version by its bytes. The Digest is
// the enforcement key: a republished version with the same name+version but
// different bytes is a different artifact and must be re-judged (build-plan §6,
// "determinism & caching correctness").
type Artifact struct {
	Ecosystem Ecosystem `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	// Digest is "sha256:<hex>" over the artifact bytes.
	Digest string `json:"digest"`
}

// Signal is one concrete finding that drove a verdict, e.g. a behavioral rule
// hit or a static red flag. Stages emit these; the verdict engine weighs them.
type Signal struct {
	Stage       string   `json:"stage"`              // "static", "osv", "detonation", "triage", ...
	Rule        string   `json:"rule,omitempty"`     // rule/check identifier
	Severity    Severity `json:"severity"`           // informational..critical
	Description string   `json:"description"`        // human-readable, grounded in evidence
	Evidence    string   `json:"evidence,omitempty"` // the observed fact (path, address, argv)
}

// Severity ranks a signal's weight in the verdict engine.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// DiffSummary is the file-level change from the previous known-good version,
// carried on the verdict so a reviewer can see what changed.
type DiffSummary struct {
	PrevVersion string   `json:"prev_version"`
	Added       []string `json:"added,omitempty"`
	Removed     []string `json:"removed,omitempty"`
	Modified    []string `json:"modified,omitempty"`
}

// Verdict is the composite decision for an artifact, with the signals that
// produced it. It is the unit stored, cached, and (later) signed.
type Verdict struct {
	Artifact  Artifact     `json:"artifact"`
	Decision  Decision     `json:"decision"`
	Reason    string       `json:"reason"`
	Signals   []Signal     `json:"signals,omitempty"`
	Diff      *DiffSummary `json:"diff,omitempty"`
	DecidedAt time.Time    `json:"decided_at"`
	// Engine records which pipeline produced this verdict, for auditability.
	Engine string `json:"engine"`
}

// Canonical returns the deterministic byte encoding of v that is signed and
// verified. Struct fields marshal in declaration order and the signals slice is
// already severity-sorted, so the same verdict always yields the same bytes —
// the property a signature depends on. A forged or tampered cached "allow"
// won't verify against these bytes.
func (v Verdict) Canonical() ([]byte, error) {
	return json.Marshal(v)
}

// SignedVerdict wraps a verdict with a detached signature over its canonical
// bytes, so a cached decision shared across a team can't be forged (build-plan
// §3, "cosign-sign the verdict"). The signing backend is pluggable; the wire
// shape records which one produced it.
type SignedVerdict struct {
	Verdict   Verdict `json:"verdict"`
	Algorithm string  `json:"algorithm"` // e.g. "ed25519"
	KeyID     string  `json:"key_id"`    // identifies the signing key
	Signature string  `json:"signature"` // base64(detached signature)
}
