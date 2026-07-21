// Package sign signs and verifies verdicts so a cached decision can't be forged
// and can be trusted when shared across a team (build-plan §3, §7).
//
// The Signer/Verifier interfaces are the pluggable seam. The default backend is
// a local ed25519 keypair — dependency-free and offline, right for solo dev.
// A cosign/sigstore keyless backend (Fulcio-issued, transparency-logged)
// implements the same interfaces for team/CI use without changing callers.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joncooper/detonator/internal/verdict"
)

// ErrBadSignature means a signed verdict failed verification: forged, tampered,
// or signed by an unknown key.
var ErrBadSignature = errors.New("sign: signature verification failed")

// Signer produces signed verdicts and can verify them.
type Signer interface {
	Verifier
	Sign(v verdict.Verdict) (verdict.SignedVerdict, error)
}

// Verifier checks a signed verdict against a known key.
type Verifier interface {
	Verify(sv verdict.SignedVerdict) error
	KeyID() string
	Algorithm() string
}

// Ed25519Signer signs verdicts with a local ed25519 key.
type Ed25519Signer struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

// LoadOrCreateEd25519 loads the ed25519 seed at path, or generates and persists
// one (0600) if it doesn't exist. The key id is a short hash of the public key.
func LoadOrCreateEd25519(path string) (*Ed25519Signer, error) {
	seed, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("sign: key %s has wrong size %d", path, len(seed))
		}
	case errors.Is(err, os.ErrNotExist):
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			return nil, fmt.Errorf("sign: persist key: %w", err)
		}
	default:
		return nil, err
	}
	return newEd25519FromSeed(seed), nil
}

func newEd25519FromSeed(seed []byte) *Ed25519Signer {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &Ed25519Signer{priv: priv, pub: pub, keyID: hex.EncodeToString(sum[:8])}
}

// Algorithm identifies the signature scheme.
func (s *Ed25519Signer) Algorithm() string { return "ed25519" }

// KeyID identifies the signing key.
func (s *Ed25519Signer) KeyID() string { return s.keyID }

// Sign returns v wrapped with a detached signature over its canonical bytes.
func (s *Ed25519Signer) Sign(v verdict.Verdict) (verdict.SignedVerdict, error) {
	msg, err := v.Canonical()
	if err != nil {
		return verdict.SignedVerdict{}, err
	}
	sig := ed25519.Sign(s.priv, msg)
	return verdict.SignedVerdict{
		Verdict:   v,
		Algorithm: s.Algorithm(),
		KeyID:     s.keyID,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks a signed verdict came from this key and hasn't been altered.
func (s *Ed25519Signer) Verify(sv verdict.SignedVerdict) error {
	if sv.Algorithm != s.Algorithm() {
		return fmt.Errorf("sign: algorithm %q not supported: %w", sv.Algorithm, ErrBadSignature)
	}
	if sv.KeyID != s.keyID {
		return fmt.Errorf("sign: unknown key id %q: %w", sv.KeyID, ErrBadSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(sv.Signature)
	if err != nil {
		return fmt.Errorf("sign: bad signature encoding: %w", ErrBadSignature)
	}
	msg, err := sv.Verdict.Canonical()
	if err != nil {
		return err
	}
	if !ed25519.Verify(s.pub, msg, sig) {
		return ErrBadSignature
	}
	return nil
}

// compile-time check
var _ Signer = (*Ed25519Signer)(nil)
