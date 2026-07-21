package sign

import (
	"path/filepath"
	"testing"

	"github.com/joncooper/detonator/internal/verdict"
)

func testSigner(t *testing.T) *Ed25519Signer {
	t.Helper()
	s, err := LoadOrCreateEd25519(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("LoadOrCreateEd25519: %v", err)
	}
	return s
}

func sampleVerdict() verdict.Verdict {
	return verdict.Verdict{
		Artifact: verdict.Artifact{Ecosystem: verdict.NPM, Name: "foo", Version: "1.0.0", Digest: "sha256:" + hex64()},
		Decision: verdict.Allow,
		Reason:   "clean",
		Engine:   "test",
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := testSigner(t)
	sv, err := s.Sign(sampleVerdict())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sv.Algorithm != "ed25519" || sv.KeyID == "" || sv.Signature == "" {
		t.Fatalf("incomplete signed verdict: %+v", sv)
	}
	if err := s.Verify(sv); err != nil {
		t.Fatalf("Verify of own signature failed: %v", err)
	}
}

func TestTamperedVerdictFailsVerify(t *testing.T) {
	s := testSigner(t)
	sv, _ := s.Sign(sampleVerdict())
	// Flip the decision from allow to block: the signature must no longer verify.
	sv.Verdict.Decision = verdict.Block
	if err := s.Verify(sv); err == nil {
		t.Fatal("tampered verdict verified successfully — forgery not detected")
	}
}

func TestWrongKeyFailsVerify(t *testing.T) {
	signer := testSigner(t)
	other := testSigner(t) // different key
	sv, _ := signer.Sign(sampleVerdict())
	if err := other.Verify(sv); err == nil {
		t.Fatal("verify succeeded under a different key")
	}
}

func TestPersistedKeyIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	a, err := LoadOrCreateEd25519(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateEd25519(path) // reload
	if err != nil {
		t.Fatal(err)
	}
	if a.KeyID() != b.KeyID() {
		t.Fatalf("key id changed across reload: %s vs %s", a.KeyID(), b.KeyID())
	}
	// A signature from the first load must verify under the reloaded key.
	sv, _ := a.Sign(sampleVerdict())
	if err := b.Verify(sv); err != nil {
		t.Fatalf("reloaded key can't verify: %v", err)
	}
}

func hex64() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}
