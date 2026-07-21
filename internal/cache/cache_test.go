package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joncooper/detonator/internal/sign"
	"github.com/joncooper/detonator/internal/verdict"
)

func newTestCache(t *testing.T, ttl time.Duration) *Cache {
	t.Helper()
	c, err := New(t.TempDir(), ttl)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestArtifactRoundTrip(t *testing.T) {
	c := newTestCache(t, time.Minute)
	body := []byte("some tarball bytes")
	digest, err := c.PutArtifact(body)
	if err != nil {
		t.Fatalf("PutArtifact: %v", err)
	}
	if digest != Digest(body) {
		t.Fatalf("digest mismatch: %s vs %s", digest, Digest(body))
	}
	if !c.HasArtifact(digest) {
		t.Fatal("HasArtifact false after Put")
	}
	got, err := c.GetArtifact(digest)
	if err != nil {
		t.Fatalf("GetArtifact: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("bytes mismatch: %q", got)
	}
}

func TestArtifactMissAndBadDigest(t *testing.T) {
	c := newTestCache(t, time.Minute)
	if _, err := c.GetArtifact("sha256:" + hex64("ff")); err != ErrMiss {
		t.Fatalf("want ErrMiss, got %v", err)
	}
	if c.HasArtifact("not-a-digest") {
		t.Fatal("HasArtifact true for garbage digest")
	}
	if _, err := c.GetArtifact("garbage"); err == nil {
		t.Fatal("want error for bad digest")
	}
}

func TestMetadataTTL(t *testing.T) {
	c := newTestCache(t, 50*time.Millisecond)
	key := "npm-packument:express"
	if err := c.PutMetadata(key, []byte(`{"ok":true}`), "application/json", time.Now()); err != nil {
		t.Fatalf("PutMetadata: %v", err)
	}
	m, fresh, err := c.GetMetadata(key)
	if err != nil || !fresh {
		t.Fatalf("expected fresh hit, got fresh=%v err=%v", fresh, err)
	}
	if string(m.Body) != `{"ok":true}` {
		t.Fatalf("body mismatch: %q", m.Body)
	}
	time.Sleep(70 * time.Millisecond)
	if _, fresh, _ := c.GetMetadata(key); fresh {
		t.Fatal("expected stale after TTL")
	}
	// Stale is still returned (fall-back), just not fresh.
	if _, _, err := c.GetMetadata(key); err != nil {
		t.Fatalf("stale entry should still be retrievable: %v", err)
	}
}

func TestLocatorNoTTL(t *testing.T) {
	c := newTestCache(t, time.Nanosecond) // even with a zero-ish TTL, locators never expire
	digest := Digest([]byte("x"))
	if err := c.PutLocator("npm:/foo/-/foo-1.0.0.tgz", digest); err != nil {
		t.Fatalf("PutLocator: %v", err)
	}
	got, err := c.GetLocator("npm:/foo/-/foo-1.0.0.tgz")
	if err != nil {
		t.Fatalf("GetLocator: %v", err)
	}
	if got != digest {
		t.Fatalf("locator mismatch: %s vs %s", got, digest)
	}
	if _, err := c.GetLocator("npm:/missing"); err != ErrMiss {
		t.Fatalf("want ErrMiss, got %v", err)
	}
}

func TestVerdictRoundTrip(t *testing.T) {
	c := newTestCache(t, time.Minute)
	digest := Digest([]byte("pkg"))
	v := verdict.Verdict{
		Artifact: verdict.Artifact{Ecosystem: verdict.NPM, Name: "foo", Version: "1.0.0", Digest: digest},
		Decision: verdict.Block,
		Reason:   "test",
		Engine:   "test",
	}
	if err := c.PutVerdict(v); err != nil {
		t.Fatalf("PutVerdict: %v", err)
	}
	got, err := c.GetVerdict(digest)
	if err != nil {
		t.Fatalf("GetVerdict: %v", err)
	}
	if got.Decision != verdict.Block || got.Artifact.Name != "foo" {
		t.Fatalf("verdict mismatch: %+v", got)
	}
	if _, err := c.GetVerdict(Digest([]byte("other"))); err != ErrMiss {
		t.Fatalf("want ErrMiss, got %v", err)
	}
}

func TestSignedVerdictRoundTripAndTamper(t *testing.T) {
	dir := t.TempDir()
	c, err := New(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sign.LoadOrCreateEd25519(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	c.SetSigner(signer)

	digest := Digest([]byte("pkg"))
	v := verdict.Verdict{
		Artifact: verdict.Artifact{Ecosystem: verdict.NPM, Name: "foo", Version: "1", Digest: digest},
		Decision: verdict.Allow, Engine: "test",
	}
	if err := c.PutVerdict(v); err != nil {
		t.Fatalf("PutVerdict: %v", err)
	}
	got, err := c.GetVerdict(digest)
	if err != nil || got.Decision != verdict.Allow {
		t.Fatalf("signed roundtrip failed: %v %+v", err, got)
	}

	// A stored entry with no signer to verify it must not be trusted.
	unverified, _ := New(dir, time.Minute)
	if _, err := unverified.GetVerdict(digest); err != ErrMiss {
		t.Fatalf("signed entry read without a verifier should miss, got %v", err)
	}

	// Tamper with the on-disk verdict: the invalid signature makes it a miss so
	// the artifact is re-analyzed rather than trusted.
	p, _ := c.verdictPath(digest)
	raw, _ := os.ReadFile(p)
	tampered := []byte(string(raw))
	// Flip "allow" to "block" in the signed payload without re-signing.
	for i := 0; i+5 < len(tampered); i++ {
		if string(tampered[i:i+5]) == "allow" {
			copy(tampered[i:i+5], "block")
			break
		}
	}
	if err := os.WriteFile(p, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetVerdict(digest); err != ErrMiss {
		t.Fatalf("tampered signed verdict should miss, got %v", err)
	}
}

func TestUnsignedEntryMissesWhenSignerSet(t *testing.T) {
	dir := t.TempDir()
	c, _ := New(dir, time.Minute)
	digest := Digest([]byte("pkg"))
	// Store unsigned (no signer yet).
	if err := c.PutVerdict(verdict.Verdict{Artifact: verdict.Artifact{Digest: digest}, Decision: verdict.Allow}); err != nil {
		t.Fatal(err)
	}
	// Now enable signing: the pre-existing unsigned entry must be treated as a miss.
	signer, _ := sign.LoadOrCreateEd25519(filepath.Join(dir, "key"))
	c.SetSigner(signer)
	if _, err := c.GetVerdict(digest); err != ErrMiss {
		t.Fatalf("unsigned entry with signer set should miss, got %v", err)
	}
}

// hex64 pads a short hex prefix to a full 64-char sha256 hex string.
func hex64(prefix string) string {
	const zeros = "0000000000000000000000000000000000000000000000000000000000000000"
	return prefix + zeros[len(prefix):]
}
