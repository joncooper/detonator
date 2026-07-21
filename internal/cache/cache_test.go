package cache

import (
	"testing"
	"time"

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

// hex64 pads a short hex prefix to a full 64-char sha256 hex string.
func hex64(prefix string) string {
	const zeros = "0000000000000000000000000000000000000000000000000000000000000000"
	return prefix + zeros[len(prefix):]
}
