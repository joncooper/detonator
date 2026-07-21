// Package cache is Detonator's on-disk store: content-addressed artifact bytes,
// TTL'd registry metadata, and content-addressed verdicts.
//
// Two invariants hold the safety story together:
//   - Artifacts are keyed by their sha256 digest, never by name+version. A
//     republished version with the same number but different bytes lands at a
//     different key and is re-judged (build-plan §6).
//   - Writes are atomic (temp file + rename), so a concurrent reader never sees
//     a half-written artifact or verdict.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/joncooper/detonator/internal/sign"
	"github.com/joncooper/detonator/internal/verdict"
)

// ErrMiss is returned when a key is absent (or stale, for metadata).
var ErrMiss = errors.New("cache: miss")

// Cache is a filesystem-backed store rooted at a single directory.
type Cache struct {
	root   string
	ttl    time.Duration
	keys   *keyedMutex
	signer sign.Signer // nil = verdicts stored unsigned (pre-Phase-4)
}

// SetSigner enables signed verdicts: PutVerdict signs, GetVerdict verifies and
// treats an unsigned or forged entry as a miss so it is re-analyzed.
func (c *Cache) SetSigner(s sign.Signer) { c.signer = s }

// New opens (creating if needed) a cache rooted at dir, serving metadata for ttl
// before it is treated as stale.
func New(dir string, ttl time.Duration) (*Cache, error) {
	for _, sub := range []string{"artifacts", "metadata", "verdicts", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("cache: mkdir %s: %w", sub, err)
		}
	}
	return &Cache{root: dir, ttl: ttl, keys: newKeyedMutex()}, nil
}

// Lock serializes work for a single logical key (e.g. one artifact fetch) so two
// concurrent requests don't both hit upstream or double-run the gate. The caller
// must invoke the returned unlock.
func (c *Cache) Lock(key string) (unlock func()) { return c.keys.lock(key) }

// ---- artifacts (content-addressed) ----

// Digest returns the canonical "sha256:<hex>" digest of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (c *Cache) artifactPath(digest string) (string, error) {
	hexstr, ok := parseSHA256(digest)
	if !ok {
		return "", fmt.Errorf("cache: bad digest %q", digest)
	}
	return filepath.Join(c.root, "artifacts", hexstr[:2], hexstr), nil
}

// HasArtifact reports whether the artifact with the given digest is cached.
func (c *Cache) HasArtifact(digest string) bool {
	p, err := c.artifactPath(digest)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// GetArtifact returns the cached bytes for digest, or ErrMiss.
func (c *Cache) GetArtifact(digest string) ([]byte, error) {
	p, err := c.artifactPath(digest)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrMiss
	}
	return b, err
}

// PutArtifact stores b under its own digest and returns that digest. The write
// is atomic and idempotent.
func (c *Cache) PutArtifact(b []byte) (string, error) {
	digest := Digest(b)
	p, err := c.artifactPath(digest)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := c.atomicWrite(p, b); err != nil {
		return "", err
	}
	return digest, nil
}

// ---- metadata (TTL'd) ----

// Metadata is a cached registry response (a packument or a simple index).
type Metadata struct {
	Body        []byte
	ContentType string
	FetchedAt   time.Time
}

type metaSidecar struct {
	ContentType string    `json:"content_type"`
	FetchedAt   time.Time `json:"fetched_at"`
}

func (c *Cache) metaPaths(key string) (body, meta string) {
	h := sha256.Sum256([]byte(key))
	name := hex.EncodeToString(h[:])
	base := filepath.Join(c.root, "metadata", name)
	return base + ".body", base + ".meta"
}

// GetMetadata returns cached metadata for key. If it is older than the TTL, it
// is returned with fresh=false so the caller can revalidate but still fall back
// to it if upstream is unreachable.
func (c *Cache) GetMetadata(key string) (m Metadata, fresh bool, err error) {
	bodyPath, metaPath := c.metaPaths(key)
	body, err := os.ReadFile(bodyPath)
	if errors.Is(err, os.ErrNotExist) {
		return Metadata{}, false, ErrMiss
	}
	if err != nil {
		return Metadata{}, false, err
	}
	sidecarRaw, err := os.ReadFile(metaPath)
	if err != nil {
		return Metadata{}, false, ErrMiss
	}
	var sc metaSidecar
	if err := json.Unmarshal(sidecarRaw, &sc); err != nil {
		return Metadata{}, false, ErrMiss
	}
	m = Metadata{Body: body, ContentType: sc.ContentType, FetchedAt: sc.FetchedAt}
	fresh = time.Since(sc.FetchedAt) < c.ttl
	return m, fresh, nil
}

// PutMetadata caches body under key with the given content type, stamped now.
func (c *Cache) PutMetadata(key string, body []byte, contentType string, now time.Time) error {
	bodyPath, metaPath := c.metaPaths(key)
	if err := c.atomicWrite(bodyPath, body); err != nil {
		return err
	}
	sc, err := json.Marshal(metaSidecar{ContentType: contentType, FetchedAt: now})
	if err != nil {
		return err
	}
	return c.atomicWrite(metaPath, sc)
}

// ---- locators (immutable request-path -> digest) ----
//
// A registry artifact URL is immutable: an npm tarball or PyPI file at a given
// path never changes bytes. So a path -> digest mapping never goes stale and
// needs no TTL. It lets the proxy skip a redundant upstream fetch once it has
// seen a URL, jumping straight to the content-addressed artifact and verdict.

func (c *Cache) locatorPath(key string) string {
	h := sha256.Sum256([]byte(key))
	return filepath.Join(c.root, "metadata", "loc-"+hex.EncodeToString(h[:]))
}

// GetLocator returns the artifact digest previously mapped to key, or ErrMiss.
func (c *Cache) GetLocator(key string) (string, error) {
	b, err := os.ReadFile(c.locatorPath(key))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrMiss
	}
	if err != nil {
		return "", err
	}
	if _, ok := parseSHA256(string(b)); !ok {
		return "", ErrMiss
	}
	return string(b), nil
}

// PutLocator records that key resolves to the given artifact digest.
func (c *Cache) PutLocator(key, digest string) error {
	if _, ok := parseSHA256(digest); !ok {
		return fmt.Errorf("cache: bad digest %q", digest)
	}
	return c.atomicWrite(c.locatorPath(key), []byte(digest))
}

// ---- package history (per package, in encounter order) ----
//
// The differ needs the previous version's bytes to diff against. History is an
// append-only log per (ecosystem, name), in the order versions were first seen
// and served, so "last known-good" is just the most recent allowed entry.

// HistoryEntry records one version the proxy has served.
type HistoryEntry struct {
	Version  string    `json:"version"`
	Digest   string    `json:"digest"`
	Decision string    `json:"decision"`
	SeenAt   time.Time `json:"seen_at"`
}

func (c *Cache) historyPath(eco, name string) string {
	h := sha256.Sum256([]byte(eco + "\x00" + name))
	return filepath.Join(c.root, "metadata", "hist-"+hex.EncodeToString(h[:]))
}

// GetHistory returns the recorded versions for a package, oldest first.
func (c *Cache) GetHistory(eco, name string) ([]HistoryEntry, error) {
	b, err := os.ReadFile(c.historyPath(eco, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []HistoryEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// AppendHistory records that a version was served. It de-dupes on digest so a
// repeated request doesn't grow the log; a re-request under the caller's key
// lock keeps this safe from concurrent double-append.
func (c *Cache) AppendHistory(eco, name string, e HistoryEntry) error {
	entries, err := c.GetHistory(eco, name)
	if err != nil {
		return err
	}
	for _, existing := range entries {
		if existing.Digest == e.Digest {
			return nil
		}
	}
	entries = append(entries, e)
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return c.atomicWrite(c.historyPath(eco, name), b)
}

// ---- verdicts (content-addressed by artifact digest) ----

func (c *Cache) verdictPath(digest string) (string, error) {
	hexstr, ok := parseSHA256(digest)
	if !ok {
		return "", fmt.Errorf("cache: bad digest %q", digest)
	}
	return filepath.Join(c.root, "verdicts", hexstr+".json"), nil
}

// GetVerdict returns the cached verdict for an artifact digest, or ErrMiss.
// When a signer is configured, a stored entry must carry a valid signature from
// the known key; an unsigned or forged entry is treated as a miss so it is
// re-analyzed rather than trusted.
func (c *Cache) GetVerdict(digest string) (verdict.Verdict, error) {
	p, err := c.verdictPath(digest)
	if err != nil {
		return verdict.Verdict{}, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return verdict.Verdict{}, ErrMiss
	}
	if err != nil {
		return verdict.Verdict{}, err
	}

	if isSignedEnvelope(b) {
		var sv verdict.SignedVerdict
		if err := json.Unmarshal(b, &sv); err != nil {
			return verdict.Verdict{}, ErrMiss
		}
		if c.signer == nil {
			// Have a signed entry but no verifier: don't trust it blindly.
			return verdict.Verdict{}, ErrMiss
		}
		if err := c.signer.Verify(sv); err != nil {
			return verdict.Verdict{}, ErrMiss
		}
		return sv.Verdict, nil
	}

	// Unsigned entry.
	if c.signer != nil {
		// A signer is configured but this entry predates signing: re-analyze.
		return verdict.Verdict{}, ErrMiss
	}
	var v verdict.Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		return verdict.Verdict{}, err
	}
	return v, nil
}

// PutVerdict stores v, keyed by its artifact digest. If a signer is configured
// the verdict is signed so a shared or cached decision can't be forged.
func (c *Cache) PutVerdict(v verdict.Verdict) error {
	p, err := c.verdictPath(v.Artifact.Digest)
	if err != nil {
		return err
	}
	var b []byte
	if c.signer != nil {
		sv, err := c.signer.Sign(v)
		if err != nil {
			return err
		}
		b, err = json.MarshalIndent(sv, "", "  ")
		if err != nil {
			return err
		}
	} else {
		b, err = json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
	}
	return c.atomicWrite(p, b)
}

// isSignedEnvelope reports whether stored bytes are a SignedVerdict (they carry
// a top-level "signature") rather than a bare Verdict.
func isSignedEnvelope(b []byte) bool {
	var probe struct {
		Signature *string `json:"signature"`
	}
	if json.Unmarshal(b, &probe) != nil {
		return false
	}
	return probe.Signature != nil
}

// ---- internals ----

// atomicWrite writes b to path via a temp file + rename, so readers see either
// the old contents or the complete new contents, never a partial write.
func (c *Cache) atomicWrite(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Join(c.root, "tmp"), "w-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func parseSHA256(digest string) (hexstr string, ok bool) {
	const prefix = "sha256:"
	if len(digest) != len(prefix)+64 || digest[:len(prefix)] != prefix {
		return "", false
	}
	hexstr = digest[len(prefix):]
	if _, err := hex.DecodeString(hexstr); err != nil {
		return "", false
	}
	return hexstr, true
}

// keyedMutex hands out one mutex per string key, so callers can serialize work
// for a logical resource without a global lock.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newKeyedMutex() *keyedMutex { return &keyedMutex{locks: map[string]*sync.Mutex{}} }

func (k *keyedMutex) lock(key string) (unlock func()) {
	k.mu.Lock()
	m, ok := k.locks[key]
	if !ok {
		m = &sync.Mutex{}
		k.locks[key] = m
	}
	k.mu.Unlock()
	m.Lock()
	return m.Unlock
}
