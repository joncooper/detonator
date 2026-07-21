package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joncooper/detonator/internal/cache"
	"github.com/joncooper/detonator/internal/config"
	"github.com/joncooper/detonator/internal/verdict"
)

func testServer(t *testing.T, cfg config.Config, g interface {
	Admit(context.Context, verdict.Artifact, []byte) (verdict.Verdict, error)
}) *Server {
	t.Helper()
	c, err := cache.New(t.TempDir(), 5*time.Minute)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	return New(cfg, c, gateFunc(g.Admit), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// gateFunc adapts a func to the gate.Gate interface.
type gateFunc func(context.Context, verdict.Artifact, []byte) (verdict.Verdict, error)

func (f gateFunc) Admit(ctx context.Context, a verdict.Artifact, b []byte) (verdict.Verdict, error) {
	return f(ctx, a, b)
}

func TestNPMPackumentRewrite(t *testing.T) {
	cfg := config.Default()
	cfg.NPMUpstream = "https://registry.npmjs.org"
	cfg.PublicURL = "http://127.0.0.1:8080"
	s := testServer(t, cfg, allowGate())

	in := []byte(`{"name":"express","versions":{"4.0.0":{"dist":{"tarball":"https://registry.npmjs.org/express/-/express-4.0.0.tgz"}}}}`)
	out, err := s.rewriteNPMPackument(in)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "http://127.0.0.1:8080/npm/express/-/express-4.0.0.tgz") {
		t.Fatalf("tarball URL not rewritten: %s", got)
	}
	if strings.Contains(got, "registry.npmjs.org") {
		t.Fatalf("upstream host leaked: %s", got)
	}
}

func TestPyPIFileURLRewrite(t *testing.T) {
	cfg := config.Default()
	cfg.PyPIFilesUpstream = "https://files.pythonhosted.org"
	cfg.PublicURL = "http://127.0.0.1:8080"
	s := testServer(t, cfg, allowGate())

	proj := pypiProject{
		Name: "click",
		Files: []pypiFile{{
			Filename: "click-8.1.7-py3-none-any.whl",
			URL:      "https://files.pythonhosted.org/packages/ab/cd/click-8.1.7-py3-none-any.whl",
			Hashes:   map[string]string{"sha256": "deadbeef"},
		}},
	}
	s.rewritePyPIFileURLs(&proj)
	if !strings.HasPrefix(proj.Files[0].URL, "http://127.0.0.1:8080/pypi/files/packages/") {
		t.Fatalf("file URL not rewritten: %s", proj.Files[0].URL)
	}
	html := string(renderPyPIHTML(proj))
	if !strings.Contains(html, "#sha256=deadbeef") || !strings.Contains(html, "click-8.1.7") {
		t.Fatalf("HTML render missing hash or filename: %s", html)
	}
}

func TestNPMVersionFromTarball(t *testing.T) {
	cases := []struct{ name, file, want string }{
		{"express", "express-4.18.2.tgz", "4.18.2"},
		{"@babel/core", "core-7.23.0.tgz", "7.23.0"},
		{"is-odd", "is-odd-3.0.1.tgz", "3.0.1"},
	}
	for _, c := range cases {
		if got := npmVersionFromTarball(c.name, c.file); got != c.want {
			t.Errorf("npmVersionFromTarball(%q,%q)=%q want %q", c.name, c.file, got, c.want)
		}
	}
}

func TestPyPINameVersionFromFile(t *testing.T) {
	cases := []struct{ file, name, ver string }{
		{"click-8.1.7-py3-none-any.whl", "click", "8.1.7"},
		{"rich-13.7.1.tar.gz", "rich", "13.7.1"},
	}
	for _, c := range cases {
		n, v := pypiNameVersionFromFile(c.file)
		if n != c.name || v != c.ver {
			t.Errorf("pypiNameVersionFromFile(%q)=(%q,%q) want (%q,%q)", c.file, n, v, c.name, c.ver)
		}
	}
}

// TestGateEnforcement is the load-bearing test: a block verdict must produce a
// 403, and the artifact bytes must never reach the client. An allow verdict
// must stream the exact upstream bytes.
func TestGateEnforcement(t *testing.T) {
	const tarball = "PK\x03\x04 pretend npm tarball bytes"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".tgz") {
			_, _ = io.WriteString(w, tarball)
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	for _, tc := range []struct {
		name       string
		decision   verdict.Decision
		wantStatus int
	}{
		{"allow", verdict.Allow, http.StatusOK},
		{"block", verdict.Block, http.StatusForbidden},
		{"quarantine", verdict.Quarantine, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.NPMUpstream = upstream.URL
			cfg.PublicURL = "http://127.0.0.1:8080"
			decision := tc.decision
			s := testServer(t, cfg, gateFunc(func(_ context.Context, a verdict.Artifact, _ []byte) (verdict.Verdict, error) {
				return verdict.Verdict{Artifact: a, Decision: decision, Reason: "test", Engine: "test"}, nil
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/npm/foo/-/foo-1.0.0.tgz", nil)
			s.Handler().ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d want %d", rec.Code, tc.wantStatus)
			}
			body := rec.Body.String()
			if tc.decision == verdict.Allow {
				if body != tarball {
					t.Fatalf("allow: body=%q want tarball", body)
				}
			} else {
				if strings.Contains(body, tarball) {
					t.Fatal("blocked artifact bytes leaked to client")
				}
				var refusal map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &refusal); err != nil {
					t.Fatalf("refusal body not JSON: %v", err)
				}
				if refusal["decision"] != string(tc.decision) {
					t.Fatalf("refusal decision=%v want %v", refusal["decision"], tc.decision)
				}
			}
		})
	}
}

func allowGate() gateFunc {
	return func(_ context.Context, a verdict.Artifact, _ []byte) (verdict.Verdict, error) {
		return verdict.Verdict{Artifact: a, Decision: verdict.Allow, Engine: "test"}, nil
	}
}
