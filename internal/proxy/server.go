// Package proxy is Detonator's enforcement point: a caching pull-through
// registry that speaks the npm and PyPI protocols. Every artifact download is
// routed through the admission gate; nothing reaches the developer's machine
// without a verdict. This is the single choke point — if a request doesn't pass
// through here, nothing installs (build-plan §3).
package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/joncooper/detonator/internal/cache"
	"github.com/joncooper/detonator/internal/config"
	"github.com/joncooper/detonator/internal/gate"
	"github.com/joncooper/detonator/internal/verdict"
)

// Server is the proxy HTTP handler.
type Server struct {
	cfg   config.Config
	cache *cache.Cache
	gate  gate.Gate
	up    *upstream
	log   *slog.Logger
}

// New builds a proxy server.
func New(cfg config.Config, c *cache.Cache, g gate.Gate, log *slog.Logger) *Server {
	return &Server{cfg: cfg, cache: c, gate: g, up: newUpstream(), log: log}
}

// Handler returns the routed HTTP handler. npm lives under /npm, PyPI under
// /pypi, so a single proxy port serves both protocols unambiguously.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/npm/", s.handleNPM)
	mux.HandleFunc("/pypi/simple/", s.handlePyPISimple)
	mux.HandleFunc("/pypi/files/", s.handlePyPIFiles)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", s.handleIndex)
	return s.withLogging(mux)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("Detonator proxy\n\n" +
		"npm:  set registry to " + s.cfg.PublicURL + "/npm/\n" +
		"pip:  set index-url to " + s.cfg.PublicURL + "/pypi/simple/\n"))
}

// serveArtifact is the gate-and-serve flow shared by npm tarballs and PyPI
// files. It resolves the request to content-addressed bytes, obtains a verdict
// (cached, else via the gate), and either streams the artifact or refuses it.
func (s *Server) serveArtifact(w http.ResponseWriter, r *http.Request, eco verdict.Ecosystem, name, version, upstreamURL, defaultCT string) {
	ctx := r.Context()
	locKey := string(eco) + ":" + r.URL.Path

	// Serialize concurrent requests for the same artifact so we fetch upstream
	// and run the gate at most once.
	unlock := s.cache.Lock(locKey)
	defer unlock()

	// Fast path: we've resolved this URL before. The mapping is immutable.
	if digest, err := s.cache.GetLocator(locKey); err == nil {
		if v, verr := s.cache.GetVerdict(digest); verr == nil {
			if v.Decision != verdict.Allow {
				s.refuse(w, v)
				return
			}
			if b, berr := s.cache.GetArtifact(digest); berr == nil {
				s.writeArtifact(w, b, defaultCT)
				return
			}
		}
	}

	// Slow path: pull the bytes from upstream and identify them by digest.
	res, err := s.up.get(ctx, upstreamURL, "")
	if err != nil {
		s.log.Error("upstream fetch failed", "url", upstreamURL, "err", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	if res.status != http.StatusOK {
		http.Error(w, "upstream returned "+http.StatusText(res.status), res.status)
		return
	}
	bytes := res.body
	digest := cache.Digest(bytes)
	art := verdict.Artifact{Ecosystem: eco, Name: name, Version: version, Digest: digest}

	// Verdict is content-addressed: judge each distinct set of bytes once.
	v, err := s.cache.GetVerdict(digest)
	if err != nil {
		v, err = s.gate.Admit(ctx, art, bytes)
		if err != nil {
			s.log.Error("gate error", "artifact", art, "err", err)
			http.Error(w, "admission gate error", http.StatusInternalServerError)
			return
		}
		if err := s.cache.PutVerdict(v); err != nil {
			s.log.Warn("verdict cache write failed", "err", err)
		}
	}

	// Cache the bytes and remember this URL resolves to them, whatever the
	// verdict — a re-request shouldn't re-fetch just to be refused again.
	if _, err := s.cache.PutArtifact(bytes); err != nil {
		s.log.Warn("artifact cache write failed", "err", err)
	}
	if err := s.cache.PutLocator(locKey, digest); err != nil {
		s.log.Warn("locator cache write failed", "err", err)
	}

	if v.Decision != verdict.Allow {
		s.refuse(w, v)
		return
	}
	ct := res.contentType
	if ct == "" {
		ct = defaultCT
	}
	s.writeArtifact(w, bytes, ct)
}

func (s *Server) writeArtifact(w http.ResponseWriter, b []byte, contentType string) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Detonator-Verdict", "allow")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// refuse denies an artifact with the verdict as a machine-readable 403 body, so
// the reason surfaces in the failing install rather than as an opaque error.
func (s *Server) refuse(w http.ResponseWriter, v verdict.Verdict) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Detonator-Verdict", string(v.Decision))
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":    "detonator refused this package",
		"decision": v.Decision,
		"reason":   v.Reason,
		"artifact": v.Artifact,
		"signals":  v.Signals,
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.log.Debug("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
