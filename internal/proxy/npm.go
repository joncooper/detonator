package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/joncooper/detonator/internal/verdict"
)

// handleNPM serves the npm registry protocol under /npm/. Two request shapes:
//
//	GET /npm/{pkg}              -> packument (version metadata), tarball URLs rewritten to us
//	GET /npm/{pkg}/-/{file}.tgz -> the tarball, routed through the admission gate
//
// {pkg} may be scoped ("@scope/name"); net/http has already percent-decoded the
// path, so scoped names arrive with a literal slash either way.
func (s *Server) handleNPM(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/npm/")
	if rest == "" {
		http.Error(w, "npm: missing package", http.StatusNotFound)
		return
	}
	if name, file, ok := splitNPMTarball(rest); ok {
		s.serveNPMTarball(w, r, name, file)
		return
	}
	s.serveNPMPackument(w, r, rest)
}

// splitNPMTarball recognizes ".../{name}/-/{file}" and returns the package name
// and tarball filename. The "/-/" separator is npm's tarball convention.
func splitNPMTarball(rest string) (name, file string, ok bool) {
	i := strings.Index(rest, "/-/")
	if i < 0 {
		return "", "", false
	}
	return rest[:i], rest[i+len("/-/"):], true
}

func (s *Server) serveNPMPackument(w http.ResponseWriter, r *http.Request, name string) {
	key := "npm-packument:" + name
	upstreamURL := s.cfg.NPMUpstream + "/" + name

	// Serve fresh cached metadata; on a stale or missing entry, revalidate.
	if m, fresh, err := s.cache.GetMetadata(key); err == nil && fresh {
		s.writeJSON(w, m.Body, m.ContentType)
		return
	}

	res, err := s.up.get(r.Context(), upstreamURL, "application/json")
	if err != nil {
		// Upstream down: fall back to stale cache if we have any.
		if m, _, cerr := s.cache.GetMetadata(key); cerr == nil {
			s.writeJSON(w, m.Body, m.ContentType)
			return
		}
		http.Error(w, "npm upstream fetch failed", http.StatusBadGateway)
		return
	}
	if res.status != http.StatusOK {
		http.Error(w, "npm upstream returned "+http.StatusText(res.status), res.status)
		return
	}

	rewritten, err := s.rewriteNPMPackument(res.body)
	if err != nil {
		http.Error(w, "npm: malformed packument", http.StatusBadGateway)
		return
	}
	ct := "application/json"
	if err := s.cache.PutMetadata(key, rewritten, ct, time.Now().UTC()); err != nil {
		s.log.Warn("npm metadata cache write failed", "err", err)
	}
	s.writeJSON(w, rewritten, ct)
}

// rewriteNPMPackument repoints every upstream tarball URL at this proxy, so the
// npm client fetches tarballs back through the admission gate rather than
// directly from the registry.
func (s *Server) rewriteNPMPackument(body []byte) ([]byte, error) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	oldPrefix := s.cfg.NPMUpstream + "/"
	newPrefix := s.cfg.PublicURL + "/npm/"
	rewriteURLStrings(doc, oldPrefix, newPrefix)
	return json.Marshal(doc)
}

// rewriteURLStrings walks a decoded JSON value and rewrites any string that
// begins with oldPrefix. This catches dist.tarball wherever it appears without
// hardcoding the document shape.
func rewriteURLStrings(v any, oldPrefix, newPrefix string) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && strings.HasPrefix(s, oldPrefix) {
				t[k] = newPrefix + strings.TrimPrefix(s, oldPrefix)
				continue
			}
			rewriteURLStrings(val, oldPrefix, newPrefix)
		}
	case []any:
		for _, val := range t {
			rewriteURLStrings(val, oldPrefix, newPrefix)
		}
	}
}

func (s *Server) serveNPMTarball(w http.ResponseWriter, r *http.Request, name, file string) {
	version := npmVersionFromTarball(name, file)
	upstreamURL := s.cfg.NPMUpstream + "/" + name + "/-/" + file
	s.serveArtifact(w, r, verdict.NPM, name, version, upstreamURL, "application/octet-stream")
}

// npmVersionFromTarball recovers the version from a tarball filename, which npm
// forms as "<unscoped-name>-<version>.tgz".
func npmVersionFromTarball(name, file string) string {
	unscoped := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		unscoped = name[i+1:]
	}
	v := strings.TrimSuffix(file, ".tgz")
	v = strings.TrimPrefix(v, unscoped+"-")
	return v
}

func (s *Server) writeJSON(w http.ResponseWriter, body []byte, contentType string) {
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
