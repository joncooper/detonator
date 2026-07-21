package proxy

import (
	"encoding/json"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/joncooper/detonator/internal/verdict"
)

// handlePyPISimple serves the PEP 503 / PEP 691 "simple" index under
// /pypi/simple/. It fetches the upstream project page as JSON, repoints every
// file URL at this proxy, then answers in whichever format the client accepts.
func (s *Server) handlePyPISimple(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/pypi/simple/")
	name := strings.Trim(rest, "/")
	if name == "" {
		http.Error(w, "pypi: full index not served; request /pypi/simple/{package}/", http.StatusNotFound)
		return
	}

	key := "pypi-simple:" + name
	upstreamURL := s.cfg.PyPISimpleUpstream + "/" + name + "/"

	proj, err := s.fetchPyPIProject(r, key, upstreamURL)
	if err != nil {
		http.Error(w, "pypi upstream fetch failed", http.StatusBadGateway)
		return
	}

	if pypiWantsJSON(r.Header.Get("Accept")) {
		body, _ := json.Marshal(proj)
		s.writeJSON(w, body, "application/vnd.pypi.simple.v1+json")
		return
	}
	s.writeHTML(w, renderPyPIHTML(proj))
}

// pypiProject is the PEP 691 project detail document.
type pypiProject struct {
	Meta  map[string]any `json:"meta"`
	Name  string         `json:"name"`
	Files []pypiFile     `json:"files"`
}

type pypiFile struct {
	Filename       string            `json:"filename"`
	URL            string            `json:"url"`
	Hashes         map[string]string `json:"hashes,omitempty"`
	RequiresPython string            `json:"requires-python,omitempty"`
	Yanked         any               `json:"yanked,omitempty"` // bool or string reason
}

// fetchPyPIProject returns the project doc with file URLs already rewritten,
// serving fresh cache when available and falling back to stale on upstream error.
func (s *Server) fetchPyPIProject(r *http.Request, key, upstreamURL string) (pypiProject, error) {
	if m, fresh, err := s.cache.GetMetadata(key); err == nil && fresh {
		var proj pypiProject
		if json.Unmarshal(m.Body, &proj) == nil {
			return proj, nil
		}
	}

	res, err := s.up.get(r.Context(), upstreamURL, "application/vnd.pypi.simple.v1+json")
	if err != nil || res.status != http.StatusOK {
		if m, _, cerr := s.cache.GetMetadata(key); cerr == nil {
			var proj pypiProject
			if json.Unmarshal(m.Body, &proj) == nil {
				return proj, nil
			}
		}
		if err != nil {
			return pypiProject{}, err
		}
		return pypiProject{}, &httpStatusError{res.status}
	}

	var proj pypiProject
	if err := json.Unmarshal(res.body, &proj); err != nil {
		return pypiProject{}, err
	}
	s.rewritePyPIFileURLs(&proj)

	rewritten, _ := json.Marshal(proj)
	if err := s.cache.PutMetadata(key, rewritten, "application/vnd.pypi.simple.v1+json", time.Now().UTC()); err != nil {
		s.log.Warn("pypi metadata cache write failed", "err", err)
	}
	return proj, nil
}

func (s *Server) rewritePyPIFileURLs(proj *pypiProject) {
	oldPrefix := s.cfg.PyPIFilesUpstream + "/"
	newPrefix := s.cfg.PublicURL + "/pypi/files/"
	for i := range proj.Files {
		if strings.HasPrefix(proj.Files[i].URL, oldPrefix) {
			proj.Files[i].URL = newPrefix + strings.TrimPrefix(proj.Files[i].URL, oldPrefix)
		}
	}
}

// renderPyPIHTML produces a PEP 503 page from the project doc, for pip clients
// that don't negotiate the JSON API.
func renderPyPIHTML(proj pypiProject) []byte {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html><head><meta name=\"pypi:repository-version\" content=\"1.0\"><title>Links for ")
	b.WriteString(html.EscapeString(proj.Name))
	b.WriteString("</title></head><body>\n")
	for _, f := range proj.Files {
		href := f.URL
		if h, ok := f.Hashes["sha256"]; ok && !strings.Contains(href, "#") {
			href += "#sha256=" + h
		}
		b.WriteString("<a href=\"")
		b.WriteString(html.EscapeString(href))
		b.WriteString("\"")
		if f.RequiresPython != "" {
			b.WriteString(" data-requires-python=\"")
			b.WriteString(html.EscapeString(f.RequiresPython))
			b.WriteString("\"")
		}
		b.WriteString(">")
		b.WriteString(html.EscapeString(f.Filename))
		b.WriteString("</a><br/>\n")
	}
	b.WriteString("</body></html>\n")
	return []byte(b.String())
}

// handlePyPIFiles serves package files under /pypi/files/, routing each through
// the admission gate.
func (s *Server) handlePyPIFiles(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/pypi/files/")
	if rest == "" {
		http.Error(w, "pypi: missing file path", http.StatusNotFound)
		return
	}
	filename := rest
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		filename = rest[i+1:]
	}
	name, version := pypiNameVersionFromFile(filename)
	upstreamURL := s.cfg.PyPIFilesUpstream + "/" + rest
	s.serveArtifact(w, r, verdict.PyPI, name, version, upstreamURL, "application/octet-stream")
}

// pypiNameVersionFromFile makes a best-effort split of a wheel or sdist filename
// into project name and version, for labeling. Exact PEP 427/625 parsing isn't
// needed — the digest is the identity, this is only for readable logs.
func pypiNameVersionFromFile(filename string) (name, version string) {
	switch {
	case strings.HasSuffix(filename, ".whl"):
		// name-version-pytag-abitag-plat.whl
		parts := strings.Split(strings.TrimSuffix(filename, ".whl"), "-")
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
		return strings.TrimSuffix(filename, ".whl"), ""
	case strings.HasSuffix(filename, ".tar.gz"):
		base := strings.TrimSuffix(filename, ".tar.gz")
		if i := strings.LastIndex(base, "-"); i >= 0 {
			return base[:i], base[i+1:]
		}
		return base, ""
	default:
		return filename, ""
	}
}

func (s *Server) writeHTML(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func pypiWantsJSON(accept string) bool {
	return strings.Contains(accept, "application/vnd.pypi.simple.v1+json") ||
		strings.Contains(accept, "application/json")
}

type httpStatusError struct{ status int }

func (e *httpStatusError) Error() string { return "upstream status " + http.StatusText(e.status) }
