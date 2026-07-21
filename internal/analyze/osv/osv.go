// Package osv queries the OSV.dev database for known vulnerabilities affecting
// an exact package version. It runs before detonation so a package can be
// blocked on CVE grounds cheaply, without ever executing it (build-plan §3).
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/joncooper/detonator/internal/verdict"
)

// Client queries an OSV API endpoint.
type Client struct {
	baseURL string
	hc      *http.Client
}

// New returns a client for the given OSV base URL (e.g. https://api.osv.dev).
func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		hc:      &http.Client{Timeout: 20 * time.Second},
	}
}

type queryReq struct {
	Version string      `json:"version"`
	Package queryReqPkg `json:"package"`
}
type queryReqPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type queryResp struct {
	Vulns []vuln `json:"vulns"`
}
type vuln struct {
	ID               string `json:"id"`
	Summary          string `json:"summary"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// Query returns one signal per known vulnerability at art's exact version. A
// transport error is returned to the caller, which should treat OSV as
// "unknown" rather than failing the verdict.
func (c *Client) Query(ctx context.Context, art verdict.Artifact) ([]verdict.Signal, error) {
	eco, ok := ecosystem(art.Ecosystem)
	if !ok {
		return nil, fmt.Errorf("osv: unsupported ecosystem %q", art.Ecosystem)
	}
	body, err := json.Marshal(queryReq{
		Version: art.Version,
		Package: queryReqPkg{Name: art.Name, Ecosystem: eco},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: status %d", resp.StatusCode)
	}

	var qr queryResp
	if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
		return nil, fmt.Errorf("osv: decode: %w", err)
	}

	sigs := make([]verdict.Signal, 0, len(qr.Vulns))
	for _, v := range qr.Vulns {
		sigs = append(sigs, verdict.Signal{
			Stage:       "osv",
			Rule:        v.ID,
			Severity:    severityOf(v),
			Description: knownVulnDesc(v),
			Evidence:    v.ID,
		})
	}
	return sigs, nil
}

func ecosystem(e verdict.Ecosystem) (string, bool) {
	switch e {
	case verdict.NPM:
		return "npm", true
	case verdict.PyPI:
		return "PyPI", true
	default:
		return "", false
	}
}

// severityOf maps an OSV vuln to a Detonator severity, preferring the database's
// own label and falling back to the CVSS base score band.
func severityOf(v vuln) verdict.Severity {
	switch strings.ToUpper(v.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return verdict.SevCritical
	case "HIGH":
		return verdict.SevHigh
	case "MODERATE", "MEDIUM":
		return verdict.SevMedium
	case "LOW":
		return verdict.SevLow
	}
	if band, ok := cvssBand(v); ok {
		return band
	}
	return verdict.SevMedium // known-vuln with no rated severity: don't ignore it
}

// cvssBand extracts a severity band from a CVSS base score if the vector encodes
// one directly; a full CVSS parse isn't warranted here.
func cvssBand(v vuln) (verdict.Severity, bool) {
	for _, s := range v.Severity {
		if strings.HasPrefix(strings.ToUpper(s.Type), "CVSS") {
			// The score field is a vector string; we don't recompute the base
			// score. Treat presence of a CVSS entry without a DB label as high,
			// since OSV only records scored, confirmed vulns.
			return verdict.SevHigh, true
		}
	}
	return "", false
}

func knownVulnDesc(v vuln) string {
	if v.Summary != "" {
		return "known vulnerability " + v.ID + ": " + v.Summary
	}
	return "known vulnerability " + v.ID
}
