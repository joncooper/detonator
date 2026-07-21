package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// upstream is a thin HTTP client for fetching from real registries. It caps
// response size and time so a hostile or hung upstream can't exhaust the proxy.
type upstream struct {
	hc          *http.Client
	maxBodySize int64
}

func newUpstream() *upstream {
	return &upstream{
		hc:          &http.Client{Timeout: 60 * time.Second},
		maxBodySize: 512 << 20, // 512 MiB ceiling per artifact
	}
}

// fetchResult carries an upstream response body and the headers we forward.
type fetchResult struct {
	body        []byte
	contentType string
	status      int
}

// get fetches url, forwarding the client's Accept header (needed for PyPI
// content negotiation), and returns the fully-read body.
func (u *upstream) get(ctx context.Context, url, accept string) (fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fetchResult{}, err
	}
	req.Header.Set("User-Agent", "detonator-proxy/0.1")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := u.hc.Do(req)
	if err != nil {
		return fetchResult{}, fmt.Errorf("upstream get %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, u.maxBodySize+1))
	if err != nil {
		return fetchResult{}, fmt.Errorf("upstream read %s: %w", url, err)
	}
	if int64(len(body)) > u.maxBodySize {
		return fetchResult{}, fmt.Errorf("upstream body from %s exceeds %d bytes", url, u.maxBodySize)
	}
	return fetchResult{
		body:        body,
		contentType: resp.Header.Get("Content-Type"),
		status:      resp.StatusCode,
	}, nil
}
