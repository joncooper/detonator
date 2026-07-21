// Package config holds runtime configuration for the Detonator proxy.
package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Config is the proxy's runtime configuration. Zero value is not valid; use
// Default and override.
type Config struct {
	// Listen is the address the proxy binds, e.g. "127.0.0.1:8080".
	Listen string
	// PublicURL is how clients reach this proxy, e.g. "http://127.0.0.1:8080".
	// It is used to rewrite upstream artifact URLs so downloads route back
	// through the admission gate. Must not have a trailing slash.
	PublicURL string
	// CacheDir is the on-disk root for cached artifacts, metadata, and verdicts.
	CacheDir string

	// Upstream registry endpoints. Overridable for testing against mirrors.
	NPMUpstream        string // npm registry base, e.g. https://registry.npmjs.org
	PyPISimpleUpstream string // PyPI simple index base, e.g. https://pypi.org/simple
	PyPIFilesUpstream  string // PyPI file host, e.g. https://files.pythonhosted.org

	// MetadataTTL bounds how long a cached packument / simple-index is served
	// before revalidation, in seconds. Package *metadata* changes as new
	// versions publish; artifact *bytes* never do.
	MetadataTTLSeconds int
}

// Default returns a config suitable for local single-user use.
func Default() Config {
	return Config{
		Listen:             "127.0.0.1:8080",
		PublicURL:          "http://127.0.0.1:8080",
		CacheDir:           "./.detonator-cache",
		NPMUpstream:        "https://registry.npmjs.org",
		PyPISimpleUpstream: "https://pypi.org/simple",
		PyPIFilesUpstream:  "https://files.pythonhosted.org",
		MetadataTTLSeconds: 300,
	}
}

// Validate checks the config is internally consistent and normalizes it.
func (c *Config) Validate() error {
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	c.NPMUpstream = strings.TrimRight(c.NPMUpstream, "/")
	c.PyPISimpleUpstream = strings.TrimRight(c.PyPISimpleUpstream, "/")
	c.PyPIFilesUpstream = strings.TrimRight(c.PyPIFilesUpstream, "/")

	for name, raw := range map[string]string{
		"public-url":   c.PublicURL,
		"npm-upstream": c.NPMUpstream,
		"pypi-simple":  c.PyPISimpleUpstream,
		"pypi-files":   c.PyPIFilesUpstream,
	} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("config: %s is not an absolute URL: %q", name, raw)
		}
	}
	if c.Listen == "" {
		return fmt.Errorf("config: listen address is empty")
	}
	if c.CacheDir == "" {
		return fmt.Errorf("config: cache dir is empty")
	}
	if c.MetadataTTLSeconds < 0 {
		return fmt.Errorf("config: metadata TTL must be >= 0")
	}
	return nil
}
