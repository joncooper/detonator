package behavior

import (
	"testing"

	"github.com/joncooper/detonator/internal/verdict"
)

// These tests use hand-built synthetic traces representing general threat
// classes — not copied from any real corpus sample — so the rules are validated
// against the shape of an attack, not memorized indicators.

func rules(sigs []verdict.Signal) map[string]verdict.Severity {
	m := map[string]verdict.Severity{}
	for _, s := range sigs {
		m[s.Rule] = s.Severity
	}
	return m
}

func TestBenignTraceNoSignals(t *testing.T) {
	tr := &Trace{Analysis: map[string]Phase{
		"install": {
			Files:   []FileOp{{Path: "/app/node_modules/foo/index.js", Read: true}, {Path: "/tmp/x", Write: true}},
			Sockets: []Socket{{Address: "8.8.8.8", Port: 53}},
			DNS:     []DNSRecord{{Queries: []DNSQuery{{Hostname: "registry.npmjs.org"}}}},
		},
	}}
	if sigs := Analyze(verdict.NPM, tr); len(sigs) != 0 {
		t.Fatalf("benign trace produced signals: %+v", sigs)
	}
}

func TestCredentialStealerShape(t *testing.T) {
	tr := &Trace{Analysis: map[string]Phase{
		"install": {
			Files: []FileOp{
				{Path: "/root/.aws/credentials", Read: true},
				{Path: "/root/.npmrc", Read: true},
			},
			Commands: []Command{{Command: []string{"sh", "-c", "curl -sf http://169.254.169.254/latest/api/token"}}},
			Sockets:  []Socket{{Address: "169.254.169.254", Port: 80}},
			DNS:      []DNSRecord{{Queries: []DNSQuery{{Hostname: "exfil.example-c2.tld"}}}},
		},
	}}
	got := rules(Analyze(verdict.NPM, tr))
	for _, want := range []string{"sensitive-read:aws-credentials", "sensitive-read:npm-token", "cloud-metadata-access", "unknown-domain", "process-spawn", "exfil-chain"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing rule %q; got %+v", want, got)
		}
	}
	if got["cloud-metadata-access"] != verdict.SevCritical || got["exfil-chain"] != verdict.SevCritical {
		t.Errorf("metadata/exfil should be critical: %+v", got)
	}
}

func TestEtcPasswdIsLowNotHigh(t *testing.T) {
	// /etc/passwd read is common in benign code (user lookups); keep it low to
	// preserve precision.
	tr := &Trace{Analysis: map[string]Phase{"import": {Files: []FileOp{{Path: "/etc/passwd", Read: true}}}}}
	got := rules(Analyze(verdict.NPM, tr))
	if got["sensitive-read:etc-passwd"] != verdict.SevLow {
		t.Fatalf("etc-passwd should be low, got %v", got)
	}
	// A lone /etc/passwd read must NOT trigger the exfil chain.
	if _, ok := got["exfil-chain"]; ok {
		t.Fatal("lone /etc/passwd read wrongly triggered exfil-chain")
	}
}

func TestSystemConfigReadsNotFlagged(t *testing.T) {
	// npm reads its own config on every install; benign packages must not be
	// flagged for it. Only home-dir credential dotfiles count.
	tr := &Trace{Analysis: map[string]Phase{"install": {Files: []FileOp{
		{Path: "/usr/lib/node_modules/npm/npmrc", Read: true},
		{Path: "/usr/etc/npmrc", Read: true},
		{Path: "/app/.npmrc", Read: true},
	}}}}
	if sigs := Analyze(verdict.NPM, tr); len(sigs) != 0 {
		t.Fatalf("system/project config reads wrongly flagged: %+v", sigs)
	}
	// But a home-dir .npmrc (holds the auth token) IS flagged.
	home := &Trace{Analysis: map[string]Phase{"install": {Files: []FileOp{{Path: "/root/.npmrc", Read: true}}}}}
	if _, ok := rules(Analyze(verdict.NPM, home))["sensitive-read:npm-token"]; !ok {
		t.Fatal("home .npmrc should be flagged")
	}
}

func TestKnownRegistryEgressNotFlagged(t *testing.T) {
	tr := &Trace{Analysis: map[string]Phase{"install": {DNS: []DNSRecord{{Queries: []DNSQuery{
		{Hostname: "registry.npmjs.org"}, {Hostname: "files.pythonhosted.org"},
	}}}}}}
	// npm registry must be clean for npm; pythonhosted is unknown for an npm pkg.
	got := rules(Analyze(verdict.NPM, tr))
	if _, ok := got["unknown-domain"]; !ok {
		t.Fatal("pythonhosted should be unknown for an npm package")
	}
	// For pypi, pythonhosted is whitelisted.
	got2 := rules(Analyze(verdict.PyPI, &Trace{Analysis: map[string]Phase{"install": {DNS: []DNSRecord{{Queries: []DNSQuery{{Hostname: "files.pythonhosted.org"}}}}}}}))
	if _, ok := got2["unknown-domain"]; ok {
		t.Fatal("pythonhosted should be whitelisted for pypi")
	}
}
