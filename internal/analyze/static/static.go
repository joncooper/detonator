// Package static is Detonator's cheap first-pass analyzer. It inspects unpacked
// artifact bytes — never executing them — for the patterns that precede most
// commodity supply-chain attacks: install-time scripts that reach the network
// or spawn shells, setup.py that runs code at build time, obfuscated blobs, and
// embedded secrets. It is fast enough to fast-block obvious cases before the
// expensive detonation stage (build-plan §3).
package static

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/joncooper/detonator/internal/artifact"
	"github.com/joncooper/detonator/internal/verdict"
)

// Analyze returns the static signals for an unpacked artifact.
func Analyze(art verdict.Artifact, u *artifact.Unpacked) []verdict.Signal {
	var sigs []verdict.Signal
	switch art.Ecosystem {
	case verdict.NPM:
		sigs = append(sigs, npmInstallScripts(u)...)
	case verdict.PyPI:
		sigs = append(sigs, pySetupExecution(u)...)
	}
	sigs = append(sigs, scanContents(u)...)
	return sigs
}

var (
	// Shell/exec danger tokens that make an install hook or setup script
	// suspicious rather than routine.
	// Note: bare `node -e` / `python -c` are NOT here — they are dual-use (e.g.
	// core-js's benign funding postinstall); a malicious inline command still
	// trips curl/wget/base64/etc. below.
	dangerToken = regexp.MustCompile(`(?i)(\bcurl\b|\bwget\b|/dev/tcp|base64\s+-d|base64\s+--decode|\|\s*(ba)?sh\b|chmod\s+\+x|\bnc\b|powershell|invoke-expression|mshta|certutil)`)

	// pyNetCall is a Python network CALL made at install time (download/exfil) — a
	// urlopen/requests/socket connect, NOT a benign url= metadata field in setup().
	// Benign setup.py runs build code (subprocess/compile/exec-of-version-file); it
	// is a network or shell-danger action that distinguishes a malicious one.
	// Require an actual network CALL, not a bare module import: `import http.client`
	// and `httplib` mentions are benign and false-positived on aiohttp/awscli/google-*.
	pyNetCall = regexp.MustCompile(`(?i)(urllib\.request\.urlopen|urllib\.urlopen|\burlopen\s*\(|requests\.(get|post|put|patch|head|delete|request)\s*\(|httpx\.(get|post|request|Client)\s*\(|http\.client\.(HTTP|HTTPS)Connection\s*\(|httplib\.(HTTP|HTTPS)|ftplib\.FTP\s*\(|smtplib\.SMTP\s*\(|urllib3\.(PoolManager|HTTPConnection)|socket\.socket\s*\([^)]*\)[\s\S]{0,120}?\.connect\s*\(|\.connect\s*\(\s*\()`)

	// netRoleBefore matches a network-role assignment/call immediately preceding a
	// quoted IP — the shape of an actual endpoint (hostname:'1.2.3.4', connect('..')).
	// Requiring this (rather than any network word nearby) keeps version strings
	// ("3.5.0.1"), OIDs (ObjectIdentifier("1.2.3.4")), and test placeholders — all
	// of which parse as public IPs and often sit near network code — from reading as
	// a hardcoded C2. The trailing $ anchors to the char just before the IP's quote.
	netRoleBefore = regexp.MustCompile(`(?i)\b(hostname|host|server|proxy|remote|target|endpoint|addr|address|connect|createconnection|dial)\s*[:=(\[]\s*$`)

	urlOrIP = regexp.MustCompile(`(https?://[^\s"'` + "`" + `]+)|(\b(?:\d{1,3}\.){3}\d{1,3}\b)`)

	awsKey        = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	privateKey    = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)
	genericSecret = regexp.MustCompile(`(?i)(secret|token|api[_-]?key|password|passwd)['"]?\s*[:=]\s*['"][A-Za-z0-9/+_\-]{16,}['"]`)

	// dynExecDecoded flags exec/eval/interpreter-`-c` applied to decoded content
	// (base64/atob/unescape/fromCharCode) — the canonical obfuscated-payload
	// shape. Benign code rarely executes freshly-decoded bytes.
	dynExecDecoded = regexp.MustCompile("(?is)(exec\\s*\\(|eval\\s*\\(|new\\s+Function\\s*\\(|[\"'`]\\s*-[ce]\\b)[^\\n;]{0,200}?(b64decode|atob\\s*\\(|unescape\\s*\\(|fromCharCode|Buffer\\.from\\([^)\\n]*base64)")

	// b64Literal finds quoted base64-looking string literals (candidate hidden endpoints).
	b64Literal = regexp.MustCompile("[\"'`]([A-Za-z0-9+/]{24,}={0,2})[\"'`]")

	// quotedIPv4 requires the IP to be a string literal (a connection target),
	// not an IP mentioned in a comment/docstring, keeping the rule precise.
	quotedIPv4   = regexp.MustCompile("[\"'`](\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})[\"'`]")
	netPrimitive = regexp.MustCompile(`(?i)(https?\.request|\.request\s*\(|fetch\s*\(|new\s+WebSocket|net\.(connect|Socket)|socket\.socket|urllib|requests\.(get|post)|\.connect\s*\(|XMLHttpRequest|axios|curl |wget |require\(['"](https?|net|dgram|tls|ws)['"]\))`)

	// --- reverse-shell / RAT source signatures (family: reverse shell / RAT) ---
	// Tier A: canonical connect-back idioms as literal source text. These strings
	// are near-absent from benign package source.
	revShellIdiom = regexp.MustCompile(`(?i)(/dev/(tcp|udp)/|(ba)?sh\s+-i\b[^\n]*(>&|0>&1|>\s*/dev/tcp)|\b(nc|ncat)\b[^\n|]*\s-[ce]\b|mkfifo\b[^\n]*\|\s*(ba)?sh|socat\b[^\n]*(exec|system):)`)
	// Tier B: language-native socket-to-shell wiring. Fires only on the triple of
	// a connect-back primitive, a file-descriptor binding, and a shell target in
	// one file — benign clients open sockets and even spawn shells, but never bind
	// a socket's fd onto a shell's stdio.
	revShellConnect = regexp.MustCompile(`(?i)(net\.(connect|Socket)\s*\(|socket\.socket\s*\(|\.connect\s*\()`)
	revShellBind    = regexp.MustCompile(`(?i)(os\.dup2\s*\(|\bdup2\s*\(|stdio\s*:\s*\[)`)
	revShellTarget  = regexp.MustCompile(`(?i)(/bin/(ba)?sh|pty\.spawn\s*\(|cmd\.exe)`)

	// --- cryptominer bundled-artifact signatures (family: cryptominer) ---
	// A literal stratum pool scheme is sufficient on its own (near-zero benign FP).
	stratumScheme = regexp.MustCompile(`(?i)stratum\+(tcp|ssl)://`)
	minerBinary   = regexp.MustCompile(`(?i)\b(xmrig|xmr-stak|minerd|cpuminer|cgminer|bfgminer|ethminer|phoenixminer|nbminer|t-rex|lolminer|gminer|teamredminer|ccminer|xmrminer)\b`)
	minerConfig   = regexp.MustCompile(`(?i)(randomx|cryptonight|--donate-level|--nicehash|--coin\b)`)

	// --- destructive / wiper signatures (family: wiper / destructive) ---
	// Precision-first: every branch requires a SYSTEM root, a device, a format
	// verb, or a home-directory reference. Benign build idioms (rm -rf dist /
	// build / node_modules, fs.rmSync('build'), shutil.rmtree('build')) never
	// match. Mirrors behavior.go's destructiveCmd, lifted into the static stage.
	destructiveToken = regexp.MustCompile(`(?is)(rm\s+-[rf]{1,2}[a-z]*\s+(--no-preserve-root|/($|\s|"|'|\*|root|home|etc|usr|var|bin|boot|lib)|~(/|\s|$)|\$HOME)|\bmkfs\b|\bdd\b[^|\n]*of=/dev/|>\s*/dev/sd|\bshred\b[^|\n]*(/dev/|/root|/home)|\b(rmSync|rmdirSync)\s*\([\s\S]{0,80}?(os\.homedir|homedir\s*\(\s*\)|process\.env\.HOME|['"]\s*/\s*['"])|shutil\.rmtree\s*\([\s\S]{0,80}?(expanduser|os\.environ|environ\[|['"]\s*/\s*['"]))`)

	// --- install-time env/credential stealer (family: install-hook env stealer) ---
	// Bulk serialization of the WHOLE environment — never a single named var. This
	// is the benign-distinguishing trait: benign code reads process.env.FOO
	// constantly but essentially never ships the entire env.
	bulkEnvSerialize = regexp.MustCompile(`(?i)(JSON\.stringify\s*\(\s*process\.env|Object\.(keys|entries|values)\s*\(\s*process\.env|\{\s*\.\.\.process\.env|dict\s*\(\s*os\.environ|os\.environ\.copy\s*\(|json\.dumps\s*\(\s*(dict\s*\(\s*)?os\.environ|str\s*\(\s*(dict\s*\(\s*)?os\.environ)`)

	// envExfilSend requires the whole-env serialization to be the payload of a
	// network SEND (a request body/data), not merely co-located with a network
	// primitive. This is the exfil-distinguishing trait: benign code spreads
	// {...process.env} into a subprocess (esbuild) or reads dict(os.environ)
	// locally (click); malware puts the serialized env inside a POST/send/body.
	envExfilSend = regexp.MustCompile(`(?is)(\.(post|put|send|write|end)\s*\(|\b(body|data|json)\s*[:=]\s*)[^;\n]{0,40}?(JSON\.stringify\s*\(\s*process\.env|\{\s*\.\.\.\s*process\.env|Object\.(keys|entries|values)\s*\(\s*process\.env|(str|json\.dumps)\s*\(\s*(dict\s*\(\s*)?os\.environ|dict\s*\(\s*os\.environ)`)

	// scriptFileToken extracts a local script path referenced by an install hook
	// command (e.g. `node collect.js` -> collect.js), used to escalate a harvest
	// that runs at install time.
	scriptFileToken = regexp.MustCompile(`[\w./@-]+\.(?:js|cjs|mjs|ts)`)

	// quotedStr matches a Python/JS string literal (triple- or single-quoted,
	// escape-aware). Used to blank long inlined docstrings/READMEs in setup.py so
	// their code EXAMPLES (`requests.get(url)`) don't read as install-time calls.
	quotedStr = regexp.MustCompile(`(?s)""".*?"""|'''.*?'''|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)

	// --- javascript-obfuscator fingerprint (family: obfuscated loader) ---
	// hexIdent matches the _0x-hexadecimal identifiers that javascript-obfuscator
	// (obfuscator.io) renames every symbol to. Benign minifiers (terser, esbuild,
	// webpack) rename to short alphanumerics (a, e, _t, $), never _0x-hex, so a
	// dense cluster of these is a precise obfuscation signal — distinct from
	// ordinary minification, which stays informational.
	hexIdent = regexp.MustCompile(`_0x[0-9a-fA-F]{4,}`)

	// --- host/identity reconnaissance (family: recon exfil) ---
	// Identity primitives that answer "who/where am I". Deliberately excludes the
	// ubiquitous process.platform / process.env.HOME (benign code reads those
	// constantly); requires the more identity-specific calls, ≥2 distinct, plus a
	// network sink, so a lone hostname read never fires.
	hostRecon = regexp.MustCompile(`(?i)(\bos\.hostname\s*\(|\bos\.userInfo\s*\(|\bos\.networkInterfaces\s*\(|process\.env\.(USER|USERNAME|LOGNAME|HOSTNAME)\b|socket\.gethostname\s*\(|getpass\.getuser\s*\(|platform\.uname\s*\(|\bwhoami\b)`)

	// --- Python string-escape obfuscation (family: obfuscated loader) ---
	// pyEscEval matches eval/exec/compile applied directly to a string literal of
	// octal/hex escape sequences — the shape emitted by BlankOBF, Hyperion, and
	// hand-rolled Python packers (`eval("\145\166\x61\x6c")`). Benign Python never
	// eval()s an escape-encoded string, so this is a near-zero-FP fingerprint. The
	// JS `_0x` detector (hexObfuscated) does not cover it; without it the whole
	// BlankOBF stealer family (keyauthkey, axelo, robloxlogger, …) scores allow.
	pyEscEval = regexp.MustCompile(`(?i)(eval|exec|compile)\s*\(\s*["'](\\x[0-9a-f]{2}|\\[0-3][0-7]{2}){2,}`)
	// escSeq counts backslash byte-escapes; pyDynExec is a dynamic-code primitive.
	// A file dominated by escape bytes AND calling one is an encoded blob even when
	// the eval is one indirection removed from the literal.
	escSeq    = regexp.MustCompile(`\\x[0-9a-fA-F]{2}|\\[0-3][0-7]{2}`)
	pyDynExec = regexp.MustCompile(`(?i)\b(eval|exec|compile|marshal\.loads|__import__)\s*\(`)

	// --- shell reconnaissance/exfil in an exec'd command (family: recon exfil) ---
	// shellRecon: identity/credential recon expressed as shell (distinct from the
	// JS/Python host primitives in hostRecon) — `$(whoami)`, /etc/passwd, ssh keys.
	// shellExfil: the command also ships bytes out (curl/wget/nc/http/base64). Fires
	// only in install context; a benign install hook never reads /etc/shadow and
	// pipes it to a remote host. Recovers the postinstall→exec(curl … recon) beacon
	// family (oast.fun/interactsh collaborators) that hostReconExfil misses.
	shellRecon = regexp.MustCompile(`(?i)(\$\(\s*(whoami|hostname|id)\s*\)|\bwhoami\b|/etc/(passwd|shadow)\b|\buname\s+-a\b|~/\.ssh/|\.aws/credentials|\.ssh/id_(rsa|ed25519))`)
	shellExfil = regexp.MustCompile(`(?i)(\bcurl\b|\bwget\b|\bncat?\b|https?://|base64\s+-?w?)`)

	// hardcodedWebhook: a Discord webhook or Telegram bot endpoint carrying a real
	// id+token — the canonical token/cookie-stealer exfil sink. A full snowflake id
	// plus token keeps bare API-doc mentions out; benign packages essentially never
	// embed one. Recovers the Discord/Telegram stealer family (xoloctwuaywkna, …).
	hardcodedWebhook = regexp.MustCompile(`(?i)(discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d{17,20}/[\w-]{24,}|api\.telegram\.org/bot\d{6,}:[\w-]{30,})`)
)

// npmInstallScripts flags install lifecycle hooks in package.json. A hook alone
// is only mildly interesting (many legit packages build native code); a hook
// that shells out or reaches the network is the classic attack and blocks.
func npmInstallScripts(u *artifact.Unpacked) []verdict.Signal {
	f := u.Lookup("package.json")
	if f == nil {
		return nil
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(f.Content, &pkg); err != nil {
		return nil
	}
	var sigs []verdict.Signal
	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		cmd, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}
		switch {
		case destructiveToken.MatchString(cmd):
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "destructive-payload", Severity: verdict.SevCritical,
				Description: "install hook '" + hook + "' runs a destructive/wiper command",
				Evidence:    truncate(cmd, 200),
			})
		case dangerToken.MatchString(cmd):
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "npm-install-hook-danger", Severity: verdict.SevCritical,
				Description: "install hook '" + hook + "' runs a shell/exec danger pattern",
				Evidence:    truncate(cmd, 200),
			})
		case urlOrIP.MatchString(cmd):
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "npm-install-hook-network", Severity: verdict.SevHigh,
				Description: "install hook '" + hook + "' references a URL or IP",
				Evidence:    truncate(cmd, 200),
			})
		default:
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "npm-install-hook", Severity: verdict.SevLow,
				Description: "package defines install hook '" + hook + "'",
				Evidence:    truncate(cmd, 200),
			})
		}
	}
	return sigs
}

// pySetupExecution flags setup.py that runs code at build/install time. Modern
// packaging prefers declarative metadata; an imperative setup.py that spawns
// processes or reaches the network is a red flag.
func pySetupExecution(u *artifact.Unpacked) []verdict.Signal {
	var sigs []verdict.Signal
	for _, name := range []string{"setup.py", "setup.cfg"} {
		f := u.Lookup(name)
		if f == nil {
			continue
		}
		// Scan with long string literals blanked: setup.py routinely inlines the
		// README into long_description, whose code examples (`requests.get(url)`,
		// `rm -rf`) are documentation, not install-time actions (false-positived on
		// backoff). Real install code is not inside a string, so it survives.
		code := stripLongLiterals(f.Content)
		// A wiper whose only act is shutil.rmtree('/') or expanduser('~') is
		// unambiguously destructive at install time.
		if destructiveToken.Match(code) {
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "destructive-payload", Severity: verdict.SevCritical,
				Description: name + " runs a destructive/wiper command at install time",
				Evidence:    firstMatch(destructiveToken, code),
			})
		}
		// Benign setup.py routinely runs code at build time (subprocess to compile,
		// exec(open('_version.py').read()), a homepage url= in setup() metadata), so
		// mere execution is NOT a signal — flagging it false-positived on numpy /
		// setuptools / boto3. Fire only when the install-time code takes a genuinely
		// dangerous action: a network CALL (download/exfil), a shell danger token, or
		// exec/eval of decoded content.
		if pyNetCall.Match(code) || dangerToken.Match(code) || dynExecDecoded.Match(code) {
			ev := firstMatch(pyNetCall, code)
			if ev == "" {
				ev = firstMatch(dangerToken, code)
			}
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "py-setup-execution", Severity: verdict.SevCritical,
				Description: name + " performs a network/shell/exec-of-decoded action at install time",
				Evidence:    ev,
			})
		}
	}
	return sigs
}

// scanContents runs content-level heuristics across every text-ish file:
// secrets, obfuscation, dynamic-exec-of-decoded payloads, and encoded network
// indicators.
func scanContents(u *artifact.Unpacked) []verdict.Signal {
	var sigs []verdict.Signal
	seenSecret := false
	seenExec := false
	seenEncoded := false
	seenHardIP := false
	seenRevShell := false
	seenMiner := false
	seenDestructive := false
	seenEnvExfil := false
	seenHostRecon := false
	seenObfCode := false
	seenWebhook := false
	hookTargets := npmHookTargets(u)
	for i := range u.Files {
		f := &u.Files[i]
		if isBinary(f.Content) {
			continue
		}
		// SBOM manifests (CycloneDX/SPDX, shipped under .dist-info/sboms/ per
		// PEP 770) are declarative provenance metadata, never executed. They
		// routinely embed base64 provenance data — git commit logs, diffs,
		// pedigree — that decodes to text containing URLs, which is not a
		// payload. Scanning them as source produces false positives (e.g. a
		// git-log blob tripping encoded-network-indicator), so skip them.
		if isSBOM(f.Path) {
			continue
		}
		content := f.Content

		// Dynamic execution of decoded content: exec/eval/interpreter-`-c` over
		// base64/atob/unescape output. Benign code rarely does this; it is the
		// canonical obfuscated-payload shape (matches GuardDog's rules).
		if !seenExec && !isTestOrDoc(f.Path) && !isDataConfig(f.Path) && dynExecDecoded.Match(content) {
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "dynamic-exec-decoded", Severity: verdict.SevCritical,
				Description: "executes dynamically-decoded code (exec/eval of base64/atob output)",
				Evidence:    f.Path + ": " + firstMatch(dynExecDecoded, content),
			})
			seenExec = true
		}

		// A public IP literal used alongside a network primitive — a hardcoded
		// C2 endpoint. Benign packages reach named services, not raw public IPs.
		if !seenHardIP && !isTestOrDoc(f.Path) {
			if ip, ok := hardcodedPublicEndpoint(content); ok {
				sigs = append(sigs, verdict.Signal{
					Stage: "static", Rule: "hardcoded-ip-endpoint", Severity: verdict.SevHigh,
					Description: "source contacts a hardcoded public IP address",
					Evidence:    f.Path + ": " + ip,
				})
				seenHardIP = true
			}
		}

		// Base64 literals that decode to a URL or raw IP — a hidden C2/endpoint.
		// Skip test/doc/example/data files (awscli ships base64 SVGs in .rst examples).
		if !seenEncoded && !isTestOrDoc(f.Path) {
			if dec, ok := decodedNetworkIndicator(content); ok {
				sigs = append(sigs, verdict.Signal{
					Stage: "static", Rule: "encoded-network-indicator", Severity: verdict.SevHigh,
					Description: "base64 literal decodes to a network endpoint (hidden C2)",
					Evidence:    f.Path + ": " + truncate(dec, 120),
				})
				seenEncoded = true
			}
		}

		// Secrets in test fixtures, docs, and data/config are placeholders or schema,
		// not leaks in executable code (requests ships test certs; boto3's docs use
		// AWS's own AKIA…EXAMPLE key; litellm's provider-fields .json declares key
		// fields), so scan only real source.
		if !seenSecret && !isTestOrDoc(f.Path) && !isDataConfig(f.Path) {
			if privateKey.Match(content) {
				sigs = append(sigs, verdict.Signal{
					Stage: "static", Rule: "embedded-private-key", Severity: verdict.SevMedium,
					Description: "embedded private key material", Evidence: f.Path,
				})
				seenSecret = true
			} else if m := awsKey.Find(content); m != nil && !strings.HasSuffix(string(m), "EXAMPLE") {
				sigs = append(sigs, verdict.Signal{
					Stage: "static", Rule: "embedded-aws-key", Severity: verdict.SevMedium,
					Description: "embedded AWS access key id", Evidence: f.Path + ": " + string(m),
				})
				seenSecret = true
			} else if genericSecret.Match(content) {
				sigs = append(sigs, verdict.Signal{
					Stage: "static", Rule: "embedded-secret", Severity: verdict.SevLow,
					Description: "possible hardcoded credential", Evidence: f.Path,
				})
				seenSecret = true
			}
		}

		// Reverse-shell / RAT payload sitting in ordinary source (family: reverse
		// shell / RAT). Tier A literal idioms, or Tier B socket-fd-to-shell wiring.
		// Both shapes are unambiguously malicious, so Critical. Skip test/doc.
		if !seenRevShell && !isTestOrDoc(f.Path) && !isVendoredBundle(f.Path) && !isDataConfig(f.Path) {
			if revShellIdiom.Match(content) {
				sigs = append(sigs, verdict.Signal{
					Stage: "static", Rule: "reverse-shell-source", Severity: verdict.SevCritical,
					Description: "source contains a reverse-shell idiom (connect-back to a shell)",
					Evidence:    f.Path + ": " + firstMatch(revShellIdiom, content),
				})
				seenRevShell = true
			} else if revShellConnect.Match(content) && revShellBind.Match(content) && revShellTarget.Match(content) {
				sigs = append(sigs, verdict.Signal{
					Stage: "static", Rule: "reverse-shell-source", Severity: verdict.SevCritical,
					Description: "source binds a network socket to a shell's stdio (reverse shell)",
					Evidence:    f.Path + ": " + firstMatch(revShellTarget, content),
				})
				seenRevShell = true
			}
		}

		// Bundled cryptominer artifact (family: cryptominer). A stratum pool scheme
		// alone is sufficient; a miner binary name needs a config/algo token to
		// fire (skipping prose so docs about miners don't trip the binary path).
		if !seenMiner {
			if stratumScheme.Match(content) ||
				(!isTestOrDoc(f.Path) && minerBinary.Match(content) && minerConfig.Match(content)) {
				sigs = append(sigs, verdict.Signal{
					Stage: "static", Rule: "cryptominer-artifact", Severity: verdict.SevHigh,
					Description: "bundles a cryptominer config/artifact (stratum pool / miner binary)",
					Evidence:    f.Path,
				})
				seenMiner = true
			}
		}

		// Destructive / wiper payload in ordinary source (family: wiper). High in
		// general source (may be conditional/time-bombed); the install-hook and
		// setup.py contexts are graded Critical separately.
		if !seenDestructive && !isTestOrDoc(f.Path) && !isBuildTooling(f.Path) && !isDataConfig(f.Path) &&
			!isVendoredBundle(f.Path) && baseName(f.Path) != "package.json" && !isSetupFile(f.Path) && destructiveToken.Match(content) {
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "destructive-payload", Severity: verdict.SevHigh,
				Description: "source contains a destructive filesystem/disk operation (wiper)",
				Evidence:    f.Path + ": " + firstMatch(destructiveToken, content),
			})
			seenDestructive = true
		}

		// Bulk environment/credential harvest co-located with a network sink
		// (family: install-hook env stealer). High by default; Critical when the
		// harvest runs at install time (an npm hook target, or setup.py).
		if !seenEnvExfil && !isTestOrDoc(f.Path) && envExfilSend.Match(content) {
			sev := verdict.SevHigh
			desc := "serializes the whole environment into a network send (env exfil)"
			if hookTargets[baseName(f.Path)] || isSetupFile(f.Path) {
				sev = verdict.SevCritical
				desc = "install-time harvest: serializes the whole environment to a network sink"
			}
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "install-env-exfil", Severity: sev,
				Description: desc, Evidence: f.Path + ": " + firstMatch(bulkEnvSerialize, content),
			})
			seenEnvExfil = true
		}

		// Host/identity reconnaissance sent to the network, at INSTALL TIME only
		// (family: recon exfil). Reading host/user identity + connecting is the normal
		// job of DB drivers, HTTP clients, and browser automation (asyncpg, playwright)
		// — so at runtime it is not a signal. It only reads as recon when it runs
		// during install: an npm hook target or a setup script. This keeps the
		// login-paypal catch (a postinstall hook) while clearing the runtime-lib FPs.
		if !seenHostRecon && (hookTargets[baseName(f.Path)] || isSetupFile(f.Path)) &&
			!isTestOrDoc(f.Path) && !isVendoredBundle(f.Path) &&
			(hostReconExfil(content) || shellReconExfil(content)) {
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "host-recon-exfil", Severity: verdict.SevHigh,
				Description: "install-time recon: collects host/user identity and sends it to the network",
				Evidence:    f.Path,
			})
			seenHostRecon = true
		}

		// A hardcoded Discord/Telegram exfil webhook (with a real id+token) — the
		// canonical stealer sink. Malicious regardless of when it runs (import-time
		// stealers are the norm), so it is not gated to install context. High ->
		// quarantine; the panel adjudicates. Skip test/doc (a client lib's fixtures).
		if !seenWebhook && !isTestOrDoc(f.Path) && !isDataConfig(f.Path) && hardcodedWebhook.Match(content) {
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "hardcoded-webhook-exfil", Severity: verdict.SevHigh,
				Description: "hardcoded Discord/Telegram exfil webhook (token/cookie stealer sink)",
				Evidence:    f.Path + ": " + firstMatch(hardcodedWebhook, content),
			})
			seenWebhook = true
		}

		// The javascript-obfuscator (_0x-hex) fingerprint is a precise obfuscation
		// signal, distinct from ordinary minification: strong enough to review
		// (High -> quarantine), not to hard-block, since a few legitimate packages
		// ship obfuscated code. Plain minification stays informational below.
		if !seenObfCode && (hexObfuscated(content) || pyObfuscated(content)) {
			desc := "javascript-obfuscator fingerprint (dense _0x-hex identifiers)"
			if !hexObfuscated(content) {
				desc = "python string-escape obfuscation (eval/exec of an escape-encoded payload)"
			}
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "obfuscated-code", Severity: verdict.SevHigh,
				Description: desc,
				Evidence:    f.Path,
			})
			seenObfCode = true
		} else if looksObfuscated(f) {
			// Minification is ubiquitous in benign packages (dist bundles), so
			// this alone is informational; dynamic-exec-decoded catches the
			// malicious form (executing decoded content).
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "obfuscated-blob", Severity: verdict.SevInfo,
				Description: "large minified/obfuscated blob with dynamic-eval markers",
				Evidence:    f.Path,
			})
		}
	}
	return sigs
}

// hexObfuscated reports the javascript-obfuscator fingerprint: many uses of
// _0x-hex identifiers spread across several distinct names. Requires both a
// volume of uses and distinct names so a single stray _0xDEAD token (a color, a
// hash) never trips it, while real obfuscator.io output (dozens of _0x names,
// each used repeatedly) always does.
func hexObfuscated(content []byte) bool {
	ms := hexIdent.FindAll(content, 200)
	if len(ms) < 8 {
		return false
	}
	distinct := map[string]struct{}{}
	for _, m := range ms {
		distinct[string(m)] = struct{}{}
		if len(distinct) >= 5 {
			return true
		}
	}
	return false
}

// hostReconExfil reports a file that reads ≥2 distinct host/identity primitives
// AND has a network sink — the recon-and-report shape. The distinct-count and
// network requirements keep a lone hostname read (common and benign) from firing.
func hostReconExfil(content []byte) bool {
	if !netPrimitive.Match(content) {
		return false
	}
	distinct := map[string]struct{}{}
	for _, m := range hostRecon.FindAll(content, 50) {
		distinct[strings.ToLower(string(m))] = struct{}{}
		if len(distinct) >= 2 {
			return true
		}
	}
	return false
}

// pyObfuscated reports Python string-escape obfuscation. The precise primary is
// eval/exec/compile applied directly to an escape-encoded string (BlankOBF et al.).
// The fallback catches variants that stage the blob one indirection removed: a file
// dominated by escape bytes (>25% of its length) that also calls a dynamic-exec
// primitive. Benign source with a few byte constants never approaches that density.
func pyObfuscated(content []byte) bool {
	if pyEscEval.Match(content) {
		return true
	}
	ms := escSeq.FindAll(content, 4000)
	if len(ms) >= 40 && pyDynExec.Match(content) {
		escBytes := 0
		for _, m := range ms {
			escBytes += len(m)
		}
		if float64(escBytes)/float64(len(content)+1) > 0.25 {
			return true
		}
	}
	return false
}

// shellReconExfil reports a shell command that both recons host/credential state
// and ships it out — the install-beacon shape hostReconExfil (JS/Python primitives)
// misses because the recon is expressed as shell inside an exec'd command string.
func shellReconExfil(content []byte) bool {
	return shellRecon.Match(content) && shellExfil.Match(content)
}

// looksObfuscated flags files with very long lines (minification) that also
// contain a dynamic-eval primitive — the shape of a hidden payload.
func looksObfuscated(f *artifact.File) bool {
	if len(f.Content) < 2000 {
		return false
	}
	if maxLineLen(f.Content) < 1000 {
		return false
	}
	s := f.Content
	return regexpEvalMarker.Match(s)
}

var regexpEvalMarker = regexp.MustCompile(`(?i)(eval\s*\(|new\s+Function\s*\(|atob\s*\(|base64\.b64decode|fromCharCode)`)

func maxLineLen(b []byte) int {
	max, cur := 0, 0
	for _, c := range b {
		if c == '\n' {
			if cur > max {
				max = cur
			}
			cur = 0
			continue
		}
		cur++
	}
	if cur > max {
		max = cur
	}
	return max
}

// isBinary treats content with a NUL byte in its head as binary (skip text scans).
func isBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}

// decodedNetworkIndicator scans base64 string literals, decodes them, and
// returns the first that decodes to a URL or raw IP — a hidden C2/endpoint.
// Benign base64 (keys, embedded assets) decodes to binary, not "http://", so
// this stays precise.
func decodedNetworkIndicator(content []byte) (string, bool) {
	for _, m := range b64Literal.FindAllSubmatch(content, 60) {
		raw := m[1]
		if len(raw) > 8192 {
			continue
		}
		dec, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil || !isPrintable(dec) {
			continue
		}
		if urlOrIP.Match(dec) {
			return strings.TrimSpace(string(dec)), true
		}
	}
	return "", false
}

// hardcodedPublicEndpoint returns a public IPv4 literal used as a network target
// — a hardcoded C2. The IP must sit near host/connect/url/port context, so a
// version string like "3.5.0.1" (which also parses as a public IP) does not read
// as an endpoint. Private, loopback, link-local, documentation, and common
// public-DNS addresses are excluded.
func hardcodedPublicEndpoint(content []byte) (string, bool) {
	for _, m := range quotedIPv4.FindAllSubmatchIndex(content, 200) {
		// m[0] is the opening quote; m[2..9] are the octet capture-group bounds.
		if !isPublicIP(content[m[2]:m[3]], content[m[4]:m[5]], content[m[6]:m[7]], content[m[8]:m[9]]) {
			continue
		}
		lo := m[0] - 24
		if lo < 0 {
			lo = 0
		}
		if netRoleBefore.Match(content[lo:m[0]]) {
			return string(content[m[2]:m[3]]) + "." + string(content[m[4]:m[5]]) + "." +
				string(content[m[6]:m[7]]) + "." + string(content[m[8]:m[9]]), true
		}
	}
	return "", false
}

// isBuildTooling reports whether a path is a shipped build/CI helper (numpy and
// friends bundle these in their sdists). Such scripts legitimately run destructive
// cleanups (rm -rf build, rmtree(workdir)), so they must not read as a payload.
func isBuildTooling(path string) bool {
	p := strings.ToLower(path)
	b := baseName(p)
	// Build files legitimately run destructive cleanups (rm -rf /usr in a cross-build
	// Makefile — scipy ships one under a vendored ARPACK dir).
	switch b {
	case "makefile", "gnumakefile", "makefile.in", "makefile.am", "cmakelists.txt",
		"dockerfile", "build.gradle", "pom.xml", "meson.build", "wscript", "sconstruct":
		return true
	}
	if strings.HasSuffix(b, ".mk") || strings.HasSuffix(b, ".cmake") || strings.HasSuffix(b, ".bazel") ||
		strings.HasSuffix(b, ".bzl") || strings.HasSuffix(b, ".gyp") || strings.HasSuffix(b, ".gypi") {
		return true
	}
	return strings.Contains(p, "/tools/") || strings.HasPrefix(p, "tools/") ||
		strings.Contains(p, "/ci/") || strings.Contains(p, "/.ci/") ||
		strings.Contains(p, ".github/") || strings.Contains(p, ".gitlab-ci") ||
		strings.Contains(p, ".circleci") || strings.Contains(p, "cibuildwheel") ||
		strings.Contains(p, "cibw") || strings.Contains(p, "noxfile") ||
		strings.Contains(p, "conftest") || strings.Contains(p, "vendored") ||
		strings.Contains(p, "/vendor/") || strings.Contains(p, "/_vendor/") ||
		strings.Contains(p, "/third_party/") || strings.Contains(p, "/third-party/") ||
		strings.Contains(p, "/packaging/") || strings.Contains(p, "/meson") ||
		strings.Contains(p, "/scripts/") || strings.HasPrefix(p, "scripts/") ||
		strings.Contains(p, "/depends/") || strings.HasPrefix(p, "depends/")
}

// isDataConfig reports whether a path is a data/config file, not executable code.
// A .yaml that *lists* malicious patterns (litellm's prompt-injection content filter
// bundles `nc -e`, `mkfs`, `eval(atob` as filter categories) is data, not a payload,
// so the code-execution heuristics skip it.
func isDataConfig(path string) bool {
	p := strings.ToLower(path)
	for _, ext := range []string{".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".lock", ".xml", ".csv", ".proto"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// isTestOrDoc reports whether a path is a non-payload location — a test, example,
// doc, fixture, or data/cache file — where pattern matches are not a shipped payload.
// Matching is component-based (a `test/` directory, not the substring in "latest"),
// and it handles paths that *start* with the component (e.g. tests/certs/ca.key.pem),
// which the old prefix checks missed and which false-positived on asyncpg/awscli.
func isTestOrDoc(path string) bool {
	p := strings.ToLower(path)
	for _, seg := range []string{
		"test", "tests", "testing", "testdata", "example", "examples",
		"fixture", "fixtures", "doc", "docs", "sample", "samples", "spec", "specs",
		"__mocks__", "__snapshots__", "snapshots", "benchmark", "benchmarks",
		"data", "cache", "discovery_cache",
	} {
		if p == seg || strings.HasPrefix(p, seg+"/") || strings.Contains(p, "/"+seg+"/") {
			return true
		}
	}
	return strings.Contains(p, "_test") || strings.Contains(p, ".test.") || strings.Contains(p, ".spec.") ||
		strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".txt") || strings.HasSuffix(p, ".rst") ||
		strings.HasSuffix(p, ".rdoc") || strings.HasSuffix(p, ".ipynb")
}

// isVendoredBundle reports whether a path is a bundled/minified vendor blob, where
// coincidental byte sequences (a "cmd.exe" string, a socket call near a shell name)
// trip the source-pattern rules. playwright/pnpm/vite ship these; they are compiled
// output, not hand-written source, so the reverse-shell / recon heuristics skip them.
func isVendoredBundle(path string) bool {
	p := strings.ToLower(path)
	b := baseName(p)
	return strings.HasSuffix(b, ".min.js") || strings.HasSuffix(b, ".min.css") ||
		strings.Contains(b, "bundle") ||
		strings.Contains(p, "/dist/") || strings.HasPrefix(p, "dist/") ||
		strings.Contains(p, "/vendor/") || strings.HasPrefix(p, "vendor/") ||
		strings.Contains(p, "_next/") || strings.Contains(p, "/.next/") ||
		strings.Contains(p, "/static/chunks/") || strings.Contains(p, "/build/") ||
		strings.Contains(p, ".chunk.js") || strings.Contains(p, "/.output/")
}

// npmHookTargets returns the set of local script basenames referenced by npm
// install lifecycle hooks (e.g. `node collect.js` -> {collect.js}). A harvest
// living in one of these files runs at install time and is escalated.
func npmHookTargets(u *artifact.Unpacked) map[string]bool {
	targets := map[string]bool{}
	f := u.Lookup("package.json")
	if f == nil {
		return targets
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(f.Content, &pkg) != nil {
		return targets
	}
	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		cmd, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}
		for _, m := range scriptFileToken.FindAllString(cmd, -1) {
			targets[baseName(m)] = true
		}
	}
	return targets
}

// isSetupFile reports whether a path is a Python install-time setup script.
func isSetupFile(path string) bool {
	b := baseName(strings.ToLower(path))
	return b == "setup.py" || b == "setup.cfg"
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// isSBOM reports whether a path is a Software Bill of Materials manifest
// (CycloneDX or SPDX). Per PEP 770, Python packages ship these under
// <dist-info>/sboms/. They are inert metadata describing provenance, so their
// embedded base64/hex blobs are not code and must not be scanned as source.
func isSBOM(path string) bool {
	p := strings.ToLower(path)
	if strings.Contains(p, "/sboms/") {
		return true
	}
	return strings.HasSuffix(p, ".cdx.json") || strings.HasSuffix(p, ".spdx.json") ||
		strings.HasSuffix(p, ".spdx") || strings.HasSuffix(p, ".cdx.xml")
}

func isPublicIP(ab, bb, cb, db []byte) bool {
	oct := func(b []byte) int {
		n := 0
		for _, c := range b {
			n = n*10 + int(c-'0')
		}
		return n
	}
	a, b, c, d := oct(ab), oct(bb), oct(cb), oct(db)
	for _, o := range []int{a, b, c, d} {
		if o > 255 {
			return false
		}
	}
	switch {
	case a == 10, a == 127, a == 0, a >= 224: // private, loopback, this-network, multicast/reserved
		return false
	case a == 172 && b >= 16 && b <= 31:
		return false
	case a == 192 && b == 168:
		return false
	case a == 169 && b == 254: // link-local (incl. cloud metadata — handled behaviorally)
		return false
	case a == 100 && b >= 64 && b <= 127: // CGNAT
		return false
	case a == 192 && b == 0 && c == 2, a == 198 && b == 51 && c == 100, a == 203 && b == 0 && c == 113: // TEST-NET docs
		return false
	case a == 8 && b == 8 && (c == 8 || c == 4), a == 1 && b == 1 && c == 1 && d == 1: // public DNS
		return false
	}
	return true
}

// isPrintable reports whether b is mostly printable text (so a coincidental
// "http" inside decoded binary doesn't trip the rule).
func isPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return printable*100/len(b) >= 90
}

// stripLongLiterals blanks the contents of string literals longer than 200 bytes —
// inlined READMEs / docstrings — so the code examples they contain don't read as
// executable install-time actions. Short literals (a URL arg, 'sh', '-c') are kept.
func stripLongLiterals(b []byte) []byte {
	return quotedStr.ReplaceAllFunc(b, func(m []byte) []byte {
		if len(m) > 200 {
			return []byte(`""`)
		}
		return m
	})
}

func firstMatch(re *regexp.Regexp, b []byte) string {
	if m := re.Find(b); m != nil {
		return string(m)
	}
	return ""
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
