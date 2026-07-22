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

	// Python build/runtime primitives that indicate code executing at install.
	pyExecToken = regexp.MustCompile(`(?i)(os\.system|subprocess\.(run|call|popen|check_output|check_call)|socket\.socket|urllib|requests\.(get|post)|\bexec\s*\(|\beval\s*\(|base64\.b64decode|__import__\s*\(|marshal\.loads|compile\s*\()`)

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

	// scriptFileToken extracts a local script path referenced by an install hook
	// command (e.g. `node collect.js` -> collect.js), used to escalate a harvest
	// that runs at install time.
	scriptFileToken = regexp.MustCompile(`[\w./@-]+\.(?:js|cjs|mjs|ts)`)
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
		// A wiper whose only act is shutil.rmtree('/') or expanduser('~') matches
		// no pyExecToken but is unambiguously destructive at install time.
		if destructiveToken.Match(f.Content) {
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "destructive-payload", Severity: verdict.SevCritical,
				Description: name + " runs a destructive/wiper command at install time",
				Evidence:    firstMatch(destructiveToken, f.Content),
			})
		}
		if pyExecToken.MatchString(string(f.Content)) {
			sev := verdict.SevHigh
			if urlOrIP.MatchString(string(f.Content)) {
				sev = verdict.SevCritical
			}
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "py-setup-execution", Severity: sev,
				Description: name + " executes code at build time (subprocess/network/exec)",
				Evidence:    firstMatch(pyExecToken, f.Content),
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
		if !seenExec && dynExecDecoded.Match(content) {
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
		if !seenEncoded {
			if dec, ok := decodedNetworkIndicator(content); ok {
				sigs = append(sigs, verdict.Signal{
					Stage: "static", Rule: "encoded-network-indicator", Severity: verdict.SevHigh,
					Description: "base64 literal decodes to a network endpoint (hidden C2)",
					Evidence:    f.Path + ": " + truncate(dec, 120),
				})
				seenEncoded = true
			}
		}

		if !seenSecret {
			if privateKey.Match(content) {
				sigs = append(sigs, verdict.Signal{
					Stage: "static", Rule: "embedded-private-key", Severity: verdict.SevMedium,
					Description: "embedded private key material", Evidence: f.Path,
				})
				seenSecret = true
			} else if m := awsKey.Find(content); m != nil {
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
		if !seenRevShell && !isTestOrDoc(f.Path) {
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
		if !seenDestructive && !isTestOrDoc(f.Path) && baseName(f.Path) != "package.json" &&
			!isSetupFile(f.Path) && destructiveToken.Match(content) {
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
		if !seenEnvExfil && !isTestOrDoc(f.Path) &&
			bulkEnvSerialize.Match(content) && netPrimitive.Match(content) {
			sev := verdict.SevHigh
			desc := "serializes the whole environment next to a network sink (env exfil)"
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

		if looksObfuscated(f) {
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

// hardcodedPublicEndpoint returns a public IPv4 literal that appears in a file
// which also uses a network primitive — a hardcoded C2. Private, loopback,
// link-local, documentation, and common public-DNS addresses are excluded.
func hardcodedPublicEndpoint(content []byte) (string, bool) {
	if !netPrimitive.Match(content) {
		return "", false
	}
	for _, m := range quotedIPv4.FindAllSubmatch(content, 200) {
		if isPublicIP(m[1], m[2], m[3], m[4]) {
			return string(m[1]) + "." + string(m[2]) + "." + string(m[3]) + "." + string(m[4]), true
		}
	}
	return "", false
}

// isTestOrDoc reports whether a path is a test, example, or documentation file,
// where IP/pattern mentions are not payloads.
func isTestOrDoc(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "/test") || strings.Contains(p, "test/") ||
		strings.Contains(p, "_test") || strings.Contains(p, "/tests") ||
		strings.Contains(p, "example") || strings.Contains(p, "/docs") ||
		strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".txt") || strings.HasSuffix(p, ".rst")
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
