// Package static is Detonator's cheap first-pass analyzer. It inspects unpacked
// artifact bytes — never executing them — for the patterns that precede most
// commodity supply-chain attacks: install-time scripts that reach the network
// or spawn shells, setup.py that runs code at build time, obfuscated blobs, and
// embedded secrets. It is fast enough to fast-block obvious cases before the
// expensive detonation stage (build-plan §3).
package static

import (
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
	dangerToken = regexp.MustCompile(`(?i)\b(curl|wget|/dev/tcp|base64\s+-d|base64\s+--decode|bash\s+-c|sh\s+-c|eval|child_process|chmod\s+\+x|node\s+-e|python[0-9]?\s+-c|powershell|invoke-expression|mshta|certutil)\b`)

	// Python build/runtime primitives that indicate code executing at install.
	pyExecToken = regexp.MustCompile(`(?i)(os\.system|subprocess\.(run|call|popen|check_output|check_call)|socket\.socket|urllib|requests\.(get|post)|\bexec\s*\(|\beval\s*\(|base64\.b64decode|__import__\s*\(|marshal\.loads|compile\s*\()`)

	urlOrIP = regexp.MustCompile(`(https?://[^\s"'` + "`" + `]+)|(\b(?:\d{1,3}\.){3}\d{1,3}\b)`)

	awsKey        = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	privateKey    = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)
	genericSecret = regexp.MustCompile(`(?i)(secret|token|api[_-]?key|password|passwd)['"]?\s*[:=]\s*['"][A-Za-z0-9/+_\-]{16,}['"]`)
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
// secrets, obfuscation, and executable network references.
func scanContents(u *artifact.Unpacked) []verdict.Signal {
	var sigs []verdict.Signal
	seenSecret := false
	for i := range u.Files {
		f := &u.Files[i]
		if isBinary(f.Content) {
			continue
		}
		content := f.Content

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

		if looksObfuscated(f) {
			sigs = append(sigs, verdict.Signal{
				Stage: "static", Rule: "obfuscated-blob", Severity: verdict.SevMedium,
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
