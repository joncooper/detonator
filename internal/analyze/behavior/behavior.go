// Package behavior applies OSCAR-style whitelist/blacklist rules to a dynamic
// analysis behavior log (from the detonation sandbox) and emits signals. It is
// deterministic, explainable, and the backstop when the LLM is unavailable or
// disagrees (build-plan §3).
//
// Design rule: every check targets a general threat CLASS — credential-path
// reads, cloud-metadata access, dangerous process spawns, egress to an unknown
// destination — never a specific sample's indicators. A rule that only fires on
// today's corpus is worthless against tomorrow's 0-day.
package behavior

import (
	"strings"

	"github.com/joncooper/detonator/internal/verdict"
)

// Analyze runs the behavioral rules over a trace and returns signals. The
// ecosystem selects the registry/CDN whitelist for egress classification.
func Analyze(eco verdict.Ecosystem, tr *Trace) []verdict.Signal {
	var sigs []verdict.Signal
	sawCredentialRead := false

	for phase, p := range tr.Analysis {
		for _, f := range p.Files {
			if !f.Read {
				continue
			}
			if class, sev := classifySensitiveRead(f.Path); class != "" {
				if sev >= sevRank(verdict.SevHigh) {
					sawCredentialRead = true
				}
				sigs = append(sigs, verdict.Signal{
					Stage: "behavior", Rule: "sensitive-read:" + class, Severity: sevOf(sev),
					Description: "reads " + class + " during " + phase,
					Evidence:    f.Path,
				})
			}
		}
		for _, c := range p.Commands {
			if sev, why := classifyCommand(c.Command); why != "" {
				sigs = append(sigs, verdict.Signal{
					Stage: "behavior", Rule: "process-spawn", Severity: sev,
					Description: why + " during " + phase,
					Evidence:    strings.Join(c.Command, " "),
				})
			}
		}
		for _, s := range p.Sockets {
			if isMetadataEndpoint(s.Address) {
				sigs = append(sigs, verdict.Signal{
					Stage: "behavior", Rule: "cloud-metadata-access", Severity: verdict.SevCritical,
					Description: "connects to the cloud instance-metadata endpoint during " + phase,
					Evidence:    s.Address,
				})
			}
		}
		for _, d := range p.DNS {
			for _, q := range d.Queries {
				if isUnknownDomain(eco, q.Hostname) {
					sigs = append(sigs, verdict.Signal{
						Stage: "behavior", Rule: "unknown-domain", Severity: verdict.SevHigh,
						Description: "resolves an unknown external domain during " + phase,
						Evidence:    q.Hostname,
					})
				}
			}
		}
	}

	// Exfil chain: reading credentials AND reaching an unknown destination is the
	// canonical stealer shape — escalate to make the composite explicit.
	if sawCredentialRead && hasUnknownEgress(eco, tr) {
		sigs = append(sigs, verdict.Signal{
			Stage: "behavior", Rule: "exfil-chain", Severity: verdict.SevCritical,
			Description: "reads credential material and contacts an unknown destination (exfiltration pattern)",
		})
	}
	return sigs
}

// classifySensitiveRead maps a path to a credential/sensitive class and severity
// rank. Credential-bearing dotfiles are high — but only when read from a user
// HOME directory: the same basenames exist as system/project config (npm reads
// /usr/lib/node_modules/npm/npmrc on every install) and flagging those would
// false-positive on benign packages. /etc/passwd and shell rc files are noisier
// (benign user lookups) so they rank lower. All of this keeps precision high.
func classifySensitiveRead(path string) (class string, rank int) {
	p := strings.ToLower(path)
	home := isHomeScoped(p)
	switch {
	case home && containsAny(p, "/.aws/credentials", "/.aws/config"):
		return "aws-credentials", sevRank(verdict.SevHigh)
	case home && containsAny(p, "/.ssh/id_", "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/id_ecdsa"):
		return "ssh-private-key", sevRank(verdict.SevHigh)
	case home && strings.HasSuffix(p, "/.npmrc"):
		// npm reads ~/.npmrc on every install to get registry auth, so a benign
		// package trips this too (confirmed by the benign baseline). Record it
		// but don't let the read alone drive a verdict.
		return "npm-token", sevRank(verdict.SevInfo)
	case home && strings.HasSuffix(p, "/.docker/config.json"):
		return "docker-config", sevRank(verdict.SevHigh)
	case home && (strings.HasSuffix(p, "/.git-credentials") || strings.HasSuffix(p, "/.gitconfig")):
		return "git-credentials", sevRank(verdict.SevHigh)
	case home && strings.HasSuffix(p, "/.netrc"):
		return "netrc", sevRank(verdict.SevHigh)
	case home && containsAny(p, "/.config/gcloud", "/.azure/", "/.kube/config"):
		return "cloud-config", sevRank(verdict.SevHigh)
	case home && (strings.HasSuffix(p, "/.env") || strings.Contains(p, "/.env.")):
		return "dotenv", sevRank(verdict.SevHigh)
	case p == "/etc/shadow":
		// The sandbox runs as root and benign pip installs read /etc/shadow and
		// /etc/passwd during setup (confirmed by the benign baseline), so these
		// are baseline noise in this environment, not a detection signal.
		return "etc-shadow", sevRank(verdict.SevInfo)
	case p == "/etc/passwd":
		return "etc-passwd", sevRank(verdict.SevInfo)
	case home && (strings.HasSuffix(p, "/.bashrc") || strings.HasSuffix(p, "/.bash_profile") || strings.HasSuffix(p, "/.profile")):
		return "shell-rc", sevRank(verdict.SevLow)
	default:
		return "", 0
	}
}

// isHomeScoped reports whether a path lives under a user's home directory, where
// credential dotfiles actually hold secrets (as opposed to system/project copies).
func isHomeScoped(p string) bool {
	return strings.HasPrefix(p, "/root/") || strings.HasPrefix(p, "/home/")
}

// classifyCommand flags process spawns that shell out, fetch, or decode — the
// tools install-stage payloads reach for.
func classifyCommand(argv []string) (verdict.Severity, string) {
	joined := strings.ToLower(strings.Join(argv, " "))
	// Metadata theft via curl/wget is the highest-signal spawn.
	if strings.Contains(joined, "169.254.169.254") || strings.Contains(joined, "169.254.170.2") || strings.Contains(joined, "metadata.google") {
		return verdict.SevCritical, "spawns a process targeting the cloud-metadata endpoint"
	}
	// Note: plain `sh -c` / `bash -c` is NOT flagged — that is how npm runs every
	// lifecycle script; the danger is in what the script does, captured below.
	for _, tok := range []string{"curl ", "wget ", " nc ", "ncat ", "/dev/tcp", "base64 -d", "base64 --decode", "chmod +x", "powershell", "invoke-expression"} {
		if strings.Contains(joined, tok) {
			return verdict.SevHigh, "spawns a network/decode process (" + strings.TrimSpace(tok) + ")"
		}
	}
	return "", ""
}

func hasUnknownEgress(eco verdict.Ecosystem, tr *Trace) bool {
	for _, p := range tr.Analysis {
		for _, s := range p.Sockets {
			if isMetadataEndpoint(s.Address) {
				return true
			}
		}
		for _, d := range p.DNS {
			for _, q := range d.Queries {
				if isUnknownDomain(eco, q.Hostname) {
					return true
				}
			}
		}
	}
	return false
}

func isMetadataEndpoint(addr string) bool {
	return addr == "169.254.169.254" || addr == "169.254.170.2"
}

// registryWhitelist is the set of domain suffixes a package may legitimately
// reach during install: its own ecosystem registry and CDN.
var registryWhitelist = map[verdict.Ecosystem][]string{
	verdict.NPM:  {"registry.npmjs.org", ".npmjs.org", ".npmjs.com", ".yarnpkg.com"},
	verdict.PyPI: {"pypi.org", ".pypi.org", ".pythonhosted.org", "files.pythonhosted.org"},
}

// isUnknownDomain reports whether a resolved hostname is outside the expected
// registry/CDN set and not localhost — i.e. a candidate exfil destination.
func isUnknownDomain(eco verdict.Ecosystem, host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".local") {
		return false
	}
	for _, suffix := range registryWhitelist[eco] {
		if h == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(h, suffix) {
			return false
		}
	}
	return true
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

var rankBySev = map[verdict.Severity]int{
	verdict.SevInfo: 1, verdict.SevLow: 2, verdict.SevMedium: 3, verdict.SevHigh: 4, verdict.SevCritical: 5,
}
var sevByRank = map[int]verdict.Severity{
	1: verdict.SevInfo, 2: verdict.SevLow, 3: verdict.SevMedium, 4: verdict.SevHigh, 5: verdict.SevCritical,
}

func sevRank(s verdict.Severity) int { return rankBySev[s] }
func sevOf(rank int) verdict.Severity {
	if s, ok := sevByRank[rank]; ok {
		return s
	}
	return verdict.SevInfo
}
