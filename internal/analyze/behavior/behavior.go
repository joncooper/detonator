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
	"fmt"
	"regexp"
	"strings"

	"github.com/joncooper/detonator/internal/verdict"
)

// Analyze runs the behavioral rules over a trace and returns signals. The
// ecosystem selects the registry/CDN whitelist for egress classification.
func Analyze(eco verdict.Ecosystem, tr *Trace) []verdict.Signal {
	var sigs []verdict.Signal
	sawCredentialRead := false
	writtenExec := map[string]bool{} // basenames of executable-looking dropped files
	reconTools := map[string]bool{}  // distinct host-profiling tools seen
	var deleted []string

	for phase, p := range tr.Analysis {
		for _, f := range p.Files {
			// A file can be read AND written AND deleted in one run (a dropper
			// writes then reads-to-exec), so these are independent, not a switch.
			if f.Read {
				if class, sev := classifySensitiveRead(f.Path); class != "" {
					if sev >= sevRank(verdict.SevHigh) {
						sawCredentialRead = true
					}
					sigs = append(sigs, verdict.Signal{
						Stage: "behavior", Rule: "sensitive-read:" + class, Severity: sevOf(sev),
						Description: "reads " + class + " during " + phase, Evidence: f.Path,
					})
				}
			}
			if f.Write {
				if rule, sev, desc := classifyWrite(f.Path); rule != "" {
					sigs = append(sigs, verdict.Signal{
						Stage: "behavior", Rule: rule, Severity: sev,
						Description: desc + " during " + phase, Evidence: f.Path,
					})
				}
				if looksExecutablePath(f.Path) {
					writtenExec[baseName(f.Path)] = true
				}
			}
			if f.Delete {
				deleted = append(deleted, f.Path)
			}
		}
		for _, c := range p.Commands {
			if rule, sev, desc := classifyCommand(c.Command); rule != "" {
				sigs = append(sigs, verdict.Signal{
					Stage: "behavior", Rule: rule, Severity: sev,
					Description: desc + " during " + phase, Evidence: strings.Join(c.Command, " "),
				})
			}
			if t := reconTool(c.Command); t != "" {
				reconTools[t] = true
			}
			if dropped := spawnsWritten(c.Command, writtenExec); dropped != "" {
				sigs = append(sigs, verdict.Signal{
					Stage: "behavior", Rule: "download-and-execute", Severity: verdict.SevCritical,
					Description: "executes a file it dropped during " + phase, Evidence: dropped,
				})
			}
		}
		for _, s := range p.Sockets {
			switch {
			case isMetadataEndpoint(s.Address):
				sigs = append(sigs, verdict.Signal{
					Stage: "behavior", Rule: "cloud-metadata-access", Severity: verdict.SevCritical,
					Description: "connects to the cloud instance-metadata endpoint during " + phase, Evidence: s.Address,
				})
			case isMiningPoolPort(s.Port):
				sigs = append(sigs, verdict.Signal{
					Stage: "behavior", Rule: "mining-pool-egress", Severity: verdict.SevHigh,
					Description: "connects to a cryptomining-pool port during " + phase,
					Evidence:    fmt.Sprintf("%s:%d", s.Address, s.Port),
				})
			}
		}
		for _, d := range p.DNS {
			for _, q := range d.Queries {
				if isUnknownDomain(eco, q.Hostname) {
					sigs = append(sigs, verdict.Signal{
						Stage: "behavior", Rule: "unknown-domain", Severity: verdict.SevHigh,
						Description: "resolves an unknown external domain during " + phase, Evidence: q.Hostname,
					})
				}
			}
		}
	}

	// ---- aggregate signals (cross-file / cross-query) ----
	if len(deleted) >= destructionThreshold {
		sigs = append(sigs, verdict.Signal{
			Stage: "behavior", Rule: "data-destruction", Severity: verdict.SevCritical,
			Description: fmt.Sprintf("deletes %d files (destructive)", len(deleted)), Evidence: firstN(deleted, 3),
		})
	}
	if len(reconTools) >= reconBurstThreshold {
		sigs = append(sigs, verdict.Signal{
			Stage: "behavior", Rule: "recon-burst", Severity: verdict.SevMedium,
			Description: fmt.Sprintf("host reconnaissance: %d distinct profiling tools", len(reconTools)),
		})
	}
	if host, n := dnsExfilPattern(eco, tr); n >= dnsExfilThreshold {
		sigs = append(sigs, verdict.Signal{
			Stage: "behavior", Rule: "dns-exfil", Severity: verdict.SevHigh,
			Description: fmt.Sprintf("%d encoded-subdomain DNS queries to one parent (exfil pattern)", n), Evidence: host,
		})
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
	case home && (strings.HasSuffix(p, "/.netrc") || strings.HasSuffix(p, "/_netrc")):
		// pip reads ~/.netrc for registry auth on every install, so a do-nothing
		// benign pypi package trips this too (confirmed by a benign-probe detonation:
		// a setup.py that only calls setup() reads /root/.netrc + /etc/{passwd,shadow}).
		// Record it but don't let the read alone drive a verdict — same reasoning as
		// npm-token/etc-passwd. Genuine netrc theft still surfaces via unknown-domain
		// (fires independently) when the stolen data is exfiltrated.
		return "netrc", sevRank(verdict.SevInfo)
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

// classifyCommand classifies a spawned process. Pure native-build invocations
// (node-gyp/gcc/make) carry no danger tokens, so they naturally return no signal
// and need no explicit whitelist.
func classifyCommand(argv []string) (rule string, sev verdict.Severity, desc string) {
	joined := strings.ToLower(strings.Join(argv, " "))
	switch {
	case containsAny(joined, "169.254.169.254", "169.254.170.2", "metadata.google"):
		return "process-spawn", verdict.SevCritical, "spawns a process targeting the cloud-metadata endpoint"
	case reverseShell.MatchString(joined):
		return "reverse-shell", verdict.SevCritical, "spawns a reverse/interactive shell"
	case destructiveCmd.MatchString(joined):
		return "data-destruction", verdict.SevCritical, "runs a destructive command"
	case containsAny(joined, "xmrig", "minerd", "stratum+tcp", "cryptonight", "--donate-level"):
		return "mining-pool-egress", verdict.SevHigh, "runs a cryptominer"
	}
	// Note: plain `sh -c` / `bash -c` is NOT flagged — that is how npm runs every
	// lifecycle script; the danger is in what the script does.
	for _, tok := range []string{"curl ", "wget ", " nc ", "ncat ", "/dev/tcp", "base64 -d", "base64 --decode", "chmod +x", "powershell", "invoke-expression"} {
		if strings.Contains(joined, tok) {
			return "process-spawn", verdict.SevHigh, "spawns a network/decode process (" + strings.TrimSpace(tok) + ")"
		}
	}
	return "", "", ""
}

// ---- new behavioral traits ----

const (
	destructionThreshold = 25 // file deletes in one run that read as destructive
	reconBurstThreshold  = 3  // distinct host-profiling tools in one run
	dnsExfilThreshold    = 3  // encoded-subdomain queries to one parent domain
)

var (
	reverseShell   = regexp.MustCompile(`(?i)((ba)?sh\s+-i\b|/dev/tcp/|(nc|ncat)\s+[^|]*-e\b|mkfifo\b[^|]*\|\s*(ba)?sh|socat\b.*exec)`)
	destructiveCmd = regexp.MustCompile(`(?i)(rm\s+-[rf]{1,2}\s+(/($|\s|root|home|etc|usr|var|bin)|~|\$home)|\bmkfs\b|\bdd\s+if=.*of=/dev/|>\s*/dev/sd)`)
)

// classifyWrite flags a file write that establishes persistence or overwrites a
// system binary. A package's own install-dir writes don't match these paths.
func classifyWrite(path string) (rule string, sev verdict.Severity, desc string) {
	p := strings.ToLower(path)
	switch {
	case containsAny(p, "/etc/cron", "/var/spool/cron", "crontab"),
		containsAny(p, "/etc/systemd/system/", "/lib/systemd/system/", "/.config/systemd/user/"),
		strings.HasSuffix(p, "/.ssh/authorized_keys"),
		strings.Contains(p, "/.config/autostart/"),
		strings.Contains(p, "/.git/hooks/"),
		p == "/etc/ld.so.preload",
		isHomeScoped(p) && hasSuffixAny(p, "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc", "/.zprofile"):
		return "persistence-write", verdict.SevCritical, "writes a persistence mechanism"
	case hasPrefixAny(p, "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"):
		return "binary-overwrite", verdict.SevCritical, "overwrites a system binary path"
	}
	return "", "", ""
}

// looksExecutablePath reports whether a written path looks like a dropped
// payload (in a writable dir, script extension or no extension).
func looksExecutablePath(path string) bool {
	p := strings.ToLower(path)
	if !containsAny(p, "/tmp/", "/dev/shm/", "/var/tmp/") && !isHomeScoped(p) {
		return false
	}
	return hasSuffixAny(p, ".sh", ".py", ".elf", ".bin", ".out") || !strings.Contains(baseName(p), ".")
}

// spawnsWritten returns the argv token that names a file the package dropped —
// the download/drop-and-execute pattern.
func spawnsWritten(argv []string, written map[string]bool) string {
	for _, a := range argv {
		if written[baseName(a)] {
			return a
		}
	}
	return ""
}

// reconTool returns a normalized host-profiling tool name for a command, or "".
func reconTool(argv []string) string {
	j := " " + strings.ToLower(strings.Join(argv, " ")) + " "
	for tok, name := range map[string]string{
		" uname ": "uname", " whoami ": "whoami", " hostname ": "hostname",
		" ifconfig ": "ifconfig", " ip addr": "ip", " printenv ": "env",
		"/etc/os-release": "os-release", " lscpu ": "lscpu",
	} {
		if strings.Contains(j, tok) {
			return name
		}
	}
	if len(argv) > 0 && strings.EqualFold(strings.TrimSpace(argv[len(argv)-1]), "id") {
		return "id"
	}
	return ""
}

func isMiningPoolPort(port int) bool {
	switch port {
	case 3333, 5555, 7777, 14444, 45700:
		return true
	}
	return false
}

// dnsExfilPattern counts encoded-looking (long) subdomain queries grouped by
// parent domain — the DNS-exfil shape — and returns the busiest parent.
func dnsExfilPattern(eco verdict.Ecosystem, tr *Trace) (string, int) {
	byParent := map[string]int{}
	for _, p := range tr.Analysis {
		for _, d := range p.DNS {
			for _, q := range d.Queries {
				h := strings.ToLower(strings.TrimSuffix(q.Hostname, "."))
				if !isUnknownDomain(eco, h) {
					continue
				}
				parent := parentDomain(h)
				if len(strings.TrimSuffix(h, "."+parent)) >= 20 {
					byParent[parent]++
				}
			}
		}
	}
	best, n := "", 0
	for p, c := range byParent {
		if c > n {
			best, n = p, c
		}
	}
	return best, n
}

func parentDomain(h string) string {
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func firstN(ss []string, n int) string {
	if len(ss) > n {
		ss = ss[:n]
	}
	return strings.Join(ss, ", ")
}

func hasSuffixAny(s string, sufs ...string) bool {
	for _, x := range sufs {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

func hasPrefixAny(s string, prefs ...string) bool {
	for _, x := range prefs {
		if strings.HasPrefix(s, x) {
			return true
		}
	}
	return false
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
