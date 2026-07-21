// Package differ compares a new package version against the previous
// known-good one. Its whole value is making a dangerous *change* loud: a benign
// library that suddenly grows an install hook that curls an IP is the classic
// supply-chain attack, and a version-over-version diff surfaces it even when the
// new version looks fine in isolation (build-plan §3).
package differ

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/joncooper/detonator/internal/artifact"
	"github.com/joncooper/detonator/internal/verdict"
)

// Diff compares prev (previous known-good) against cur (the candidate) and
// returns a file-level summary plus behavioral-change signals.
func Diff(art verdict.Artifact, prevVersion string, prev, cur *artifact.Unpacked) (verdict.DiffSummary, []verdict.Signal) {
	rep := verdict.DiffSummary{PrevVersion: prevVersion}
	prevHashes := hashByPath(prev)
	curHashes := hashByPath(cur)

	for p, h := range curHashes {
		ph, existed := prevHashes[p]
		switch {
		case !existed:
			rep.Added = append(rep.Added, p)
		case ph != h:
			rep.Modified = append(rep.Modified, p)
		}
	}
	for p := range prevHashes {
		if _, ok := curHashes[p]; !ok {
			rep.Removed = append(rep.Removed, p)
		}
	}

	var sigs []verdict.Signal
	switch art.Ecosystem {
	case verdict.NPM:
		sigs = append(sigs, npmHookDiff(prev, cur)...)
	case verdict.PyPI:
		sigs = append(sigs, pySetupDiff(prev, cur, rep)...)
	}
	return rep, sigs
}

func hashByPath(u *artifact.Unpacked) map[string]string {
	m := make(map[string]string, len(u.Files))
	for i := range u.Files {
		sum := sha256.Sum256(u.Files[i].Content)
		m[u.Files[i].Path] = string(sum[:])
	}
	return m
}

// npmHookDiff flags install lifecycle hooks that appeared or changed since the
// previous version. An appearing hook is the loudest signal a differ can give.
func npmHookDiff(prev, cur *artifact.Unpacked) []verdict.Signal {
	prevHooks := npmHooks(prev)
	curHooks := npmHooks(cur)
	var sigs []verdict.Signal
	for hook, cmd := range curHooks {
		old, existed := prevHooks[hook]
		switch {
		case !existed:
			sigs = append(sigs, verdict.Signal{
				Stage: "diff", Rule: "npm-install-hook-added", Severity: verdict.SevHigh,
				Description: "install hook '" + hook + "' is new since the previous version",
				Evidence:    truncate(cmd, 200),
			})
		case old != cmd:
			sigs = append(sigs, verdict.Signal{
				Stage: "diff", Rule: "npm-install-hook-changed", Severity: verdict.SevMedium,
				Description: "install hook '" + hook + "' changed since the previous version",
				Evidence:    truncate(cmd, 200),
			})
		}
	}
	return sigs
}

func npmHooks(u *artifact.Unpacked) map[string]string {
	out := map[string]string{}
	f := u.Lookup("package.json")
	if f == nil {
		return out
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(f.Content, &pkg) != nil {
		return out
	}
	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		if cmd, ok := pkg.Scripts[hook]; ok {
			out[hook] = cmd
		}
	}
	return out
}

// pySetupDiff flags a setup.py that appeared or changed, since build-time code
// is where PyPI install-stage payloads hide.
func pySetupDiff(prev, cur *artifact.Unpacked, rep verdict.DiffSummary) []verdict.Signal {
	prevHas := prev.Lookup("setup.py") != nil
	curHas := cur.Lookup("setup.py") != nil
	var sigs []verdict.Signal
	if curHas && !prevHas {
		sigs = append(sigs, verdict.Signal{
			Stage: "diff", Rule: "py-setup-added", Severity: verdict.SevMedium,
			Description: "setup.py is new since the previous version",
			Evidence:    "setup.py",
		})
		return sigs
	}
	for _, p := range rep.Modified {
		if p == "setup.py" {
			sigs = append(sigs, verdict.Signal{
				Stage: "diff", Rule: "py-setup-changed", Severity: verdict.SevLow,
				Description: "setup.py changed since the previous version",
				Evidence:    "setup.py",
			})
		}
	}
	return sigs
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
