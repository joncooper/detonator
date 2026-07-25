#!/usr/bin/env python3
"""Provision package-analysis for detonator: parallel-safe sandbox + coverage patches.

Patch 1 (parallel safety) is the new one. Upstream assumes ONE analysis per host, so
per-analysis cleanup is global: `podman rm --all --force` removes every container,
`podman image prune -f` prunes shared images, and removeAllLogs() deletes every
sandbox log dir. When several analyses share the bind-mounted /var/lib/containers
store, one worker finishing destroys the others' RUNNING sandboxes — which surfaces
as "error creating container: exit status 125" and a lost trace (~33% at 2-4 workers).

Scope those operations to the worker's own container, gated on DETONATOR_PARALLEL so
upstream single-host behaviour is unchanged when it is unset.
"""
import os, sys
os.chdir("/opt/package-analysis")
changed = []

# ---- Patch 1a: Clean() removes only this sandbox's container ----
p = "internal/sandbox/sandbox.go"
s = open(p).read()
old_clean = """	if err := s.forceStopContainer(ctx); err != nil {
		return err
	}
	return podmanCleanContainers(ctx)
}"""
new_clean = """	if err := s.forceStopContainer(ctx); err != nil {
		return err
	}
	// Remove ONLY this sandbox's container. Upstream's `podman rm --all --force`
	// assumes one analysis per host; when analyses share the container store
	// (parallel detonation) it force-removes other workers' RUNNING sandboxes,
	// surfacing as "error creating container: exit status 125" and a lost trace.
	if os.Getenv("DETONATOR_PARALLEL") != "" {
		return podmanRun(ctx, "rm", "--force", s.container)
	}
	return podmanCleanContainers(ctx)
}"""
if old_clean in s:
    s = s.replace(old_clean, new_clean); changed.append("Clean -> own container only")
elif "DETONATOR_PARALLEL" in s:
    changed.append("Clean: already patched")
else:
    sys.exit("ANCHOR MISSING: Clean()")

# ---- Patch 1b: skip the global image prune and log wipe when parallel ----
old_prune = """	if err := podmanPrune(ctx); err != nil {
		return fmt.Errorf("error pruning images: %w", err)
	}"""
new_prune = """	// A global image prune races with another worker pulling or creating from the
	// same shared image; skip it when analyses run concurrently.
	if os.Getenv("DETONATOR_PARALLEL") == "" {
		if err := podmanPrune(ctx); err != nil {
			return fmt.Errorf("error pruning images: %w", err)
		}
	}"""
if old_prune in s:
    s = s.replace(old_prune, new_prune); changed.append("prune -> skipped when parallel")

old_logs = """	if err := removeAllLogs(); err != nil {
		return fmt.Errorf("failed removing all logs: %w", err)
	}"""
new_logs = """	// removeAllLogs() deletes every sandbox_logs_* dir, including live ones
	// belonging to other concurrent analyses.
	if os.Getenv("DETONATOR_PARALLEL") == "" {
		if err := removeAllLogs(); err != nil {
			return fmt.Errorf("failed removing all logs: %w", err)
		}
	}"""
if old_logs in s:
    s = s.replace(old_logs, new_logs); changed.append("removeAllLogs -> skipped when parallel")

if '"os"' not in s.split(")")[0]:
    s = s.replace("import (", "import (\n\t\"os\"", 1)
    changed.append("added os import")
open(p, "w").write(s)

# ---- Patch 2: import-phase continue (analyze-node.js) ----
p = "sandboxes/dynamicanalysis/analyze-node.js"
s = open(p).read()
old = ("    // Always exit on failure.\n"
       "    // Install failing is either an interesting issue, or an opportunity to\n"
       "    // improve the analysis.\n"
       "    console.log('Install failed.');\n"
       "    process.exit(1);")
new = ("    // Install returned non-zero, but a package's main-module payload runs at\n"
       "    // import/require time regardless. Continue to the import phase (detonator).\n"
       "    console.log('Install failed (continuing to import phase).');")
if old in s:
    s = s.replace(old, new); changed.append("import-continue")
    open(p, "w").write(s)

# ---- Patch 3: CI env baits (rundynamic.go) ----
p = "internal/worker/rundynamic.go"
s = open(p).read()
anchor = 'sbOpts = append(sbOpts, sandbox.SetEnv("AWS_SECRET_ACCESS_KEY", AWSSecretAccessKey))'
if anchor in s and "GITHUB_ACTIONS" not in s:
    s = s.replace(anchor, anchor + (
        "\n\n\t// CI-environment baits: much malware only detonates under CI (detonator).\n"
        '\tsbOpts = append(sbOpts, sandbox.SetEnv("CI", "true"))\n'
        '\tsbOpts = append(sbOpts, sandbox.SetEnv("GITHUB_ACTIONS", "true"))\n'
        '\tsbOpts = append(sbOpts, sandbox.SetEnv("GITLAB_CI", "true"))'))
    open(p, "w").write(s); changed.append("ci-spoof")

for c in changed:
    print("  applied:", c)
print("DONE")
