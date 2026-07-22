# Harmless behavioral simulators

npm packages that exhibit the *shape* of a supply-chain technique with the
payload removed (localhost/discard/sinkhole targets, benign file writes), so the
recording-sinkhole detonation produces a real trace that exercises the behavioral
rules end-to-end. The runtime counterpart to `internal/eval`'s hand-built traces.

Build + detonate each on the burner (`-nopull -local`, networked through the
sinkhole) and score with `dscore`. Validated 6/6 on 2026-07-22, and caught a real
bug (read+write file ops handled as a switch) — see the eval writeup.

- sim-reverse-shell → reverse-shell   - sim-dropper → download-and-execute
- sim-persistence   → persistence-write - sim-metadata → cloud-metadata-access
- sim-miner         → mining-pool-egress - sim-dns-exfil → dns-exfil
