# Detonator — A Supply-Chain Admission Gate for npm & PyPI

**Build plan v0.4 · July 2026**

A local registry proxy that refuses to serve a package version to your machine until it has been statically scanned, detonated in a sandbox, behaviorally judged, and diffed against the last known-good version. Nothing installs until it earns a verdict.

> Changed in v0.4: the §7 open decisions are resolved — triage model (GPT-5.6 Sol Medium), burner lifecycle (spin-up-per-batch, EC2, custom AMI), cache (local-first but signed from day one), and quarantine default (fail-to-review). See §7.
> Changed in v0.3: no third-party malicious package ever runs outside the burner. The early spike (Phase 0) validates the telemetry path with benign + synthetic samples only; live-corpus detonation waits for the burner in Phase 3. (v0.2 moved detonation off localhost onto a disposable burner host and replaced host-side Falco with gVisor's own trace points, since Falco can't see guest syscalls under gVisor.) See §3, §5, §6.

---

## 1. The idea in one paragraph

Today `npm install` and `pip install` execute arbitrary code from strangers on your laptop, at install time, with your credentials in the environment. Detonator inserts itself as the registry your tools talk to. When a package version is requested that hasn't been seen before, Detonator holds the request, runs the artifact through a layered analysis pipeline — static signatures, a real execution ("detonation") inside a locked-down sandbox on a throwaway host, behavioral rule matching over the captured syscalls and network activity, a diff against the previous trusted version, and an LLM triage pass — and only releases the tarball if the composite verdict is *allow*. Verdicts are cached and signed, so the cost is paid once per version across your whole team. The design borrows OSCAR's dynamic-analysis playbook (Ant Group), reuses OpenSSF's sandbox and data assets rather than reinventing them, and uses OpenAI Codex as the reasoning/triage brain via the Agent/Codex SDK.

---

## 2. What we're borrowing, and from where

**OSCAR (Ant Group), *Towards Robust Detection of OSS Supply Chain Poisoning Attacks in Industry Environments*** — this is the technical spine. OSCAR's contribution is that static analysis alone drowns in false positives on packages that merely *look* malicious (minifiers, crypto libs, network tools), so it actually runs the code and watches what it does. Key techniques we adopt:

- **Three activation points.** Install the package, import every module, then *fuzz every exported function/class* — because a lot of malware only fires when a specific function is called, not on import. OSCAR builds parameters via static type inference (names, defaults, types) rather than random values, and recurses into nested objects to depth 2.
- **Aspect-oriented API hooking.** Runtime-woven hooks on the dangerous surface: network (`net.Socket.connect`, `dgram`, `dns.*`, `http.ClientRequest` / Python `socket`, `http.client`, `urllib3`), filesystem (`fs` / `os` + `shutil`), and process spawn (`child_process` / `subprocess`, `os.system`).
- **Defense against hook evasion — adapted for gVisor.** Attackers replace stdlib APIs with their own implementations to dodge language-level hooks, so OSCAR *also* watches at the syscall layer with Falco. We keep the dual-layer *idea* — semantic hooks for the "what" plus syscall ground truth for the "really" — but not the Falco mechanism. OSCAR ran on plain Docker/runc, where the host kernel sees container syscalls directly. Under gVisor the host kernel only ever sees the Sentry's own narrow syscall set, so a host-based Falco goes blind to what the guest is doing. The syscall-layer signal instead comes from gVisor's own `runsc` trace points / remote-sink protocol — the same source `package-analysis` and commercial gVisor monitors use. Falco, if kept at all, demotes to an outer tripwire on the detonation *host*, watching for anything that shouldn't be happening there at all.
- **Rule-based verdicts + whitelist/blacklist.** Heuristic rules over behavior logs: whitelist localhost/temp-dir/legit-npm noise; blacklist unknown IPs & malicious domains, sensitive-file reads (`/etc/passwd`, shell rc files), credential/token exfil, suspicious binaries (`nc`, `chmod +x`). Sensitive-data-to-unknown-domain → human review, not auto-block.
- **Proven numbers to aim at.** OSCAR reports F1 0.95 (npm) / 0.91 (PyPI), precision ~0.99, and cut false positives on benign-but-suspicious packages from ~35–41% down to ~1–3%. Runtime ~128s npm / ~165s PyPI single-threaded. These are our target benchmarks.

**OpenSSF projects** — don't rebuild what exists:

- **`ossf/package-analysis`** — production-grade dynamic analysis in **gVisor** containers, capturing files/sockets/DNS/commands/syscalls, runnable locally via Docker (`scripts/run_analysis.sh -ecosystem pypi -package Django`), JSON out. This becomes our detonation engine's starting point rather than a from-scratch sandbox. Note its local mode runs the *outer* container `--privileged` to support the nested sandbox — fine on a throwaway host, which is one more reason detonation doesn't belong on your laptop (see §3).
- **`ossf/malicious-packages`** — a large corpus of confirmed-malicious packages in OSV format. This is our red-team labelled set for tuning and regression.
- **OSV / OSV-Scanner** — known-vuln lookup by exact version, so a package can be blocked on CVE grounds before we even detonate.
- **Sigstore / cosign** — used two ways: verify upstream provenance/signatures where they exist, and **sign our own verdicts** so a cached "allow" can't be forged.
- **Scorecard & GUAC** — reputation/provenance signals (Scorecard health metrics) and a graph of what-depends-on-what (GUAC) to feed the risk score and blast-radius estimate.

**OpenAI Codex (per your redirect from Kimi K3)** — the "intelligence" layer. Instead of hand-writing every heuristic, Codex reads the source + the behavior log and produces a structured judgment. Run headless via `codex exec` with `--output-schema` for machine-readable JSON verdicts and `--json` for event streaming; sandbox `read-only`; `--ask-for-approval never` for unattended runs. Auth via ChatGPT subscription OAuth (`~/.codex/auth.json`) for dev, API key for CI. Model behind a pluggable interface so Kimi K3 (open-weight, 1M context, strong agentic/coding) or a local model can be swapped in for code you won't send to a third party.

---

## 3. Architecture

Two planes. The **control plane** runs locally, holds your credentials, and *never executes package code*. The **detonation plane** is a disposable host that executes package code but holds nothing worth stealing. The proxy ships an artifact to the burner and gets a behavior log back.

```
 ═══ LOCAL · control plane ════════════════════════════════════════════════
     Holds your credentials. Never executes package code.

     npm / pip ──▶ PROXY (npm + PyPI registry · cache · admission gate)
                     │
        cache hit ───┴─▶ serve signed verdict + tarball        (fast path)

        miss / new version:
             1  static · secrets · OSV · Scorecard
             2  diff vs last known-good
                   └─▶ if new / changed / suspicious, ship artifact ─▶ [BURNER]
             …behavior log returns…
             4  behavioral rules  (OSCAR whitelist / blacklist)
             5  Codex triage  (source + behavior log + diff)
             6  verdict engine + policy → allow / block / quarantine
                   └─▶ cosign-sign + cache the verdict → serve or 403

 ═══ BURNER · detonation plane (disposable VM / EC2, destroyed per batch) ══
     No creds · SSH agent stripped · metadata API blocked · egress sinkholed

     3  DETONATE in gVisor:  install → import → fuzz exports
        telemetry = AOP hooks (net/fs/proc) + gVisor trace points
        (syscall ground truth)  →  behavior log  ─▶ returned to control plane
```

**Component list**

- **Proxy / admission gate** *(local)* — a caching pull-through registry speaking both the npm and PyPI (PEP 503 / JSON simple) protocols. Configure via `.npmrc registry=` and `pip index-url`. On cache miss it blocks the response, kicks the pipeline, and either streams the tarball or returns a 403 with a reason. This is the single enforcement point; if it's not in the path, nothing installs.
- **Fetcher/normalizer** *(local)* — pulls the artifact + metadata from the real upstream, records digest, maintainer, publish time, dist-tags.
- **Static analyzer** *(local)* — secret/entropy scan, `install`/`postinstall`/`setup.py` red-flag detection, minified-blob & install-time-network heuristics, OSV known-vuln lookup, Scorecard fetch. Cheap and fast; can fast-block obvious cases before detonation.
- **Differ** *(local)* — pulls the previous trusted version from cache and diffs: which files changed, did an install script appear/change, did the maintainer/publisher change, did previously-absent network/process calls show up. A benign library that suddenly gains a `postinstall` that curls an IP is the classic attack, and the diff makes it loud.
- **Detonation engine** *(burner)* — forked from `ossf/package-analysis`: gVisor sandbox, our OSCAR-style harness layered on top (three activation points, typed-parameter fuzzer, AOP hooks for net/fs/proc, gVisor trace points for syscall ground truth). Runs on the disposable host, not localhost. Emits a normalized behavior log that ships back to the control plane.
- **Behavioral rule engine** *(local)* — OSCAR's whitelist/blacklist heuristics over the returned log; deterministic, fast, explainable, and the backstop when the LLM is unavailable or disagrees.
- **LLM triage (Codex)** *(local)* — structured verdict from source + behavior log + diff, with a written rationale and a confidence. Pluggable model interface.
- **Verdict engine & policy** *(local)* — combines signals into a weighted score, applies org policy (thresholds, allowlists, "block on maintainer change", license rules), outputs allow / block / quarantine.
- **Verdict store** *(local)* — content-addressed by `(ecosystem, name, version, digest)`, cosign-signed, shareable across a team so analysis is paid once.
- **Review UI / CLI** *(local)* — a queue for quarantined packages: show the diff, the behavior log, the LLM rationale; let a human allow/block, which feeds back as labels.

**Why the burner is the load-bearing safety decision.** Detonating on the machine you're trying to protect is self-defeating: the fuzzer's whole job is to trigger payloads, and package-analysis wants a privileged outer container anyway. So detonation runs on a separate ephemeral host — Firecracker/Kata locally, or a short-lived EC2 instance — with no credentials, the SSH agent stripped, the cloud **metadata endpoint blocked** (the exact hole behind the 2020 GKE gVisor escape, which reached the GCE metadata API through a network-policy gap rather than breaking isolation), egress pointed at a sinkhole/recording resolver, and the whole instance torn down after each batch. This reframes the scary question. It stops being "is gVisor unescapable?" — nothing is — and becomes "what does an escape actually buy the attacker?" Answer: a root shell in an empty, credential-free room that's about to be demolished, with no network path out. That's a containment story I'd stake the design on.

**Tech choices (proposed):** Go for the proxy and pipeline orchestrator (matches package-analysis, good concurrency, single binary); the detonation harnesses in JS and Python natively (they must run inside the target runtimes); gVisor for the sandbox, with its trace points / remote-sink for syscall telemetry (not host-side Falco, which can't see guest syscalls under gVisor); SQLite/Postgres for the verdict store; cosign for signing; Codex via the Codex SDK / `codex exec`. The burner is provisioned as disposable infra (Terraform/cloud-init or a local microVM), reachable from the control plane over a single narrow control channel.

---

## 4. Verdict model

No single signal decides. Each stage emits findings with severity; the verdict engine computes a weighted risk score and maps it through policy:

- **Hard block (any one):** OSV critical vuln at this version; blacklist behavior with high confidence (credential exfil to unknown domain, reverse shell, known-malware signature); Sigstore provenance verification failure where provenance is expected.
- **Quarantine for human review:** sensitive-data-to-unknown-domain (OSCAR's manual-review class); suspicious diff (new install script, maintainer change + new network behavior); LLM flags but rules don't, or vice-versa (disagreement is a signal).
- **Allow:** clean static + no blacklist behavior + benign diff + LLM concurs, or an exact digest match to an already-trusted verdict.

Two deliberate biases, both from OSCAR's results: optimize for **precision** (a false block that stalls a build erodes trust faster than anything), and treat **benign-but-suspicious** packages as the hard case the whole design exists to get right — that's where naive scanners produce 35%+ false positives and where detonation + diffing earns its keep.

---

## 5. Phased build

**Phase 0 — Spike & de-risk (1–2 wks).** Two goals, neither of which needs live malware: prove the telemetry plumbing and prove the Codex verdict path. Stand up `ossf/package-analysis` and detonate (a) benign packages like `express` / `Django` to confirm the logs are well-formed, and (b) a *synthetic* sample we write ourselves that deliberately trips every hook — opens a socket, reads `/etc/passwd`, spawns `nc`, writes a temp file, resolves a domain — to confirm gVisor's trace points / remote-sink deliver the syscall stream we're counting on in place of Falco, and that our rules fire on known-safe-but-suspicious behavior. Run `codex exec --output-schema` over one log and confirm a clean structured verdict. Decide Go module layout. *Exit:* every hook and rule exercised by known inputs, the syscall-telemetry path proven, a structured verdict round-tripped. **No third-party malicious package runs in this phase — live-corpus detonation from `ossf/malicious-packages` waits for the burner in Phase 3.**

**Phase 1 — The gate, dumb (2–3 wks).** Pull-through proxy for npm + PyPI with a real cache; installs work through it with analysis stubbed to always-allow. This is the riskiest integration surface (registry protocol edge cases, tarball streaming, dist-tags, PEP 503), so build it first and prove `npm install` / `pip install` are transparent through it. *Exit:* a dev can point their tooling at Detonator and not notice.

**Phase 2 — Static + OSV + differ (2–3 wks).** Real static analyzer, OSV lookup, and the version differ. Wire the verdict engine with static-only signals. Now the gate can actually block on cheap signals. *Exit:* known-CVE and obvious-install-script-malware packages get blocked; diffs render.

**Phase 3 — Detonation + behavioral rules (3–4 wks).** Move detonation onto the disposable burner host — **this is where the EC2 node comes in, and the first time any third-party malicious package actually runs, only ever here** — and layer the OSCAR harness onto package-analysis: three activation points, typed-parameter fuzzer, AOP hooks, and gVisor trace points for syscalls. Lock the burner down (no creds, metadata blocked, egress sinkholed, auto-teardown) and prove the control-plane↔burner round trip. Port the whitelist/blacklist rule set. This is the technical heart and the longest phase. *Exit:* reproduce OSCAR-class detection on the labelled corpus; measure F1/precision against the 0.95/0.91 targets.

**Phase 4 — Codex triage + policy + signing (2–3 wks).** LLM triage stage behind a pluggable model interface; verdict engine blends rules + LLM; cosign-signed verdict cache; org policy config. *Exit:* full allow/block/quarantine flow with signed, shareable verdicts.

**Phase 5 — Review UI, hardening, benchmark (2–3 wks).** Quarantine review queue, feedback loop, anti-evasion hardening (sandbox timing, resource caps, non-determinism), and a published benchmark run vs the labelled set with a false-positive audit on popular real packages. *Exit:* precision/recall numbers you'd put in front of a security team.

Rough total: ~3–4 months to a defensible v1 for one engineer, faster with two (proxy and detonation engine parallelize cleanly).

---

## 6. Known risks & honest limits

- **Sandbox evasion, not escape, is the likelier failure.** The nastier problem than a break-out is a payload that detects the sandbox, stays dormant, and earns a false "allow." OSCAR admits this limit directly. This is where I'd spend hardening budget, and it's the main argument for fail-to-review when the behavioral and LLM signals disagree.
- **Fuzzing executes attacker code by design — so we make escape worthless, not impossible.** The fuzzer *wants* to trigger payloads, so escape is the catastrophic failure mode, and no sandbox is provably unescapable. We manage it by topology: detonation runs on the disposable burner, so a gVisor break lands in a credential-free box with the metadata endpoint blocked and egress sinkholed, destroyed after the batch. gVisor + no host network + strict resource/time caps + per-batch teardown are non-negotiable, and the burner is the one component to threat-model hardest. Grounding note: mass-published supply-chain malware is nearly all commodity credential/info-stealers (OSCAR's corpus was ~89% info-leak) that assume a real developer laptop — nobody burns a gVisor 0-day inside a public npm package, because it would be captured and patched within days. The burner design means even if someone did, it costs them nothing of yours.
- **Sandbox coverage gaps.** OSCAR misses Windows-only payloads (Linux sandbox) and malware behind hard-to-construct function parameters. We inherit both. Mitigation: fuzzing depth, syscall ground truth, and quarantine-on-uncertainty rather than pretending to catch everything.
- **Latency vs. developer patience.** ~128–165s per *new* version is fine because it's cached and paid once, but a cold `npm ci` on a fresh lockfile could detonate dozens of packages. Mitigations: heavy concurrency across burner instances, a shared team cache, tiered analysis (static fast-path allows obvious-good instantly, detonation only for new/changed/suspicious), and pre-warming popular packages.
- **Sending source to Codex.** The hosted-API path ships package source to a third party. That's why the model layer is pluggable — Kimi K3 self-hosted or a local model for sensitive contexts, hosted Codex for speed. Make it a policy toggle.
- **Determinism & caching correctness.** Verdicts key on artifact digest, not name+version, so a re-published version with the same number but different bytes must invalidate. Getting this wrong is a silent bypass.
- **Maintenance drift.** Rules and hooks rot as ecosystems change; the malicious-packages corpus and the human-review feedback loop are what keep it current. Budget for it as ongoing, not one-time.

---

## 7. Decisions

Resolved July 2026. Each preserves the design's two biases — precision over recall, and *make escape worthless, not impossible* — and keeps the expensive or irreversible choices (shared-store service, local microVM, fail-closed) as later opt-ins rather than day-one commitments.

- **Codex model tier & auth → GPT-5.6 Sol Medium, OAuth for dev.** Triage is the load-bearing security judgment, and it runs once per new version and is cached, so the cost is amortized — no reason to weaken it with a `-mini` tier. Default the triage model to GPT-5.6 Sol Medium. Auth via subscription OAuth (`~/.codex/auth.json`) while this is a solo spike; add the API-key path when there's CI. The pluggable model interface stays the escape hatch for source we won't send to a third party.
- **Burner lifecycle → spin-up-per-batch, EC2-only, custom AMI.** Per-batch teardown *is* the containment story, so the burner stays disposable — no long-lived-but-wiped host to drift. Kill the 3–5 min cloud-init cold start by baking a custom AMI (Docker + gVisor + package-analysis pre-installed) once Phase 0 proves the setup. Skip local Firecracker for v1, but define the burner as a narrow interface — take an artifact, return a behavior log — so a local-microVM driver can slot in later for air-gapped use without touching the pipeline.
- **Cache → local-first, signed from day one.** The shared distribution service is deferred, but the two things that make sharing possible later are cheap now and painful to retrofit: content-addressed keys `(ecosystem, name, version, digest)` and a cosign signature on every verdict. Include both from the start; ship the team-shared store later. A schema decision, not a service decision.
- **Quarantine default → fail-to-review (queue), policy-configurable.** A false block stalls a build and burns trust; a queue entry doesn't. Default to queue, expose it as org policy so a high-security org can flip to fail-closed. Rule/LLM disagreement stays a first-class quarantine trigger either way.
- **Scope guardrail → npm + PyPI for v1.** Containers/OCI, Rust/Go, and editor extensions are real attack surfaces but v2, on the same pipeline shape.

---

*Sources: OSCAR — arXiv 2409.09356; OpenSSF package-analysis, malicious-packages, Scorecard, OSV, Sigstore/GUAC; the 2020 GKE gVisor metadata-API escape (cloudvulndb.org); gVisor trace-point / remote-sink telemetry; OpenAI Codex `exec` headless guide; Kimi K3 spec (OpenRouter) as the pluggable fallback model.*
