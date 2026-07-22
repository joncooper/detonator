# Detonator eval — 2026-07-21

Blind evaluation of the Detonator pipeline (static + OSV + behavioral rules)
against the WhoaThere real-malware corpus, detonated on a disposable EC2 burner
through the recording sinkhole. The detector received only the source + the
behavior trace — never the ground-truth labels.

## Headline

- **Recall: 9/10 blind malware detected (90%)** — 5 block, 4 quarantine, 1 miss.
- **Precision: 4/4 benign `allow` (0% false positives).**
- One miss: `the-matrix-ai-premium` (malice buried in a large trojanized dev tool).

The number moved **8/8 (inflated, noise-based) → 62% (honest) → 90% (honest,
after the recording sinkhole + static payload rules)**. The benign baseline is
what exposed the inflation: the first pass had 100% false positives on
package-manager noise (`~/.npmrc`, `/etc/passwd`) that also drove several
"detections".

## Per-sample (blind, networked)

| Sample | Verdict | Caught by |
|---|---|---|
| moltbook-api-helper | block | exfil-chain, ssh-key, unknown-domain |
| moltbook-health | quarantine | unknown-domain C2 (recording sinkhole) |
| sbx | block | cloud-metadata, exfil-chain, encoded-C2 |
| strapi-nordica-tools | quarantine | hardcoded-ip-endpoint (static) |
| the-matrix-ai-premium | **allow (MISS)** | — |
| react-router | quarantine | unknown-domain C2 |
| solution-tool | quarantine | encoded-network-indicator |
| telnyx 4.87.1 / 4.87.2 ×2 | block | dynamic-exec-decoded + encoded-C2 (static) |
| left-pad / is-number / six / certifi (benign) | allow | — (0 FP) |

## C2 IOCs captured

Behavioral (recording sinkhole, TLS SNI / DNS):
- `probe-worker.hugebigballs87.workers.dev` — Cloudflare Workers C2
- `moltbook-health.the-l.ink`
- `unexpected-conflicts-compiled-anymore.trycloudflare.com` — Cloudflare tunnel C2
- `hooks.slack.com` — Slack-webhook exfil
- `codeload.github.com` — GitHub-hosted second stage

Static (decoded / hardcoded):
- `http://83.142.209.203:8080/hangup.wav` — telnyx (base64'd)
- `144.31.107.231:9999` — strapi (plaintext, plain-HTTP exfil)

## Methodology notes

- Offline (`--network none`) suppressed the strongest discriminator (egress) and
  broke dependency installs; the **recording sinkhole** (fake resolver + TLS
  sinkhole + registry allowlist) fixed both — real deps install, payloads run,
  C2/second-stage land in the recorder, nothing reaches the real internet.
- Tier-3 signals (`~/.npmrc`, `/etc/passwd`, `/etc/shadow`, bare `sh -c`) were
  dropped — the benign baseline proved they are package-manager/sandbox noise.
- Detection now rests on discriminating signals only: unknown-domain egress,
  cloud-metadata access, unambiguous credential-store reads, exfil chain, and
  the static payload rules (dynamic-exec-decoded, encoded/hardcoded C2).

## Caveats / next

- Benign set is only 4 packages; the new static rules are precise by
  construction but "0% FP" needs a **large** benign cohort (incl. minified
  bundles, dynamic loaders, IP-using packages) to confirm at scale.
- `the-matrix-ai-premium` needs a targeted signature or the payload to actually
  fire; HTTPS exfil bodies from cert-verifying clients stay opaque (SNI only).
- Expand the corpus (real via MalwareBazaar + synthetic modeling current
  in-the-wild techniques) and ground the tier weights against
  `ossf/malicious-packages`, GuardDog, and package-analysis traces.

Raw behavior traces are under `traces/`; captured DNS/TCP in `dns.log`/`tcp.log`;
verdicts in `*-verdicts.jsonl`.
