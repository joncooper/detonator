# Phase 0 Runbook — prove the telemetry + verdict path on a burner

**Goal:** confirm two things before we build anything on top — (1) the sandbox behavior log has the syscall-level fidelity our rules need, captured via gVisor rather than Falco, and (2) a behavior log round-trips through Codex into a clean structured verdict. **No third-party malware runs in this phase.** We use benign packages plus a synthetic sample that trips every hook by design.

Everything runs on a disposable EC2 burner: no IAM role, IMDS disabled, metadata endpoint firewalled, torn down after. An escape lands in an empty, credential-free box that terminates on shutdown.

---

## Prereqs (on your machine)

- AWS CLI configured (`aws sts get-caller-identity` works).
- Your public IP: `curl -s https://checkip.amazonaws.com`.

No EC2 key pair needed up front — the launch script mints a dedicated one for
the burner and writes its private key next to the script (torn down with the
host). Set `KEY_NAME` only if you want to reuse an existing key pair.

## 1 — Launch the burner

From the `phase0/` directory (so `burner-setup.sh` is next to the launch script):

```bash
export MY_IP=$(curl -s https://checkip.amazonaws.com)
export REGION=us-east-1            # optional, defaults to us-east-1
bash burner-launch.sh
```

It mints a burner-only SSH key, then prints the instance ID, the ready-to-use
SSH command (with `-i <key>.pem`), and the exact teardown commands (including
deleting the minted key). Setup (Docker + gVisor + package-analysis) runs via
cloud-init in ~3–5 min.

## 2 — Confirm it's ready

```bash
ssh ubuntu@<IP> 'cloud-init status --wait && cat /opt/BURNER_READY'
# expect: BURNER READY: docker+runsc+package-analysis installed, metadata blocked, no IAM role
```

Sanity-check the lockdown while you're in:

```bash
ssh ubuntu@<IP> 'curl -s --max-time 3 http://169.254.169.254/latest/meta-data/ ; echo "exit=$?"'
# expect: a timeout / non-200 — the metadata endpoint is black-holed
```

## 3 — Benign smoke detonation

Confirms the pipeline produces a well-formed log on a known-good package.

```bash
ssh ubuntu@<IP>
cd /opt/package-analysis
sudo scripts/run_analysis.sh -ecosystem pypi -package requests
sudo cat /tmp/results/*.json | jq '.'      # files / sockets / commands / DNS captured
```

> If the script asks for a runtime/privileged flag, gVisor is installed on the host (`runsc`) and registered as a Docker runtime — we'll wire the exact invocation here; that's part of what this spike settles.

## 4 — Synthetic tripwire detonation

Build the harmless sample into an sdist and detonate it. This is the real telemetry test — we know exactly what it *should* do, so we can check the log caught all of it.

```bash
# copy the tripwire source up (from your machine, in phase0/)
scp -r tripwire-src ubuntu@<IP>:/home/ubuntu/tripwire-src

# on the burner
ssh ubuntu@<IP>
cd /home/ubuntu/tripwire-src
python3 -m pip install --quiet build 2>/dev/null || sudo apt-get install -y python3-build
python3 -m build --sdist          # -> dist/tripwire-0.0.1.tar.gz
cd /opt/package-analysis
sudo scripts/run_analysis.sh -ecosystem pypi -local /home/ubuntu/tripwire-src/dist/tripwire-0.0.1.tar.gz
sudo cat /tmp/results/*.json | jq '.' | tee ~/tripwire-result.json
```

## 5 — What the log must show

The tripwire fires four behaviors. Confirm each appears in the log — this is the pass/fail for the telemetry path:

| Behavior in the sample        | Must appear in the log as                        |
|-------------------------------|--------------------------------------------------|
| read `/etc/passwd`            | a file **read** of `/etc/passwd`                 |
| `subprocess.run(["id"])`      | a **command/exec** of `id`                       |
| resolve + TCP-connect host    | a **DNS** query and an outbound **socket** connect |
| write temp marker file        | a file **write** under the temp dir              |

If all four are present with syscall-level detail (paths, addresses, argv), the gVisor telemetry path is proven and Falco is confirmed unnecessary. If any is missing, that's exactly the gap Phase 0 exists to find — note which, and we adjust the harness before Phase 3.

## 6 — Verdict path (Codex)

If you have the `codex` CLI set up (ChatGPT-sub OAuth or `OPENAI_API_KEY`):

```bash
# on your machine or the burner, next to verdict-schema.json, with the log at ./tripwire-result.json
codex exec --output-schema verdict-schema.json --ask-for-approval never --sandbox read-only \
  "You are a software supply-chain malware triage system. Using ONLY this dynamic-analysis \
   behavior log, classify the package and return the schema. Log:
$(cat tripwire-result.json)"
```

Expect a JSON object matching `verdict-schema.json` (`verdict`/`confidence`/`rationale`/`signals`). The tripwire *should* read as `quarantine` or `block` — it reads `/etc/passwd` and opens a socket — which confirms the model sees the signals. This proves the structured-output path end to end; blending it with the rule engine is Phase 4.

## 7 — Hand back

Paste `tripwire-result.json` (or just the sockets/files/commands sections) back into our chat and I'll check it has everything the rule engine needs and sanity-check the Codex verdict. Or, if you prefer I drive, set up SSH access and I'll run steps 3–6.

## Teardown

```bash
aws ec2 terminate-instances --region $REGION --instance-ids <INSTANCE_ID>
aws ec2 delete-security-group --region $REGION --group-id <SG_ID>
aws ec2 delete-key-pair       --region $REGION --key-name <KEY_NAME>   # if minted
rm -f phase0/<KEY_NAME>.pem                                            # if minted
# or, from on the box:  sudo shutdown -h now   (shutdown-behavior=terminate destroys it)
```

The exact teardown commands (with real ids) are printed by `burner-launch.sh`.

---

### Exit criteria

- [ ] Burner launches hardened (no role, IMDS off, metadata firewalled) and self-reports ready
- [ ] Benign package produces a well-formed behavior log
- [ ] Synthetic tripwire log shows all four behaviors with syscall-level detail
- [ ] A behavior log round-trips through Codex into a schema-valid verdict
- [ ] We've noted any telemetry gaps to close before Phase 3
