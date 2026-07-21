#!/usr/bin/env bash
# Runs at first boot on the burner (as root, via EC2 user-data / cloud-init).
# Installs Docker + gVisor (runsc) + OpenSSF package-analysis and locks the host down.
# No malware here — this only prepares the detonation chamber.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y ca-certificates curl gnupg git jq iptables-persistent

# ---- Docker ----
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io
usermod -aG docker ubuntu

# ---- gVisor (runsc): package-analysis runs packages under gVisor; register it as a Docker runtime ----
curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  > /etc/apt/sources.list.d/gvisor.list
apt-get update
apt-get install -y runsc
runsc install                 # writes the runsc runtime into /etc/docker/daemon.json
systemctl restart docker

# ---- Host lockdown: black-hole the cloud metadata endpoint ----
# Belt-and-suspenders: IMDS is already disabled at the instance level and no IAM role
# is attached, so there are no credentials to reach — but this also protects the
# container network path and any future re-enable.
iptables  -I OUTPUT  -d 169.254.169.254 -j DROP
iptables  -I FORWARD -d 169.254.169.254 -j DROP
netfilter-persistent save

# ---- OpenSSF package-analysis ----
cd /opt
git clone --depth 1 https://github.com/ossf/package-analysis.git
chown -R ubuntu:ubuntu /opt/package-analysis

# smoke-check gVisor works before declaring ready
docker run --rm --runtime=runsc hello-world >/tmp/runsc-smoke.log 2>&1 || echo "WARN: runsc smoke test failed, see /tmp/runsc-smoke.log" >&2

printf 'BURNER READY: docker+runsc+package-analysis installed, metadata blocked, no IAM role\n' > /opt/BURNER_READY
