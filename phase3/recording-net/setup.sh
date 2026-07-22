#!/usr/bin/env bash
# Bring up the recording detonation network on a fresh burner, one command.
# Run as `ubuntu` (sudo available) from the dir holding resolver.py + sinkhole.py.
#
# Result: the sandbox installs real deps from the registry, its payload runs, and
# every exfil/second-stage connection lands in the recorders — while real-internet
# egress is denied. See README.md.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SINK=/home/ubuntu/sink
mkdir -p "$SINK"; : > "$SINK/dns.log"; : > "$SINK/tcp.log"
cp "$HERE/resolver.py" "$HERE/sinkhole.py" /home/ubuntu/

WAN=$(ip route show default | awk '/default/{print $5; exit}')
DOCKER=docker0
echo "WAN=$WAN  DOCKER=$DOCKER"

command -v jq >/dev/null || sudo apt-get install -y -qq jq >/dev/null
command -v 7z >/dev/null || sudo apt-get install -y -qq p7zip-full unzip >/dev/null 2>&1 || true

# self-signed cert for TLS termination
[ -f "$SINK/sink.crt" ] || openssl req -x509 -newkey rsa:2048 \
  -keyout "$SINK/sink.key" -out "$SINK/sink.crt" -days 3 -nodes -subj "/CN=sinkhole" >/dev/null 2>&1

# resolve registry endpoints to stable IPs (the egress allowlist)
python3 - "$SINK" <<'PY'
import json, subprocess, sys
m = {}
for d in ("registry.npmjs.org", "files.pythonhosted.org", "pypi.org"):
    try:
        m[d] = subprocess.check_output(["getent", "ahostsv4", d]).decode().split()[0]
    except Exception:
        pass
json.dump(m, open(sys.argv[1] + "/registry_ips.json", "w"))
print("registry map:", m)
PY
REGIPS=$(python3 -c "import json;print(' '.join(json.load(open('$SINK/registry_ips.json')).values()))")

# start recorders (idempotent, detached under systemd)
sudo systemctl reset-failed det-resolver det-sinkhole 2>/dev/null || true
systemctl is-active --quiet det-resolver || sudo systemd-run --unit=det-resolver --collect python3 /home/ubuntu/resolver.py
systemctl is-active --quiet det-sinkhole || sudo systemd-run --unit=det-sinkhole --collect python3 /home/ubuntu/sinkhole.py
sleep 2

# egress: keep SSH + established + loopback, allow registry IPs, deny the rest
sudo iptables -C OUTPUT -p tcp --sport 22 -j ACCEPT 2>/dev/null || sudo iptables -I OUTPUT 1 -p tcp --sport 22 -j ACCEPT
sudo iptables -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || sudo iptables -I OUTPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || sudo iptables -I OUTPUT 3 -o lo -j ACCEPT
for ip in $REGIPS; do
  sudo iptables -C OUTPUT -d "$ip" -p tcp -j ACCEPT 2>/dev/null || sudo iptables -I OUTPUT 4 -d "$ip" -p tcp -j ACCEPT
  sudo iptables -C FORWARD -d "$ip" -p tcp -j ACCEPT 2>/dev/null || sudo iptables -I FORWARD 1 -d "$ip" -p tcp -j ACCEPT
done
sudo iptables -C OUTPUT -o "$WAN" -j DROP 2>/dev/null || sudo iptables -A OUTPUT -o "$WAN" -j DROP
sudo iptables -C FORWARD -o "$WAN" -j DROP 2>/dev/null || sudo iptables -I FORWARD 1 -o "$WAN" -j DROP

# redirect the sandbox's DNS + non-registry TCP into the recorders
sudo iptables -t nat -F PREROUTING
for ip in $REGIPS; do sudo iptables -t nat -A PREROUTING -i "$DOCKER" -p tcp -d "$ip" -j RETURN; done
sudo iptables -t nat -A PREROUTING -i "$DOCKER" -p udp --dport 53 -j REDIRECT --to-ports 5353
sudo iptables -t nat -A PREROUTING -i "$DOCKER" -p tcp -j REDIRECT --to-ports 8443

echo "recorders: resolver=$(systemctl is-active det-resolver) sinkhole=$(systemctl is-active det-sinkhole)"
echo -n "generic egress: "; timeout 5 curl -sS https://example.com/ >/dev/null 2>&1 && echo "OPEN (BAD)" || echo "denied (good)"
echo "READY: detonate networked (drop -offline/-fully-offline; keep -nopull -local)."
