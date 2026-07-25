#!/usr/bin/env bash
# Stand up local registry mirrors so a detonating package can resolve its real
# dependencies with ZERO egress to the internet.
#
# Why not the previous approach: the sinkhole allowlisted the registries by IP.
# That failed two ways — the FORWARD chain's blanket DROP was ordered before the
# registry ACCEPTs, and the registries are anycast CDNs whose resolved address is
# neither stable nor reachable from the host. So pip could never fetch build
# dependencies and every pypi behavioural result was undercounted.
#
# A caching mirror on the burner is strictly better: deps resolve, nothing the
# malware does reaches the real internet, and the mirror's access log is itself a
# record of what the package asked for.
set -u
MIRROR_DIR=/home/ubuntu/mirrors
mkdir -p "$MIRROR_DIR"/{verdaccio,devpi}

DOCKER_GW=$(ip -4 addr show docker0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
DOCKER_GW=${DOCKER_GW:-172.17.0.1}
echo "docker gateway: $DOCKER_GW"

# --- npm mirror: verdaccio, uplinking to the real registry and caching ---
cat > "$MIRROR_DIR/verdaccio/config.yaml" <<'YAML'
storage: /verdaccio/storage
uplinks:
  npmjs:
    url: https://registry.npmjs.org/
    cache: true
packages:
  '**':
    access: $all
    publish: $all
    proxy: npmjs
log: { type: stdout, format: pretty, level: http }
listen: 0.0.0.0:4873
YAML
sudo chown -R 10001:65533 "$MIRROR_DIR/verdaccio" 2>/dev/null || true

sudo docker rm -f verdaccio devpi >/dev/null 2>&1 || true
sudo docker run -d --name verdaccio --restart unless-stopped \
  -p 4873:4873 -v "$MIRROR_DIR/verdaccio":/verdaccio/conf \
  verdaccio/verdaccio:6 >/dev/null 2>&1 && echo "verdaccio started"

# --- pypi mirror: devpi, uplinking to pypi.org and caching ---
sudo docker run -d --name devpi --restart unless-stopped \
  -p 3141:3141 -v "$MIRROR_DIR/devpi":/devpi/server \
  -e DEVPI_PASSWORD=detonator \
  muccg/devpi:latest >/dev/null 2>&1 && echo "devpi started" || echo "devpi image unavailable — will fall back"

sleep 20
echo "--- health ---"
curl -sS -m 10 -o /dev/null -w "verdaccio: http=%{http_code}\n" http://localhost:4873/ 2>&1 || echo "verdaccio: down"
curl -sS -m 10 -o /dev/null -w "devpi:     http=%{http_code}\n" http://localhost:3141/root/pypi/+simple/ 2>&1 || echo "devpi: down"
echo
echo "point the sandbox at:  npm  -> http://$DOCKER_GW:4873"
echo "                       pypi -> http://$DOCKER_GW:3141/root/pypi/+simple/"
