# Recording detonation network

Contained network for detonating live malware: the sample's install and payload
run for real, its exfil/second-stage connections **succeed into a recorder**
(so behavior gated on a working connection actually fires), and **nothing
reaches the real internet** except the package registry.

Without this, `--network none` (fully offline) suppresses the strongest signal —
egress — and dependency installs fail, so payloads that need deps or a live
connection never run. That produced false "misses" in the first corpus pass.

## Pieces

- `resolver.py` — fake DNS on `:5353`. Registry domains (npm/PyPI) resolve to
  their **real** IP so `npm`/`pip` can fetch dependencies; every other name
  resolves to a sinkhole IP (`192.0.2.1`). All queries logged to `sink/dns.log`.
- `sinkhole.py` — TCP recorder on `:8443`. Accepts any redirected connection,
  recovers the original destination (`SO_ORIGINAL_DST`), extracts the TLS SNI or
  plaintext request (the exfil payload / second-stage fetch), logs to
  `sink/tcp.log`, and answers so the sample proceeds.

## Setup (on the burner, host side)

Pre-resolve the registries and allow egress only to those IPs; deny the rest;
redirect the sandbox's DNS and non-registry TCP into the recorders:

```bash
# registry allowlist (real egress so deps install)
for ip in <registry IPs>; do
  sudo iptables -I OUTPUT 4 -d $ip -p tcp -j ACCEPT
  sudo iptables -I FORWARD 1 -d $ip -p tcp -j ACCEPT
done
sudo iptables -A OUTPUT -o <wan> -j DROP        # deny all other host egress
                                                # (FORWARD default DROP contains containers)

# redirect sandbox traffic into the recorders (registry IPs bypass the sinkhole)
for ip in <registry IPs>; do
  sudo iptables -t nat -A PREROUTING -i docker0 -p tcp -d $ip -j RETURN
done
sudo iptables -t nat -A PREROUTING -i docker0 -p udp --dport 53 -j REDIRECT --to-ports 5353
sudo iptables -t nat -A PREROUTING -i docker0 -p tcp             -j REDIRECT --to-ports 8443
```

Then detonate **networked** (drop `-offline`/`-fully-offline`), keeping
`-nopull -local`.

## Known limits

- **HTTPS payloads stay encrypted.** We capture the C2 domain (SNI) and that the
  connection succeeded, but not the exfiltrated bytes. A TLS-terminating sinkhole
  (self-signed, for samples that don't verify) would recover plaintext.
- **Hardcoded-IP C2** is contained and its connect is captured, but only
  sinkholed if the broad TCP redirect is in place (it is, above).
- **Registry CDN IPs can rotate**; re-resolve per burner generation.
