#!/usr/bin/env python3
# Recording fake resolver. Registry domains resolve to their real IP (so the
# sandbox can fetch real dependencies and the payload actually runs); every other
# name resolves to a sinkhole IP so the exfil/second-stage connect lands in our
# recorder. All queries are logged.
import socket, struct, time, json, os
LOG = "/home/ubuntu/sink/dns.log"
SINK = bytes([192, 0, 2, 1])
MAP_PATH = "/home/ubuntu/sink/registry_ips.json"

def load_map():
    try:
        return json.load(open(MAP_PATH))
    except Exception:
        return {}

REG = load_map()
REG_SUFFIXES = ("npmjs.org", "npmjs.com", "yarnpkg.com", "pythonhosted.org", "pypi.org")

def registry_ip(name):
    n = name.lower().rstrip(".")
    if n in REG:
        return REG[n]
    if any(n == s or n.endswith("." + s) for s in REG_SUFFIXES):
        # a registry subdomain we didn't pre-resolve: fall back to the npm IP
        for k in ("registry.npmjs.org", "files.pythonhosted.org", "pypi.org"):
            if k in REG:
                return REG[k]
    return None

def qname(d):
    i = 12; parts = []
    while d[i] != 0:
        l = d[i]; parts.append(d[i+1:i+1+l].decode("latin1")); i += l + 1
    return ".".join(parts), i + 1

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 5353))
while True:
    try:
        d, a = s.recvfrom(2048)
        name, qe = qname(d)
        qtype = struct.unpack(">H", d[qe:qe+2])[0]
        regip = registry_ip(name)
        with open(LOG, "a") as f:
            f.write("%.3f %s %s type=%d -> %s\n" % (time.time(), a[0], name, qtype, regip or "SINK"))
        tid = d[:2]; q = d[12:qe+4]
        if qtype == 1:
            ip = bytes(int(x) for x in regip.split(".")) if regip else SINK
            hdr = tid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            ans = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" + ip
            s.sendto(hdr + q + ans, a)
        else:
            hdr = tid + b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
            s.sendto(hdr + q, a)
    except Exception:
        pass
