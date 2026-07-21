#!/usr/bin/env python3
# Recording TCP sinkhole with TLS termination. Accepts any redirected connection,
# recovers the original destination (SO_ORIGINAL_DST), captures the TLS SNI, and
# — for clients that don't verify the cert (common in stealers) — completes the
# handshake with a self-signed cert and captures the DECRYPTED request (the
# exfiltrated payload / second-stage fetch). Clients that verify the cert still
# yield the SNI plus a handshake-refused note. Nothing is forwarded upstream.
import socket, struct, threading, time, ssl

LOG = "/home/ubuntu/sink/tcp.log"
CERT = "/home/ubuntu/sink/sink.crt"
KEY = "/home/ubuntu/sink/sink.key"
SO_ORIGINAL_DST = 80

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)

def orig_dst(c):
    x = c.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    return ".".join(map(str, x[4:8])), struct.unpack(">H", x[2:4])[0]

def sni(d):
    try:
        if d[0] != 0x16:
            return None
        i = 5 + 4 + 2 + 32
        i += 1 + d[i]
        i += 2 + struct.unpack(">H", d[i:i+2])[0]
        i += 1 + d[i]
        end = i + 2 + struct.unpack(">H", d[i:i+2])[0]; i += 2
        while i + 4 <= end:
            et = struct.unpack(">H", d[i:i+2])[0]
            el = struct.unpack(">H", d[i+2:i+4])[0]; i += 4
            if et == 0:
                j = i + 2; nl = struct.unpack(">H", d[j+1:j+3])[0]
                return d[j+3:j+3+nl].decode("latin1")
            i += el
    except Exception:
        return None
    return None

def log(line):
    with open(LOG, "a") as f:
        f.write(line + "\n")

def handle(c, a):
    try:
        oip, oport = orig_dst(c)
        c.settimeout(5)
        try:
            head = c.recv(2048, socket.MSG_PEEK)
        except Exception:
            head = b""
        ts = time.time()
        if head[:1] == b"\x16":
            server = sni(head)
            try:
                ss = ctx.wrap_socket(c, server_side=True)
                try:
                    req = ss.recv(16384)
                except Exception:
                    req = b""
                log("%.3f src=%s orig_dst=%s:%d TLS sni=%s DECRYPTED=%r" %
                    (ts, a[0], oip, oport, server, req[:600]))
                try:
                    ss.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                except Exception:
                    pass
                ss.close()
            except ssl.SSLError:
                log("%.3f src=%s orig_dst=%s:%d TLS sni=%s handshake-refused(client-verifies-cert)" %
                    (ts, a[0], oip, oport, server))
                c.close()
        else:
            try:
                data = c.recv(8192)
            except Exception:
                data = b""
            log("%.3f src=%s orig_dst=%s:%d plaintext=%r" % (ts, a[0], oip, oport, data[:600]))
            try:
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except Exception:
                pass
            c.close()
    except Exception:
        try:
            c.close()
        except Exception:
            pass

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 8443))
srv.listen(128)
while True:
    try:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()
    except Exception:
        pass
