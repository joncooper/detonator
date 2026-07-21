#!/usr/bin/env python3
# Recording TCP sinkhole: accepts any redirected connection, recovers the
# original destination (SO_ORIGINAL_DST), captures the TLS SNI or the plaintext
# request (the exfil payload / second-stage fetch), logs it, and answers so the
# sample proceeds. Nothing is forwarded to the real internet.
import socket, struct, threading, time
LOG = "/home/ubuntu/sink/tcp.log"
SO_ORIGINAL_DST = 80

def orig_dst(c):
    x = c.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    return ".".join(map(str, x[4:8])), struct.unpack(">H", x[2:4])[0]

def sni(d):
    try:
        if d[0] != 0x16:
            return None
        i = 5 + 4 + 2 + 32                 # record + handshake hdr + version + random
        i += 1 + d[i]                      # session id
        i += 2 + struct.unpack(">H", d[i:i+2])[0]   # cipher suites
        i += 1 + d[i]                      # compression methods
        end = i + 2 + struct.unpack(">H", d[i:i+2])[0]; i += 2   # extensions
        while i + 4 <= end:
            et = struct.unpack(">H", d[i:i+2])[0]
            el = struct.unpack(">H", d[i+2:i+4])[0]; i += 4
            if et == 0:                    # server_name
                j = i + 2; nl = struct.unpack(">H", d[j+1:j+3])[0]
                return d[j+3:j+3+nl].decode("latin1")
            i += el
    except Exception:
        return None
    return None

def handle(c, a):
    try:
        oip, oport = orig_dst(c)
        c.settimeout(4)
        try:
            data = c.recv(8192)
        except Exception:
            data = b""
        if data[:1] == b"\x16":
            info = "TLS sni=%s hello_bytes=%d" % (sni(data), len(data))
        else:
            info = "plaintext=%r" % (data[:400],)
        with open(LOG, "a") as f:
            f.write("%.3f src=%s orig_dst=%s:%d %s\n" % (time.time(), a[0], oip, oport, info))
        if data[:1] != b"\x16":
            try:
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except Exception:
                pass
    finally:
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
