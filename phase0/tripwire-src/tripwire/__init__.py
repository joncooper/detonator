"""Synthetic detonation test sample — HARMLESS by construction.

This is NOT malware. It is the *shape* of malicious behavior with every payload
removed, so Phase 0 can confirm the sandbox telemetry actually captures each
class of action before we ever run a real sample on the burner.

Each function trips exactly one Detonator hook / rule:
  - _read_sensitive : sensitive-file read  (blacklist rule: /etc/passwd)
  - _spawn          : process spawn        (child_process / subprocess hook)
  - _dns_and_connect: DNS + network        (dns + socket hooks)
  - _write_temp     : filesystem write     (fs hook; whitelisted temp path)

Nothing is exfiltrated: reads report only a byte count, the network step connects
to a benign host and sends nothing, spawned commands have their output discarded.
"""
import os
import socket
import subprocess
import tempfile

# Point this at your recording sinkhole for the real burner; defaults to a benign host.
SINK_HOST = os.environ.get("TRIPWIRE_SINK", "example.com")


def _read_sensitive():
    """Sensitive-file read. We measure length only — exfiltrate nothing."""
    try:
        with open("/etc/passwd", "rb") as fh:
            return len(fh.read())
    except OSError:
        return -1


def _spawn():
    """Process-spawn hook target. Benign command, output discarded."""
    try:
        return subprocess.run(["id"], capture_output=True).returncode
    except OSError:
        return -1


def _dns_and_connect():
    """DNS + network hooks. Resolve and TCP-connect to a benign host; send nothing."""
    try:
        addr = socket.gethostbyname(SINK_HOST)
        conn = socket.create_connection((addr, 80), timeout=3)
        conn.close()
        return addr
    except OSError:
        return None


def _write_temp():
    """Filesystem-write hook target (temp path — a whitelisted location)."""
    path = os.path.join(tempfile.gettempdir(), "tripwire.marker")
    with open(path, "w") as fh:
        fh.write("detonator-tripwire")
    return path


def run():
    """Fire every hook. Returns a summary dict; performs no exfiltration."""
    return {
        "sensitive_bytes": _read_sensitive(),
        "spawn_rc": _spawn(),
        "resolved": _dns_and_connect(),
        "temp": _write_temp(),
    }


# Some real malware acts at import time, so fire the cheap, safe subset on import too.
_read_sensitive()
