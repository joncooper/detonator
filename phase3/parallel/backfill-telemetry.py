#!/usr/bin/env python3
"""Back-fill raw telemetry for samples already detonated.

pdet.py originally kept only the summarised results.json (~170KB/sample) and
discarded the evidence it was derived from: the gVisor boot log is a full syscall
strace (~18MB/sample — every open/exec/connect with arguments) and
write_buffers_.zip holds the bytes the package actually wrote. Those are exactly
what you need to prototype a detector that uses a signal the current summariser
does not extract, and re-detonating to get them back costs burner-hours.

The res/ trees are still on disk, so this recovers them. Compressed ~1-2MB/sample.
"""
import os, glob, shlex, subprocess, sys

CORPUS = sys.argv[1] if len(sys.argv) > 1 else "/home/ubuntu/benigncorpus"
dstroot = CORPUS + "/telemetry"
os.makedirs(dstroot, exist_ok=True)

done = skipped = 0
for rd in sorted(glob.glob(CORPUS + "/res/*")):
    name = os.path.basename(rd)
    dst = f"{dstroot}/{name}"
    if os.path.exists(dst + "/strace.log.gz"):
        skipped += 1
        continue
    os.makedirs(dst, exist_ok=True)
    boots = glob.glob(rd + "/l/*/runsc.log.boot")
    if boots:
        biggest = max(boots, key=os.path.getsize)
        subprocess.run(
            f"sudo gzip -c {shlex.quote(biggest)} > {shlex.quote(dst)}/strace.log.gz",
            shell=True, timeout=300)
    for src, out in ((rd + "/fw/write_buffers_.zip", "write_buffers.zip"),
                     (rd + "/s/results.json", "static.json")):
        if os.path.exists(src):
            subprocess.run(["sudo", "cp", src, f"{dst}/{out}"], timeout=120)
    done += 1
    if done % 25 == 0:
        print(f"  {done} back-filled", flush=True)

subprocess.run(["sudo", "chown", "-R", "ubuntu:ubuntu", dstroot], timeout=300)
size = subprocess.run(["du", "-sh", dstroot], capture_output=True, text=True).stdout.split()[0]
print(f"back-filled {done} (skipped {skipped}) -> {dstroot} [{size}]")
