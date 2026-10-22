import gdb


def iv(expr):
    try:
        return int(gdb.parse_and_eval(expr))
    except Exception:
        return -1


def bss():
    return iv("ps_globals.http_session_vars.value.ptr")


def bss_type():
    return iv("ps_globals.http_session_vars.u1.type_info") & 0xffffffff


def ref_info(r):
    if not r:
        return "0"
    rc = iv(f"*(unsigned int*)({r})")
    ti = iv(f"*(unsigned int*)({r}+4)")
    val = iv(f"*(unsigned long*)({r}+8)")
    ti2 = iv(f"*(unsigned int*)({r}+16)")
    return f"rc={rc} gcti={ti:#x} val={val:#x} valti={ti2:#x}"


print(f"ATTACH bss={bss():#x} t={bss_type():#x}", flush=True)
r = bss()
if r:
    print("  " + ref_info(r), flush=True)

ntrack = [0]
nrefd = [0]
nfree_hit = [0]


class Track(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_session_track_init", internal=True)

    def stop(self):
        ntrack[0] += 1
        r = bss()
        if ntrack[0] <= 6 or ntrack[0] % 200 == 0:
            print(f"TRACK#{ntrack[0]} bss={r:#x} t={bss_type():#x} "
                  f"{ref_info(r) if r else ''}", flush=True)
        return False


class RefD(gdb.Breakpoint):
    def __init__(self):
        super().__init__("zend_reference_destroy", internal=True)

    def stop(self):
        nrefd[0] += 1
        r = iv("$rdi")
        br = bss()
        print(f"REFD#{nrefd[0]} ref={r:#x} {ref_info(r)} bss={br:#x}"
              f"{' <== BSS' if r == br else ''}", flush=True)
        return False


class HashD(gdb.Breakpoint):
    def __init__(self):
        super().__init__("zend_hash_destroy", internal=True)

    def stop(self):
        ht = iv("$rdi")
        des = iv(f"*(unsigned long*)({ht}+0x30)")
        ne = iv(f"*(unsigned int*)({ht}+0x1c)")
        if des:
            print(f"HASHD ht={ht:#x} n={ne} dtor={des:#x}", flush=True)
        return False


class Init(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_session_initialize", internal=True)

    def stop(self):
        md = iv("ps_globals.mod_data")
        sid = iv("ps_globals.id")
        ln = iv(f"*(unsigned long*)({sid}+0x10)") if sid else -1
        s = ""
        try:
            s = gdb.parse_and_eval(f"(char*)({sid}+0x18)").string()
        except Exception:
            pass
        print(f"INIT mod_data={md:#x} id={sid:#x} len={ln} idstr={s!r}",
              flush=True)
        return False


class CloseF(gdb.Breakpoint):
    def __init__(self):
        super().__init__("ps_close_files", internal=True)

    def stop(self):
        ap = iv("$rdi")
        d = iv(f"*(unsigned long*){ap}") if ap else 0
        if d:
            last = iv(f"*(unsigned long*)({d})")
            base = iv(f"*(unsigned long*)({d}+8)")
            fd = iv(f"*(int*)({d}+0x24)")
            print(f"CLOSEF data={d:#x} last_key={last:#x} basedir={base:#x} "
                  f"fd={fd}", flush=True)
        return False


class Zif(gdb.Breakpoint):
    def __init__(self):
        super().__init__("zif_system", internal=True)

    def stop(self):
        print(f"ZIF cmd={iv('$rdi'):#x}", flush=True)
        try:
            print("  cmdstr=" + gdb.parse_and_eval("(char*)$rdi").string(),
                  flush=True)
        except Exception:
            pass
        return False


class Bail(gdb.Breakpoint):
    def __init__(self):
        super().__init__("zend_bailout", internal=True)

    def stop(self):
        r = bss()
        caller = iv("*(unsigned long*)$rsp")
        print(f"BAILOUT bss={r:#x} t={bss_type():#x} caller={caller:#x} "
              f"{ref_info(r) if r else ''}", flush=True)
        return False


Track()
RefD()
HashD()
Init()
CloseF()
Zif()
Bail()
gdb.execute("continue")
print(f"STOPPED tracks={ntrack[0]} refd={nrefd[0]}", flush=True)
print(f"RIP {iv('$rip'):#x} bss={bss():#x}", flush=True)
gdb.execute("bt 12")
