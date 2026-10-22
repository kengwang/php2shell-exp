import gdb


def iv(expr):
    try:
        return int(gdb.parse_and_eval(expr))
    except Exception:
        return -1


r0 = iv("ps_globals.http_session_vars.value.ptr")
print(f"ATTACH R0={r0:#x}", flush=True)
if r0:
    for off in (0, 8, 16, 24):
        print(f"  R0+{off:#x}={iv(f'*(unsigned long*)({r0}+{off})'):#x}", flush=True)


class Track(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_session_track_init", internal=True)

    def stop(self):
        ar0 = iv("ps_globals.http_session_vars.value.ptr")
        print(f"TRACK R0={ar0:#x}", flush=True)
        for off in (0, 8, 16, 24):
            print(f"  R0+{off:#x}={iv(f'*(unsigned long*)({ar0}+{off})'):#x}", flush=True)
        return False


class RefD(gdb.Breakpoint):
    def __init__(self):
        super().__init__("zend_reference_destroy", internal=True)

    def stop(self):
        print(f"REFDESTROY ref={iv('$rdi'):#x}", flush=True)
        return False


class ArrD(gdb.Breakpoint):
    def __init__(self):
        super().__init__("zend_array_destroy", internal=True)

    def stop(self):
        print(f"ARRDESTROY ht={iv('$rdi'):#x}", flush=True)
        return False


class HashD(gdb.Breakpoint):
    def __init__(self):
        super().__init__("zend_hash_destroy", internal=True)

    def stop(self):
        print(f"HASHDESTROY ht={iv('$rdi'):#x}", flush=True)
        return False


class Zif(gdb.Breakpoint):
    def __init__(self):
        super().__init__("zif_system", internal=True)

    def stop(self):
        print(f"ZIF cmd={iv('$rdi'):#x}", flush=True)
        try:
            print("  cmdstr=" + gdb.parse_and_eval("(char*)$rdi").string(), flush=True)
        except Exception:
            pass
        return False


Track()
RefD()
ArrD()
HashD()
Zif()
gdb.execute("continue")
