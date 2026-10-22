import gdb


def iv(expr):
    try:
        return int(gdb.parse_and_eval(expr))
    except Exception:
        return -1


def hv(expr):
    try:
        return gdb.parse_and_eval(expr).string()
    except Exception:
        return ""


main = iv("alloc_globals.mm_heap->main_chunk")
sid = iv("ps_globals.id")
sp = iv("ps_globals.save_path")
print("PSDUMP main=%#x id=%#x off=%#x send=%d status=%d mod_data=%#x "
      "hsv_t=%#x hsv_p=%#x real=%d limit=%d fp=%d chunks=%d cached=%d" % (
          main, sid, (sid - main) if sid else 0,
          iv("ps_globals.send_cookie"), iv("ps_globals.session_status"),
          iv("ps_globals.mod_data"),
          iv("ps_globals.http_session_vars.u1.type_info") & 0xffffffff,
          iv("ps_globals.http_session_vars.value.ptr"),
          iv("alloc_globals.mm_heap->real_size"),
          iv("alloc_globals.mm_heap->limit"),
          iv(f"((zend_mm_chunk*){main:#x})->free_pages"),
          iv("alloc_globals.mm_heap->chunks_count"),
          iv("alloc_globals.mm_heap->cached_chunks_count")), flush=True)
print("SAVE_PATH=%r SESSION_NAME=%r" % (hv("ps_globals.save_path"),
                                        hv("ps_globals.session_name")),
      flush=True)
if sid:
    rc = iv(f"*(unsigned int*)({sid:#x})")
    ti = iv(f"*(unsigned int*)({sid:#x}+4)")
    ln = iv(f"*(unsigned long*)({sid:#x}+0x10)")
    val = iv(f"*(unsigned long*)({sid:#x}+0x18)")
    print("  IDSTR rc=%#x ti=%#x len=%#x val=%#x %r" % (
        rc, ti, ln, val, hv(f"(char*)({sid:#x}+0x18)")[:64]), flush=True)
hsv = iv("ps_globals.http_session_vars.value.ptr")
if hsv:
    print("  HSV rc=%#x ti=%#x val=%#x valti=%#x" % (
        iv(f"*(unsigned int*)({hsv:#x})"),
        iv(f"*(unsigned int*)({hsv:#x}+4)"),
        iv(f"*(unsigned long*)({hsv:#x}+8)"),
        iv(f"*(unsigned int*)({hsv:#x}+16)")), flush=True)
gdb.execute("detach")
gdb.execute("quit")
