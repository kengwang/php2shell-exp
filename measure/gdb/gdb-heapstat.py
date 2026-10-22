import gdb


def iv(expr):
    try:
        return int(gdb.parse_and_eval(expr))
    except Exception:
        return -1


def fv(expr):
    try:
        return float(gdb.parse_and_eval(expr))
    except Exception:
        return -1.0


h = "alloc_globals.mm_heap"
print("HEAP cached=%d avg=%.3f peak=%d chunks=%d real=%d limit=%d pid=%d" % (
    iv(f"(unsigned) {h}->cached_chunks_count"),
    fv(f"(double) {h}->avg_chunks_count"),
    iv(f"(unsigned) {h}->peak_chunks_count"),
    iv(f"(unsigned) {h}->chunks_count"),
    iv(f"(unsigned long) {h}->real_size"),
    iv(f"(unsigned long) {h}->limit"),
    iv("(int) getpid()")), flush=True)
gdb.execute("detach")
gdb.execute("quit")
