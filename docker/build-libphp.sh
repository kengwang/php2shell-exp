#!/bin/sh
# Compile the lab's mod_php from a php-src 8.4.4 git archive.
#
#   docker run -d --name p2s-srcbuild -v /path/php-src-844.tar:/src.tar:ro \
#          p2s-builder            # then:  docker cp p2s-srcbuild:/out/libphp.so ...
#
# The configure command below is the one the calibrated binary was built with
# (recoverable with `strings docker/bin/libphp.so | grep './configure'`); the
# heap offsets only stay valid while it does not change.
set -eu

SRC=${SRC:-/src.tar}
JOBS=${JOBS:-2}
OUT=${OUT:-/out}
BUILD=${BUILD:-/tmp/php}

CONFIGURE_ARGS="--with-apxs2=/usr/bin/apxs2 \
--with-config-file-path=/usr/local/etc/php \
--with-mhash --enable-mbstring --enable-mysqlnd --with-password-argon2 \
--with-sodium --with-pdo-sqlite=/usr --with-sqlite3=/usr --with-curl \
--with-iconv --with-openssl --with-readline --with-zlib --enable-opcache \
--disable-cgi --disable-phpdbg --with-pic"

rm -rf "$BUILD" "$OUT"
mkdir -p "$BUILD" "$OUT"
echo "== source $SRC ($(sha256sum "$SRC" | cut -c1-12))"
tar -xf "$SRC" -C "$BUILD"
cd "$BUILD"

# the archive is a git checkout: no configure script yet
./buildconf --force

echo "== configure $CONFIGURE_ARGS"
# shellcheck disable=SC2086
./configure $CONFIGURE_ARGS || { tail -40 config.log; exit 1; }

echo "== make -j$JOBS"
make -j"$JOBS"

test -f libs/libphp.so || { echo "libs/libphp.so missing"; exit 1; }
cp libs/libphp.so "$OUT/libphp.so"
if [ -f modules/opcache.so ]; then
    cp modules/opcache.so "$OUT/opcache.so"
fi
nm -C libs/libphp.so | grep -E ' (T|t) (zif_system|zval_ptr_dtor)$' \
    > "$OUT/symbols.txt" || echo "zif_system/zval_ptr_dtor not found"
cat "$OUT/symbols.txt"
md5sum "$OUT"/*.so
echo "== built; copy out with: docker cp <name>:/out/libphp.so ..."
