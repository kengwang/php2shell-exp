#!/bin/sh
# Compile the nginx + PHP-FPM victim (sapi/fpm) from the same php-src 8.4.4
# archive that docker/build-libphp.sh uses for mod_php.
#
#   docker run -d --name p2s-fpmbuild -v $PWD/docker/src/php-src-844.tar:/src.tar:ro p2s-builder /build-phpfpm.sh
#   docker cp p2s-fpmbuild:/out/phpfpm.tar docker/staged/phpfpm.tar
#
# The flags are part of the calibration: -O0 (not -O2) and --disable-all define
# the request-start allocation sequence that the heap offsets were measured on.
set -eux

SRC=${SRC:-/src.tar}
OUT=${OUT:-/out}
JOBS=${JOBS:-2}
PREFIX=${PREFIX:-/opt/phpfpm}

rm -rf /src
mkdir -p /src "$OUT"
tar -xf "$SRC" -C /src
cd /src

./buildconf --force
./configure --disable-all --enable-fpm --enable-session \
    --disable-cgi --disable-cli --disable-phpdbg --prefix="$PREFIX" \
    CFLAGS='-g -O0 -fPIC'
make -j"$JOBS"
make install

"$PREFIX"/sbin/php-fpm -v
# archive from the prefix's parent so extracting it yields ./phpfpm/...
tar -C "$(dirname "$PREFIX")" -cf "$OUT/phpfpm.tar" "$(basename "$PREFIX")"
md5sum "$PREFIX"/sbin/php-fpm "$OUT/phpfpm.tar"
ls -l "$OUT"
