# php2shell lab target image.
#
#   docker build -t p2s-php844:latest .                       # ubuntu:24.04 + USTC apt mirror
#   docker build -t p2s-php844:latest --build-arg APT_MIRROR=mirrors.ustc.edu.cn .
#   docker build -t p2s-php844:latest \
#          --build-arg BASE=<image-that-already-has-the-php-build-deps> \
#          --build-arg APT=skip .                             # offline: reuse a warm base image
#
# The exploit chains are calibrated against bin/libphp.so byte-for-byte
# (zif_system = 0x457fe0, zval_ptr_dtor = 0x64b890), so the PHP binary ships
# prebuilt; see `p2s.py build --from-source` (README) for compiling it instead —
# measured: a from-source rebuild keeps both symbol offsets and R0/CMDOFF.
# bin/libphp.so is libs/libphp.so of a php-src 8.4.4 build (src/php-src-844.tar)
# configured as documented in the README.

ARG BASE=ubuntu:24.04
ARG APT=cn
ARG APT_MIRROR=mirrors.ustc.edu.cn
FROM ${BASE}

ARG APT
ARG APT_MIRROR

RUN set -eux; \
    mkdir -p /srv/out; \
    if [ "$APT" = "cn" ]; then \
        codename=$(. /etc/os-release; echo "$VERSION_CODENAME"); \
        printf 'Types: deb\nURIs: http://%s/ubuntu/\nSuites: %s %s-updates %s-backports\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\nTypes: deb\nURIs: http://%s/ubuntu/\nSuites: %s-security\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n' \
            "$APT_MIRROR" "$codename" "$codename" "$codename" \
            "$APT_MIRROR" "$codename" > /etc/apt/sources.list.d/ubuntu.sources; \
        rm -f /etc/apt/sources.list; \
    elif [ "$APT" = "skip" ]; then \
        echo "apt=skip: relying on packages already present in ${BASE}"; \
        exit 0; \
    fi; \
    apt-get update && apt-get install -y --no-install-recommends \
        apache2 apache2-bin \
        libcurl4 libonig5 libsqlite3-0 libssl3 libsodium23 libargon2-1 \
        libzip4 zlib1g libxml2 libedit2 libncurses6 \
        iproute2 procps psmisc gdb binutils \
    && rm -rf /var/lib/apt/lists/*

COPY bin/libphp.so /usr/local/lib/apache2/libphp.so
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
