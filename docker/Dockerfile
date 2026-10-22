# php2shell lab target image.
#
#   docker build -t p2s-php844:latest .                       # ubuntu:24.04 + USTC apt mirror
#   docker build -t p2s-php844:latest --build-arg APT_MIRROR=mirrors.ustc.edu.cn .
#   docker build -t p2s-php844:latest \
#          --build-arg BASE=php844apache-full:latest \
#          --build-arg APT=skip .                             # offline: reuse the lab base image
#
# The exploit chains are calibrated against bin/libphp.so byte-for-byte
# (zif_system = 0x457fe0, zval_ptr_dtor = 0x64b890), so the PHP binary is
# shipped prebuilt instead of being recompiled; recompiling shifts offsets.
# bin/libphp.so was extracted from the lab build (php-src 8.4.4,
# src/php-src-844.tar) with:
#   docker cp php844full_def:/usr/src/php/libs/libphp.so docker/bin/libphp.so

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
