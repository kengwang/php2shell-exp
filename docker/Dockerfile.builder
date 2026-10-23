# Builder stage for the php2shell lab: compiles mod_php from a php-src 8.4.4
# git archive instead of shipping a 53 MB prebuilt libphp.so.
#
#   python p2s.py build --from-source            # does all of this
#
#   docker build -t p2s-builder -f docker/Dockerfile.builder docker
#   docker run -d --name p2s-srcbuild -v $PWD/docker/src/php-src-844.tar:/src.tar:ro p2s-builder
#   docker wait p2s-srcbuild && docker cp p2s-srcbuild:/out/libphp.so docker/bin/libphp.so
#   docker rm -f p2s-srcbuild
#
# The source tar is bind-mounted, never COPYed: docker/.dockerignore keeps it out
# of build contexts (it is 136 MB), and it is regenerable with
#   git -C <php-src checkout> archive --format=tar -o docker/src/php-src-844.tar HEAD
# from branch PHP-8.4.4.
#
# -dev packages are pinned to what the calibrated binary actually links (see
# `objdump -p docker/bin/libphp.so | grep NEEDED`): readline, not libedit; no
# libzip, no libicu.  Adding a -dev package silently enables an extension and
# moves the heap layout the PoCs are calibrated for.
ARG BASE=ubuntu:24.04
ARG APT=cn
ARG APT_MIRROR=mirrors.ustc.edu.cn
FROM ${BASE}

ARG APT
ARG APT_MIRROR

RUN set -eux; \
    if [ "$APT" = "cn" ]; then \
        codename=$(. /etc/os-release; echo "$VERSION_CODENAME"); \
        printf 'Types: deb\nURIs: http://%s/ubuntu/\nSuites: %s %s-updates %s-backports\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\nTypes: deb\nURIs: http://%s/ubuntu/\nSuites: %s-security\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n' \
            "$APT_MIRROR" "$codename" "$codename" "$codename" \
            "$APT_MIRROR" "$codename" > /etc/apt/sources.list.d/ubuntu.sources; \
        rm -f /etc/apt/sources.list; \
    fi; \
    apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool m4 pkg-config bison re2c \
        apache2 apache2-bin apache2-dev \
        libxml2-dev libssl-dev libsqlite3-dev zlib1g-dev \
        libcurl4-openssl-dev libonig-dev libsodium-dev libargon2-dev \
        libreadline-dev gdb binutils \
    && rm -rf /var/lib/apt/lists/*

COPY build-libphp.sh /build-libphp.sh
COPY build-phpfpm.sh /build-phpfpm.sh
RUN chmod +x /build-libphp.sh /build-phpfpm.sh
CMD ["/build-libphp.sh"]
