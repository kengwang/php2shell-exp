#!/bin/sh
# /srv/profile/apache.conf  - per-profile Apache config (bind-mounted, ro)
# /usr/local/etc/php/php.ini - the ini PHP actually loads (compiled-in path)
# /srv/www is the bare target page, /srv/out is where PoC commands write proofs.
set -e
mkdir -p /srv/out
chmod 777 /srv/out /tmp
rm -f /tmp/sess_*
exec apache2 -f /srv/profile/apache.conf -DFOREGROUND
