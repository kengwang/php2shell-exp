#!/bin/sh
# nginx front-end + PHP-FPM in one container.
#   /srv/fpm/{nginx.conf,php-fpm.conf,php.ini}  read-only mount of the profile
#              directory (docker/fpm or docker/fpm128), which shadows the copy
#              baked into the image
#   /srv/www   the two victim pages (bind-mounted, writable: the chain writes
#              its shell here, so the artifact is visible on the host)
#   /srv/out   proof files from the mod_php PoCs (unused by this target)
set -e
mkdir -p /srv/out /tmp/ngx-body /tmp/ngx-fcgi /tmp/ngx-proxy
chmod 777 /srv/out /tmp /var/lib/php/sessions
rm -f /var/lib/php/sessions/sess_* /tmp/fpm-error.log /tmp/nginx-error.log
/opt/phpfpm/sbin/php-fpm -y /srv/fpm/php-fpm.conf -c /srv/fpm/php.ini &
exec nginx -g 'daemon off;' -c /srv/fpm/nginx.conf
