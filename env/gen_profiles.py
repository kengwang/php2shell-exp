#!/usr/bin/env python3
"""Generate php.ini + apache2.conf for every lab profile (single source of truth)."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "generated")

PHP_INI = """memory_limit = {mem}
post_max_size = 8M
upload_max_filesize = 2M
max_file_uploads = 20
max_multipart_body_parts = -1
max_input_vars = 1000
max_input_time = 300

display_errors = {disp}
display_startup_errors = {disp}
error_reporting = E_ALL
log_errors = On
error_log = /proc/self/fd/2
output_buffering = 0
implicit_flush = 1

session.save_path = {save}
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
session.use_cookies = On
session.use_strict_mode = Off

expose_php = {expo}
{opcache}"""

OPCACHE = """
zend_extension=/usr/local/etc/php/opcache.so
opcache.enable=1
opcache.enable_cli=0
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.validate_timestamps=0
"""

APACHE = """ServerRoot "/etc/apache2"
ServerName localhost
Listen 80
PidFile /tmp/apache.pid

LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule php_module /usr/local/lib/apache2/libphp.so

User www-data
Group www-data

DocumentRoot "/srv/www"
<Directory "/srv/www">
    Require all granted
</Directory>
DirectoryIndex index.php
<FilesMatch "\\.php$">
    SetHandler application/x-httpd-php
</FilesMatch>

ErrorLog /proc/self/fd/2
LogLevel warn

KeepAlive {keepalive}

<IfModule mpm_prefork_module>
    StartServers           {workers}
    MinSpareServers        {workers}
    MaxSpareServers        {maxspare}
    MaxRequestWorkers      {workers}
    ServerLimit            {workers}
    MaxConnectionsPerChild 0
</IfModule>

# The mounted ini lives at libphp's compiled-in path: PHP reads
# /usr/local/etc/php/php.ini at module init (PHPIniDir in a -f config is not
# honoured by this build; the line below is kept only as documentation).
PHPIniDir /usr/local/etc/php
"""

# name: (memory_limit, display_errors, expose_php, save_path, opcache, workers, keepalive, port)
PROFILES = {
    "def":    ("128M", "Off", "Off", '"/tmp"',                      False, 1, "Off", 8098),
    "on":     ("128M", "Off", "On",  '"/tmp"',                      False, 1, "Off", 8099),
    "default":("128M", "On",  "Off", '"/tmp"',                      False, 1, "Off", 8096),
    "dev":    ("128M", "On",  "On",  '"/tmp"',                      False, 1, "Off", 8102),
    "ub":     ("128M", "Off", "Off", "/var/lib/php/sessions",       False, 1, "Off", 8103),
    "ub-on":  ("128M", "Off", "On",  "/var/lib/php/sessions",       False, 1, "Off", 8104),
    "256":    ("256M", "Off", "Off", '"/tmp"',                      False, 1, "Off", 8105),
    "512":    ("512M", "Off", "Off", '"/tmp"',                      False, 1, "Off", 8106),
    "1g":     ("1024M", "Off", "Off", '"/tmp"',                     False, 1, "Off", 8107),
    "dd256":  ("256M", "On",  "Off", '"/tmp"',                      False, 1, "Off", 8108),
    "dd512":  ("512M", "On",  "Off", '"/tmp"',                      False, 1, "Off", 8109),
    "dd1g":   ("1024M", "On", "Off", '"/tmp"',                      False, 1, "Off", 8110),
    "mw":     ("128M", "Off", "Off", '"/tmp"',                      False, 8, "On",  8100),
    "opc":    ("128M", "On",  "Off", '"/tmp"',                      True,  1, "Off", 8111),
}

os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "profiles.json"), "w", newline="\n") as f:
    import json
    json.dump(PROFILES, f, indent=2)

for name, (mem, disp, expo, save, opc, workers, ka, port) in PROFILES.items():
    d = os.path.join(OUT, name)
    os.makedirs(d, exist_ok=True)
    ini = PHP_INI.format(mem=mem, disp=disp, expo=expo, save=save,
                         opcache=OPCACHE if opc else "")
    with open(os.path.join(d, "php.ini"), "w", newline="\n") as f:
        f.write(ini)
    conf = APACHE.format(workers=workers, maxspare=workers, keepalive=ka)
    with open(os.path.join(d, "apache.conf"), "w", newline="\n") as f:
        f.write(conf)
    with open(os.path.join(d, "port"), "w", newline="\n") as f:
        f.write(str(port))

print(f"wrote {len(PROFILES)} profiles to {OUT}")
