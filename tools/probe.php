<?php
/* Mounted temporarily at /srv/www/probe.php to show which ini the worker loaded.
   index.php (the exploit target page) is unaffected. */
header("Content-Type: text/plain");
echo "loaded=", var_export(php_ini_loaded_file(), true), "\n";
echo "scanned=", var_export(php_ini_scanned_files(), true), "\n";
echo "expose_php=", var_export(ini_get("expose_php"), true), "\n";
echo "memory_limit=", var_export(ini_get("memory_limit"), true), "\n";
echo "save_path=", var_export(ini_get("session.save_path"), true), "\n";
