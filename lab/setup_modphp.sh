#!/usr/bin/env bash
# Single-worker Apache + mod_php lab for php2shell verification (Debian/Kali).
# usage: ./setup_modphp.sh start|stop [port] [memory_limit]
set -euo pipefail

ACTION="${1:-start}"
PORT="${2:-18090}"
MEM="${3:-16M}"
DIR="${DIR:-/tmp/php2shell-lab}"
CONF="$DIR/httpd.conf"

case "$ACTION" in
  start)
    mkdir -p "$DIR/www" "$DIR/sess"
    chmod 777 "$DIR" "$DIR/sess"
    cat > "$DIR/www/index.php" <<'PHP'
<?php
$n = count($_POST) + count($_FILES);
echo "limit=", ini_get('memory_limit'), " post_max=", ini_get('post_max_size'),
     " fields=", $n, " peak=", memory_get_peak_usage(true), "\n";
PHP
    cat > "$CONF" <<EOF
ServerRoot $DIR
Listen 127.0.0.1:$PORT
PidFile $DIR/apache.pid
ErrorLog $DIR/error.log
LogLevel warn
User www-data
Group www-data
ServerName php2shell.local
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module   /usr/lib/apache2/modules/mod_authz_core.so
LoadModule mime_module         /usr/lib/apache2/modules/mod_mime.so
LoadModule php_module          /usr/lib/apache2/modules/libphp8.4.so
TypesConfig /etc/mime.types
StartServers 1
MinSpareServers 1
MaxSpareServers 1
MaxRequestWorkers 1
ServerLimit 1
DocumentRoot $DIR/www
<Directory $DIR/www>
    Require all granted
    AllowOverride None
    php_admin_value memory_limit $MEM
    php_admin_value post_max_size 0
    php_admin_value upload_max_filesize 64M
    php_admin_value session.save_path $DIR/sess
    php_admin_value session.use_strict_mode 1
    php_admin_value session.use_only_cookies 1
    php_admin_value session.upload_progress.enabled 1
    php_admin_value display_errors 1
</Directory>
<FilesMatch "\.php$">
    SetHandler application/x-httpd-php
</FilesMatch>
EOF
    apache2 -f "$CONF" -t >/dev/null
    apache2 -f "$CONF" -k start
    sleep 1
    echo "[+] target http://127.0.0.1:$PORT  (memory_limit=$MEM, 1 worker)"
    echo "[+] logs: $DIR/error.log"
    ;;
  stop)
    [ -f "$CONF" ] && apache2 -f "$CONF" -k stop 2>/dev/null || true
    echo "[+] stopped"
    ;;
  *)
    echo "usage: $0 start|stop [port] [memory_limit]" >&2; exit 2 ;;
esac
