#!/usr/bin/env bash
# Lab A - the CVE surface only.
#   * one session handler (default "php"), no gadget class, no LFI
#   * session.upload_progress enabled (PHP default)
#   * one Apache worker, so request N+1 lands on the process request N left behind
# Demonstrates: the pre-RINIT abort, and the (unreached) stale-session window.
# Does NOT demonstrate code execution. See ../../docs/MECHANISM.md.
set -uo pipefail
DIR=${DIR:-/tmp/php2shell-verify-labs/verify}
PORT=${PORT:-18090}
MEM=${MEM:-16M}

case "${1:-start}" in
  start)
    mkdir -p "$DIR/www" "$DIR/sess"; chmod -R 777 "$DIR"
    cat > "$DIR/www/index.php" <<'PHP'
<?php
$n = count($_POST) + count($_FILES);
echo "limit=", ini_get('memory_limit'),
     " fields=", $n,
     " peak=", memory_get_peak_usage(true), "\n";
PHP
    cat > "$DIR/httpd.conf" <<EOF
ServerRoot $DIR
Listen 127.0.0.1:$PORT
PidFile $DIR/apache.pid
ErrorLog $DIR/error.log
LogLevel warn
User www-data
Group www-data
ServerName verify.local
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule php_module /usr/lib/apache2/modules/libphp8.4.so
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
    php_admin_value session.save_path $DIR/sess
    php_admin_value session.use_strict_mode 1
    php_admin_value session.use_only_cookies 1
    php_admin_value session.upload_progress.enabled 1
    php_admin_value display_errors 0
</Directory>
<FilesMatch "\.php$">
    SetHandler application/x-httpd-php
</FilesMatch>
EOF
    chmod 777 "$DIR"
    apache2 -f "$DIR/httpd.conf" -k stop >/dev/null 2>&1
    apache2 -f "$DIR/httpd.conf" -t >/dev/null
    rm -f "$DIR/apache.pid"
    for _ in 1 2 3 4 5; do
        apache2 -f "$DIR/httpd.conf" -k start >/dev/null 2>&1
        [ -s "$DIR/apache.pid" ] && break
        sleep 0.4
    done
    if [ ! -s "$DIR/apache.pid" ]; then
        echo "[-] failed to start on 127.0.0.1:$PORT (port already in use?)" >&2
        exit 1
    fi
    sleep 1
    echo "[+] target  http://127.0.0.1:$PORT  (memory_limit=$MEM, 1 worker)"
    echo "[+] logs    $DIR/error.log"
    echo "[+] probe   python3 poc/verify.py --target http://127.0.0.1:$PORT --mode oom"
    ;;
  stop)
    [ -f "$DIR/httpd.conf" ] && apache2 -f "$DIR/httpd.conf" -k stop >/dev/null 2>&1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null || break
        sleep 0.3
    done
    ;;
  logs)  tail -n "${2:-20}" "$DIR/error.log" ;;
  *) echo "usage: $0 start|stop|logs [n]" >&2; exit 2 ;;
esac
