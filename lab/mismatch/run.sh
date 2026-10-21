#!/usr/bin/env bash
# Lab B - session handler MISMATCH (not CVE-2026-109618).
#   * /app writes with php_serialize, /api reads with php, both share save_path
#   * /api defines a Runner class whose __destruct executes a command
# Demonstrates: object injection through the "|" delimiter, then command execution.
# Requires an application that already has this misconfiguration + gadget.
set -uo pipefail
DIR=${DIR:-/tmp/php2shell-verify-labs/mismatch}
PORT=${PORT:-18092}

case "${1:-start}" in
  start)
    mkdir -p "$DIR"/{app,api,sess}; chmod -R 777 "$DIR"
    cat > "$DIR/app/index.php" <<'PHP'
<?php
session_start();
$_SESSION['note'] = $_POST['note'] ?? '';
header('Content-Type: text/plain');
echo "writer ok\n";
PHP
    cat > "$DIR/api/index.php" <<'PHP'
<?php
class Runner {
    public $cmd = 'id';
    public function __destruct() {
        file_put_contents(__DIR__ . '/out.txt', (string) shell_exec($this->cmd . ' 2>&1'));
    }
}
session_start();
header('Content-Type: text/plain');
echo "reader ok\n";
PHP
    cat > "$DIR/httpd.conf" <<EOF
ServerRoot $DIR
Listen 127.0.0.1:$PORT
PidFile $DIR/apache.pid
ErrorLog $DIR/error.log
LogLevel warn
User www-data
Group www-data
ServerName mismatch.local
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule php_module /usr/lib/apache2/modules/libphp8.4.so
TypesConfig /etc/mime.types
DocumentRoot $DIR
<Directory $DIR>
    Require all granted
    AllowOverride None
</Directory>
<FilesMatch "\.php$">
    SetHandler application/x-httpd-php
</FilesMatch>
<Directory $DIR/app>
    php_admin_value session.serialize_handler php_serialize
    php_admin_value session.save_path $DIR/sess
    php_admin_value display_errors 1
</Directory>
<Directory $DIR/api>
    php_admin_value session.serialize_handler php
    php_admin_value session.save_path $DIR/sess
    php_admin_value display_errors 1
</Directory>
EOF
    chmod 777 "$DIR"
    apache2 -f "$DIR/httpd.conf" -k stop >/dev/null 2>&1
    apache2 -f "$DIR/httpd.conf" -t >/dev/null
    apache2 -f "$DIR/httpd.conf" -k start >/dev/null 2>&1
    rc=$?
    if [ $rc -ne 0 ] || [ ! -s "$DIR/apache.pid" ]; then
        echo "[-] failed to start on 127.0.0.1:$PORT (port already in use?)" >&2
        exit 1
    fi
    sleep 1
    echo "[+] target  http://127.0.0.1:$PORT"
    echo "[+] shell   python3 poc/mismatch.py --target http://127.0.0.1:$PORT -c id"
    ;;
  stop)
    [ -f "$DIR/httpd.conf" ] && apache2 -f "$DIR/httpd.conf" -k stop >/dev/null 2>&1
    ;;
  logs)  tail -n "${2:-20}" "$DIR/error.log" ;;
  *) echo "usage: $0 start|stop|logs [n]" >&2; exit 2 ;;
esac
