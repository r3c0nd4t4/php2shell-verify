#!/usr/bin/env bash
# Deliberately vulnerable lab for the session handler MISMATCH.
# NOT CVE-2026-109618 / CVE-2026-109619. See README.md.
set -uo pipefail
DIR=${DIR:-/tmp/exec-lab}
PORT=${PORT:-18092}

case "${1:-start}" in
  start)
    mkdir -p "$DIR"/{app,api,sess}; chmod -R 777 "$DIR"
    cat > "$DIR/app/index.php" <<'PHP'
<?php
// writer: php_serialize
session_start();
$_SESSION['note'] = $_POST['note'] ?? '';
header('Content-Type: text/plain');
echo "writer ok\n";
PHP
    cat > "$DIR/api/index.php" <<'PHP'
<?php
// reader: php handler + application gadget
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
ServerName exec-lab.local
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
    php_admin_value session.use_strict_mode 0
    php_admin_value display_errors 1
</Directory>
<Directory $DIR/api>
    php_admin_value session.serialize_handler php
    php_admin_value session.save_path $DIR/sess
    php_admin_value session.use_strict_mode 0
    php_admin_value display_errors 1
</Directory>
EOF
    chmod 777 "$DIR"
    apache2 -f "$DIR/httpd.conf" -k stop >/dev/null 2>&1
    apache2 -f "$DIR/httpd.conf" -k start
    sleep 1
    echo "[+] http://127.0.0.1:$PORT  (writer /app/index.php, reader /api/index.php)"
    ;;
  stop)
    [ -f "$DIR/httpd.conf" ] && apache2 -f "$DIR/httpd.conf" -k stop
    ;;
  *) echo "usage: $0 start|stop"; exit 2 ;;
esac
