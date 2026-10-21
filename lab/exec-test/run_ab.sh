#!/usr/bin/env bash
# A/B: does `id` execute through (A) the CVE surface, or (B) a misconfiguration?
#
#   A = upload_progress only, one session handler, no gadget, no LFI   -> expect NO execution
#   B = php_serialize writer + php reader + app-defined gadget        -> expect `id` to run
#
# B is a configuration bug known long before CVE-2026-109618 and is included
# only as a positive control: it proves the harness can detect execution.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
A_DIR=/tmp/php2shell-lab
B_DIR=/tmp/exec-lab
A_PORT=18090
B_PORT=18091

stop_b() { [ -f "$B_DIR/httpd.conf" ] && apache2 -f "$B_DIR/httpd.conf" -k stop >/dev/null 2>&1; }
trap 'stop_b; "$HERE/../setup_modphp.sh" stop '"$A_PORT"' >/dev/null 2>&1' EXIT

echo "=== A: CVE surface (upload_progress, one handler, no gadget) ==="
"$HERE/../setup_modphp.sh" start "$A_PORT" 16M >/dev/null
rm -f "$A_DIR/id.txt"
python3 "$REPO/poc/php2shell_probe.py" --target "http://127.0.0.1:$A_PORT" --mode oom | tail -3
python3 "$REPO/poc/php2shell_probe.py" --target "http://127.0.0.1:$A_PORT" --mode stale-sid | tail -3
if [ -e "$A_DIR/id.txt" ] || grep -rq 'uid=' "$A_DIR" 2>/dev/null; then
  echo "A: EXECUTION OBSERVED (unexpected)"
else
  echo "A: no execution, no artifact  <- expected for the CVE surface"
fi

echo
echo "=== B: control, handler mismatch (NOT the CVE) ==="
mkdir -p "$B_DIR"/{app,api,sess}; chmod -R 777 "$B_DIR"
cat > "$B_DIR/app/index.php" <<'PHP'
<?php
session_start();
$_SESSION['note'] = $_POST['note'] ?? '';
echo "app ok\n";
PHP
cat > "$B_DIR/api/index.php" <<'PHP'
<?php
class Marker {
    public function __destruct() {
        file_put_contents('/tmp/exec-lab/id.txt', shell_exec('id') . "\n", FILE_APPEND);
    }
}
session_start();
echo "api ok\n";
PHP
cat > "$B_DIR/httpd.conf" <<EOF
ServerRoot $B_DIR
Listen 127.0.0.1:$B_PORT
PidFile $B_DIR/apache.pid
ErrorLog $B_DIR/error.log
LogLevel warn
User www-data
Group www-data
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule php_module /usr/lib/apache2/modules/libphp8.4.so
TypesConfig /etc/mime.types
DocumentRoot $B_DIR
<Directory $B_DIR>
    Require all granted
</Directory>
<FilesMatch "\.php$">
    SetHandler application/x-httpd-php
</FilesMatch>
<Directory $B_DIR/app>
    php_admin_value session.serialize_handler php_serialize
    php_admin_value session.save_path $B_DIR/sess
    php_admin_value display_errors 1
</Directory>
<Directory $B_DIR/api>
    php_admin_value session.serialize_handler php
    php_admin_value session.save_path $B_DIR/sess
    php_admin_value display_errors 1
</Directory>
EOF
chmod 777 "$B_DIR"
stop_b
apache2 -f "$B_DIR/httpd.conf" -k start 2>/dev/null; sleep 1
rm -f "$B_DIR/id.txt"
python3 "$REPO/related/handler-mismatch/verify_handler_mismatch.py" \
    --target "http://127.0.0.1:$B_PORT" --write-path /app/index.php \
    --read-path /api/index.php --marker-url /id.txt | tail -2
if [ -s "$B_DIR/id.txt" ]; then
  echo "B: execution observed; id said: $(cat "$B_DIR/id.txt")"
else
  echo "B: no execution (harness problem)"
fi
