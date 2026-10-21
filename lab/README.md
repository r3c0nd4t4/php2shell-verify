# Lab

Vulnerable **PHP 8.4.24 + Apache mod_php**, one worker, `memory_limit=16M`,
`post_max_size=0`, `session.use_strict_mode=1` — the configuration used for all
measurements in `analysis/`.

```bash
sudo ./setup_modphp.sh start 18090 16M     # root only needed to bind <1024 / drop to www-data
python3 ../poc/php2shell_probe.py --target http://127.0.0.1:18090 --mode oom
sudo ./setup_modphp.sh stop
```

Single worker matters: `MaxRequestWorkers 1` keeps request A and request B on the
same process, which is the only way a stale pointer is observable.

For a patched control, point the same probe at a host running PHP 8.4.27+
(mod_php or FPM). `upload_progress.cleanup` does not matter for `--mode oom`;
it only affects whether the progress record survives the upload.

Requires Debian/Kali Apache module paths (`/usr/lib/apache2/modules/`). On other
distributions adjust the `LoadModule` lines and the PHP module path.
