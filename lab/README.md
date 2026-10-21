# Labs

| Lab | Port | Proves | Runs on |
|---|---|---|---|
| `lab/verify/` | 18090 | the CVE surface: pre-RINIT abort, stale-session window | any PHP 8.4 + Apache mod_php |
| `lab/mismatch/` | 18092 | command execution via a **different** bug (handler mismatch) | same |

```bash
./lab/verify/run.sh start        # then: python3 poc/verify.py --mode oom
./lab/mismatch/run.sh start      # then: python3 poc/mismatch.py -c id
./lab/verify/run.sh stop
```

Both are local-only, single-worker, and use Debian/Kali Apache module paths. The
differing session handlers and `memory_limit` are set with `php_admin_value`
because `.user.ini` is ignored by mod_php and by `php -S`.

`lab/docker/` holds the reference configuration used by the public amd64 chains;
it is not executed here (see `docs/REPRODUCTIONS.md`).
