# exec-test — does `id` run through these CVEs?

Direct answer, tested: **no.** This directory contains the A/B that shows why, and
the positive control that proves the harness can detect execution.

```bash
./run_ab.sh          # starts both labs, runs both tests, stops them
```

## Result

| Lab | Configuration | `id` executed? |
|---|---|---|
| **A** | `session.upload_progress` on, **one** session handler, no gadget class, no LFI | **no** — only the pre-RINIT abort |
| **B** | `php_serialize` writer + `php` reader, app-defined `__destruct` gadget | **yes** — `uid=...` captured |

A: request aborts with `Allowed memory size ... exhausted ... in Unknown on line 0`
(no script frame), empty body, no `Set-Cookie`, worker survives. No execution
artifact is produced because nothing in the request path can run a command.

B: the classic handler mismatch — the session file written by the `php_serialize`
endpoint contains a `|` inside a value; the `php` endpoint splits there and
unserializes the remainder, and the gadget's `__destruct` runs `id`.

## Reading the result

Lab B is **not** CVE-2026-109618/109619. It is a configuration bug: two
applications with different `session.serialize_handler` values sharing one
`session.save_path`, plus an application class with a dangerous destructor. It
works on any PHP version, patched or not.

That is why every public "php2shell → `id`" demo is one of:

1. this handler mismatch (its "Chain 2"), or
2. session-file poisoning followed by an **LFI** the target already has (Chain 1,
   and the log-poisoning / `/proc/self/fd` / `phpinfo()` / PEARCMD variants), or
3. a framework gadget chain reached through either of the above.

None of them exercises the OOM state corruption the CVEs describe. If you want to
demonstrate *this* CVE, the observable is the abort in Lab A and — if you can
solve the heap grooming — a malformed `Set-Cookie`; not a shell.

## Requirements

Debian/Kali Apache module paths, PHP 8.4.24 (`libapache2-mod-php8.4`). Lab B needs
`shell_exec` enabled and a writable `/tmp/exec-lab`. Both labs are local-only and
bind to 127.0.0.1.
