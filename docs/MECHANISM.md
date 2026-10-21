# Mechanism

Two sentences: `session.upload_progress` initialises the session while the
multipart body is parsed, **before RINIT**. If an allocation fails there, PHP
aborts with `zend_bailout()`/`longjmp()` out of a half-initialised operation, and
state that a later request still uses is left pointing at freed memory.

## Where it happens

`ext/session/session.c`, PHP 8.4.24 (vulnerable), with the fix in parentheses:

```c
3187  php_session_initialize();
3188  PS(session_status) = php_session_active;   /* forced even if init FAILED (fixed) */
...
 445          zend_string_release_ex(PS(id), 0); /* freed, pointer left dangling */
 446          PS(id) = PS(mod)->s_create_sid(...);
...
3213  case MULTIPART_EVENT_START:               /* runs BEFORE RINIT (globals reset added) */
```

The callback is reached without any application code: a multipart POST carrying
`PHP_SESSION_UPLOAD_PROGRESS` plus a file part is enough. No `session_start()` is
required, so the script can literally be `<?php echo "OK\n"; ?>`.

## What the abort leaves behind

The request is torn down before the normal shutdown path clears session globals.
Depending on where the allocation failed, `PS(id)`, `PS(send_cookie)` and
`PS(http_session_vars)` can survive into the next request handled by the same
worker. Modern chains use two of them:

| Leftover | Consumed by | Result |
|---|---|---|
| `PS(id)` + `PS(send_cookie)=1` | next request's `php_session_send_cookie()` → `php_url_encode()` | out-of-bounds read → heap/chunk pointers in `Set-Cookie` |
| `PS(http_session_vars)` (a `zend_reference`) | next request's `php_session_track_init()` → `zval_ptr_dtor()` | fake reference → fake `HashTable` → `pDestructor` call |

The public chains place the OOM inside `php_session_send_cookie()` →
`php_url_encode()`'s `zend_string_safe_alloc(3, sid_length, 0, 0)` (~121 B), or in
`php_session_initialize()`, then re-enter the stale state from the next request's
pre-RINIT `rfc1867_cleanup`.

## Why it is hard to reproduce by hand

Small allocations are served from bins inside 2 MB chunks, so a bin allocation
only fails when a new chunk cannot be allocated. Reaching that point requires
heap shaping (the public chains ship per-build field parameters), and the OOM must
land at the specific allocation that leaves the useful pointer behind — not at the
multipart parser buffer, which is what naive body shaping hits.

Reachability with default limits is solved by amplification: duplicate 6-byte
multipart headers cost ~314 B of heap each, so a ~2.5 MB body can OOM a 128 MB
limit.

## The fix (8.4.27, commit `3584a98b`)

- engine-wide: OOM `longjmp` replaced by a delayed OOM (`EG(delayed_oom)`,
  UnwindExit) and a hard memory limit;
- session: `PS(id) = NULL` after every release, `php_session_initialize()` checked,
  `in_rfc1867_update` gate so no user code runs during the pre-RINIT decode, and
  `php_rinit_session_globals()` at `MULTIPART_EVENT_START`.

## What this repository demonstrates

The pre-RINIT abort, reliably, and the per-SAPI consequence (mod_php child
survives, CGI process exits). Not the disclosure, not execution — see
`REPRODUCTIONS.md`.
