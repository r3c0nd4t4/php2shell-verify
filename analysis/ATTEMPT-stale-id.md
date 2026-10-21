# Attempt log: stale `PS(id)` → disclosure (not reproduced)

> **Correction (2026-10-21):** the public chain does not fail `s_create_sid()`.
> It OOMs inside `php_session_send_cookie()` → `php_url_encode()`
> (`zend_string_safe_alloc(3, sid_length, 0, 0)`, ~121 B) after `send_cookie=1`,
> and the next request's pre-RINIT `rfc1867_cleanup` re-enters `PS(id)`. For
> execution the dangling object is `PS(http_session_vars)`, a `zend_reference`.
> See `docs/REPRODUCTIONS.md`. The experiments below are kept because they show
> which shapes do *not* reach the window.

Time-boxed attempt to turn the verified trigger into the documented memory
disclosure. **Result: not achieved.** Recorded so the next person does not
repeat the same dead ends.

## What has to happen

`PS(id)` must be freed and **not** reassigned:

```c
/* ext/session/session.c 8.4.24 */
462   zend_string_release_ex(PS(id), 0);        /* pointer now dangles */
463   PS(id) = PS(mod)->s_create_sid(...);      /* a bailout here leaves it dangling */
```

Between those two lines there is exactly one call, and inside it one allocation
of `session.sid_length` bytes (22–256, default 32). So the 22–256-byte alloc has
to be the allocation that fails. Zend MM serves that size from a bin; a bin
allocation only raises OOM when a new 2 MB chunk cannot be allocated, i.e. the
heap must be exhausted *and* the bin's page must be full.

## Experiments

Lab: PHP 8.4.24 + mod_php, 1 worker, `memory_limit=16M`, `post_max_size=0`,
`use_strict_mode=1`, invalid 32-byte cookie.

| Shaping | Failure size reported by PHP | Reached `s_create_sid`? |
|---|---|---|
| 4 MB progress key | `4194336` (the key, huge alloc) | no — happens earlier than FILE_START |
| 1000 fields × 8 KB | `12288` (parser grow-buffer) | no |
| 1000 fields × 12 KB | `12288` | no |
| 1000 fields × 16 KB | `16384` | no |
| 1000 fields × 14 KB, 15 MB total | `16384` | no |
| 4 MB key + 0–15 MB filler (8 fields) | `872448 … 1941504` | no |
| byte-accurate `memory_limit` sweep 19–24 MB, 64 B steps | `4194336` / `4194352` only | no |

Follow-up: 5 requests after the abort on the same worker — all issued
well-formed 32-char `[0-9a-v]` session ids, none malformed.

## Why the shaping fails

Input-shaped allocations are dominated by **parser buffers** and the **progress
key**, both large allocations that fail first. Filling chunk memory with field
values makes the *parser's* next grow-buffer the failure point, not the SID bin.
`max_input_vars=1000` caps how many small strings an attacker can create, which
is ~64 KB — orders of magnitude short of exhausting a 2 MB chunk's bins.

## What would move this forward

- an instrumented build (`--enable-debug`, valgrind or ASan) with a breakpoint on
  `zend_mm_safe_error` to see the requested size and the bin/page state;
- allocator-level input control that this HTTP surface does not provide, or a
  different trigger than the progress key (the shutdown-path hypothesis — a
  bailout in session RSHUTDOWN before `php_rshutdown_session_globals` — is
  untested);
- note the vendor position: reliable exploitation "requires precise heap
  manipulation and timing".

## Not attempted

Control-flow hijack. Even with a working disclosure this is a further stage and
was out of scope for the box. No `id`, no shell, nothing published as an exploit.
