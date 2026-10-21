# php2shell-verify

Verification toolkit and source-level analysis for **CVE-2026-109618 / CVE-2026-109619** ("php2shell") — state corruption when an out-of-memory `longjmp` escapes PHP's pre-RINIT `session.upload_progress` callback.

**What this is:** a probe that reproduces the trigger I could verify — an OOM aborting the request *before any application code runs* — plus the probe for the documented memory-disclosure primitive (stale `PS(id)` echoed in `Set-Cookie: PHPSESSID`).

**What this is not:** a working RCE exploit. No code execution, no heap-grooming chain, no weaponisation. The status table below is deliberate.

| Item | Status |
|---|---|
| pre-RINIT upload-progress callback reachable, OOM abort before script | **verified** (PHP 8.4.24, mod_php + php-cgi) |
| worker survives the abort on mod_php; process exits 255 under CGI | **verified** |
| `session.init` failure ignored after `PS(session_status) = active` | **verified in source**, patch removes it |
| stale `PS(id)` → malformed/oversized `Set-Cookie` | **implemented, not reproduced** |
| remote code execution | **not attempted** |

If you found this while looking for a "php2shell exploit": it won't give you a shell. It will tell you whether a target is in the affected code path.

## The bug in one paragraph

`session.upload_progress` processes a multipart body *before* RINIT. That callback (`php_session_rfc1867_callback`, `ext/session/session.c`) initialises the session and writes attacker-controlled data, relying on request globals that were not reset for this request yet. On memory exhaustion PHP aborts via `zend_bailout()`/`longjmp()` out of a half-initialised operation. Two things are left inconsistent:

```c
/* 8.4.24, ext/session/session.c */
3187  php_session_initialize();
3188  PS(session_status) = php_session_active;   /* forced even when init FAILED */
...
 445          zend_string_release_ex(PS(id), 0); /* freed, pointer left dangling */
 446          PS(id) = PS(mod)->s_create_sid(...); /* a bailout here leaves it dangling */
```

The 8.4.27 fix (`ext/session/session.c` plus engine-wide OOM handling) does four things: `PS(id) = NULL` immediately after release, initialisation failures returned instead of forced to `active`, `in_rfc1867_update` gating user code during the pre-RINIT decode, and `php_rinit_session_globals()` at `MULTIPART_EVENT_START` — *"This runs before RINIT, so we need to clear these early"*. The engine side replaces OOM `longjmp` with a delayed OOM (`EG(delayed_oom)`, UnwindExit) and adds a hard memory limit.

## Quick start

No third-party dependencies; the probe is stdlib-only Python 3.8+.

```bash
# vulnerable target (Apache + mod_php 8.4.24, single worker, memory_limit 16M)
./lab/setup_modphp.sh start               # port 18090 + writable log dir, no root required

# fingerprint
python3 poc/php2shell_probe.py --target http://127.0.0.1:18090 --mode recon

# verified trigger: 4 MB progress value vs 16 M limit
python3 poc/php2shell_probe.py --target http://127.0.0.1:18090 --mode oom
```

Observed:

```
[*] POST 4194558 bytes, progress key 4194304 bytes
[*] HTTP 200 in 0.00s, body=0B, Set-Cookie=None
[+] request aborted before any application code ran (empty response, no session cookie) -> pre-RINIT callback path
[*] worker still serving: True
```

Server side, same request: `PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 4194336 bytes) in Unknown on line 0` — no script frame, i.e. request startup, not application code.

## Modes

| Mode | Purpose |
|---|---|
| `recon` | PHP version vs fixed versions, cookie behaviour |
| `oom` | trigger the pre-RINIT abort; report body/cookie shape and worker survival |
| `stale-sid` | request A drives the strict-mode release path into an OOM, request B probes the same worker and inspects `Set-Cookie` for a malformed/oversized SID |
| `sweep` | lab only: vary filler to try to make the *small* SID allocation the one that fails |

Exit codes: `0` observed, `1` unusable target, `2` probe ran but no symptom.

Useful flags: `--key-bytes`, `--filler-fields`, `--filler-bytes`, `--sid` (strict-mode probe), `--path`.

## Why it does not fire everywhere (measured)

The disclosure needs `PS(id)` to be freed and **not** reassigned, i.e. the ~32-byte `zend_string_alloc()` inside `s_create_sid()` must be the allocation that fails. Small-bin allocations only fail when a new 2 MB chunk cannot be allocated, so it is a chunk-grooming problem, not a request-shaping one. Measurements on 8.4.24, `memory_limit=16M`:

| Attempt | Failures observed |
|---|---|
| sweep 19–24 MB at 64-byte steps | only huge allocations, `4194336` / `4194352` B |
| 4 MB key, 0–15 MB of filler fields | `872 K – 1.94 M` B (parser / serializer), never ~32 B |
| 40-step field sweeps | 0 malformed session ids |

Red Hat's own statement matches: *"reliable exploitation requires precise heap manipulation and timing."* The probe exposes the knobs; the grooming chain is missing.

## Related, but a different bug

`related/handler-mismatch/` demonstrates the `php_serialize` ↔ `php` `|` delimiter mismatch (object injection into `__destruct`). It is a **configuration bug**, not these CVEs. It is included because the most-shared "php2shell" PoC repository lists exactly that as "Chain 2", alongside generic LFI/log-poisoning chains that need a pre-existing file-inclusion bug. Those chains work on a lab that sets `upload_progress.cleanup=Off` and an LFI endpoint; they do not exercise this vulnerability.

## Affected and fixed

Affected: PHP 8.2.x < 8.2.35, 8.3.x < 8.3.36, 8.4.x < 8.4.27, 8.5.x < 8.5.12 (code dates to 5.4). Fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, 2026-10-21; upstream commit `3584a98b` (2026-10-18), `analysis/patch-commit.txt`.

## Detection

- `200` with an empty body and **no** `Set-Cookie` on a multipart POST that carries `PHP_SESSION_UPLOAD_PROGRESS`
- `Allowed memory size ... exhausted ... in Unknown on line 0` / `PHP Request Startup:` prefixed errors
- worker churn / `MaxRequestWorkers` reached after upload requests
- `Set-Cookie: PHPSESSID=` values outside `[0-9a-v]{26,256}` (the disclosure symptom)

## Mitigation

Patch. Interim, per PHP: `memory_limit = -1` at a level applications cannot override (`php_admin_value`) — this only closes the engine OOM path and lets a request consume all server memory, so monitor RSS; disable `session.upload_progress` and filter multipart bodies at the edge as defence in depth. PHP's own advisory is explicit that configuration workarounds close only some paths.

## Timeline and sources

- 2026-10-18 upstream fix commit `3584a98b`; 2026-10-21 releases 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
- Advisories: `GHSA-w8hw-w9fx-j79w`, `GHSA-6wmf-4rv5-p3rp`
- Analysis: Red Hat, Unit 42, Wiz, Imperva, Sansec, watchTowr

## Authorised use

Run this only against systems you own or have written permission to test. It sends large multipart bodies and deliberately exhausts the request memory limit; it will terminate workers and can cause a denial of service on the target. See `SECURITY.md`.

## License

MIT — see `LICENSE`.
