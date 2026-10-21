# Findings

Everything below was observed on PHP 8.4.24 (Debian/Kali, `php8.4` + `libapache2-mod-php8.4`), and cross-checked against php-src 8.4.24 and 8.4.27 sources.

## 1. Upstream fix

Commit `3584a98b` — *"Avoid state corruption via bailout"*, 2026-10-18:

```
- Replace bailout on OOM with UnwindExit
- Properly reset various globals that may be accessed during startup

Fix GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
Fix GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
```

`NEWS` for 8.4.27 carries the same mapping. Not a `|`-delimiter or session-file-poisoning bug.

## 2. Pre-RINIT path is reachable and attacker-controlled

`php_session_rfc1867_callback()` runs while the multipart body is parsed, before RINIT. Evidence from a request that OOMs:

```
PHP Fatal error: Allowed memory size of 16777216 bytes exhausted
(tried to allocate 4194336 bytes) in Unknown on line 0
```

`Unknown on line 0` = no executing script → the abort happens during request startup. With `display_errors=On` the same errors appear as `PHP Request Startup: ...`, e.g.:

```
PHP Warning:  PHP Request Startup: Failed to decode session object. Session has been destroyed in Unknown on line 0
PHP Warning:  PHP Request Startup: Failed to write session data (files). ... in Unknown on line 0
```

The progress key (`session.upload_progress.prefix` + the `PHP_SESSION_UPLOAD_PROGRESS` field value) and the uploaded filename are attacker-controlled. Both land in the session file:

```
a:1:{s:17:"upload_progress_x";a:5:{...s:5:"files";a:1:{i:0;a:7:{s:10:"field_name";s:1:"f";
s:4:"name";s:19:"x|O:6:"Marker":0:{}";...
```

## 3. The defects the patch removes

8.4.24 `ext/session/session.c`:

| Line | Code | Problem |
|---|---|---|
| 3187–3188 | `php_session_initialize(); PS(session_status) = php_session_active;` | failure ignored; flush proceeds on a half-initialised module |
| 3202–3203 | same in `php_session_rfc1867_cleanup()` | same |
| 445–446 | `zend_string_release_ex(PS(id), 0); PS(id) = s_create_sid(...)` | `PS(id)` dangles if `s_create_sid` bails |
| 462–466 | strict-mode branch: release, then `s_create_sid`, then fallback | same; reachable with an attacker-chosen cookie when `session.use_strict_mode=1` |
| 3213 | no reset before `MULTIPART_EVENT_START` | INI-derived PS globals (`session_name`, `rfc1867_name/prefix`) are read before RINIT | 

8.4.27 adds `PS(id) = NULL` after every release, checks `php_session_initialize()`, sets `in_rfc1867_update` for the pre-RINIT decode (no autoload / `__wakeup` / `__unserialize`; objects stay `__PHP_Incomplete_Class`), and calls `php_rinit_session_globals()` at `MULTIPART_EVENT_START`.

## 4. Observable outcomes

| Scenario | Result |
|---|---|
| php-cgi (FastCGI worker), 16 M limit, 4 MB progress key | fatal OOM then **process exit 255**; no further requests served |
| mod_php 8.4.24, same request | `200`, `Content-Length: 0`, no `Set-Cookie`, child **survives** |
| mod_php, 24 M limit, 4 MB key | cookie issued, then OOM in the serializer (`4194352` B) |
| mod_php, key below the limit | normal response, script runs |

The mod_php case is the interesting one: the abort leaves state inside a *surviving* worker, which is the precondition for the cross-request stale pointer.

## 5. What the disclosure needs (and why it did not fire here)

Documented primitive (Wiz / Imperva): `PS(id)` points at freed memory after the failed `s_create_sid`; a later multipart request reaches the pre-RINIT callback before header startup resets it, and the freed `zend_string` header is read as an oversized length and echoed via `Set-Cookie: PHPSESSID`.

For that, the failing allocation must be the ~32-byte SID string. Zend MM serves small sizes from bins inside 2 MB chunks, so it only fails when a new chunk cannot be allocated. Measured attempts, all failing at huge allocations instead:

| Sweep | Failure sizes |
|---|---|
| `memory_limit` 19–24 MB, 64-byte steps, 4 MB key | `4194336`, `4194352` only |
| 4 MB key + 0–15 MB filler fields (8 fields) | `872 448 … 1 941 504` |
| small key + 0–15 MB filler (chunk filling) | `872 448 … 1 941 504`, no ~32-byte failure |
| 40-step sweeps via `--mode sweep` | 0 malformed SIDs |

Conclusion: a working disclosure needs deterministic chunk grooming at the `FILE_START` boundary, not a different request shape. Not achieved here, and no RCE was attempted.

## 6. Circulating PoC conflates a different bug

`wakemeiflose/php2shell` lists "Chain 2" as the session-serializer `|` delimiter → object injection → `__destruct`. That is a `php_serialize` (write) vs `php` (read) handler mismatch — a configuration bug, demonstrable on any PHP version, requiring two handlers and a second application sharing `session.save_path`. Its other chains (LFI + session poisoning, log poisoning, `/proc/self/fd`, `phpinfo()` temp files, PEARCMD, wrappers) all require a pre-existing LFI. Its lab sets `upload_progress.cleanup=Off`, which no default target has.

`poc/mismatch.py` contains a working demonstration of that *different* primitive, with a control run showing that `Failed to decode session object` is emitted for an empty session file too — so that warning is not evidence of anything.
