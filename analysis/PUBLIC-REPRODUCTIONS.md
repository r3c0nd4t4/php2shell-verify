# Public reproductions of php2shell

Checked 2026-10-21 via the GitHub API. Working chains exist and are independent
of this repository. This page records what each one actually does, so the
"RCE is only a claim" status here is read correctly: it describes *our*
reproduction effort, not the state of the art.

## Repositories

| Repo | ★ | What it is | Mechanism (as implemented) | Environment |
|---|---|---|---|---|
| [`3em0/php2shell`](https://github.com/3em0/php2shell) | 1 | `exploit.py` + Docker lab; full HTTP-only chain | stage 1: OOM in `php_session_send_cookie()` → `php_url_encode()` over-read leaks Zend MM chunk base in `Set-Cookie`; stage 2: `ZSTR_LEN(PS(id))` reads `nTableSize` → libphp base; stage 3: fake reference/HashTable, `pDestructor = zif_system` | `linux/amd64`, `php:8.4.26-apache` / `8.5.11-apache`, single worker, `display_errors=On`, `memory_limit=8M` |
| [`dinosn/php-cve-2026-10961x-lab-poc`](https://github.com/dinosn/php-cve-2026-10961x-lab-poc) | 45 | four-request self-contained RCE, amplification + patch-gap study | Chain A: bucket published but uninitialised after OOM → shutdown `pDestructor`; Chain B: dangling `zend_reference` in `PS(http_session_vars)`; 52× memory amplification via duplicate 6-byte multipart headers | `x86_64`, PHP 8.5.11 / 8.4.x, Docker; negative control on 8.5.12 |
| [`ikow/php2shell-poc`](https://github.com/ikow/php2shell-poc) | 801 | research writeup, 5 chains | D: mod_php OOM → stale `EG()` → shutdown on stale globals; E: FPM stale `BG(unserialize)` | mixed |
| [`unlimit0118/CVE-2026-109619-php2shell-poc`](https://github.com/unlimit0118/CVE-2026-109619-php2shell-poc) | 2 | minimal Docker lab | forged `ZSTR_LEN` on the stale id → heap/libphp leak → `id>/tmp/p` | `x86_64`, hard-coded offsets, one worker |
| `ersinkoc/php-fix`, `HOSTED-POWER/php_uploadprogress_guard`, `chrisdfir/php2shell-detection`, `zarguell/php2shell-scanner`, `fufufuwa/php2shell-detect` | — | mitigations, detection, non-destructive scanners | defensive | — |

Note on `ikow`: chains A (session-file injection + LFI) and C (two session
handlers on one `save_path`) are the older, unrelated tricks, and B is a
`var_destroy` UAF reachable only when the application unserializes controlled
data. Only D/E are this CVE. Repos that lead with A/B/C are demonstrating
application misconfiguration, not the engine bug.

## How this changes the record here

- `analysis/ATTEMPT-stale-id.md` targeted a failing `s_create_sid()`. The public
  chain instead OOMs later, inside `php_session_send_cookie()` →
  `php_url_encode()`'s `zend_string_safe_alloc(3, sid_length, 0, 0)` (~121 B),
  *after* `PS(send_cookie)=1` and before it is cleared, then re-enters the
  dangling `PS(id)` from the next request's pre-RINIT
  `rfc1867_cleanup → php_session_initialize`. The dangling object that matters
  for execution is `PS(http_session_vars)` (a `zend_reference`), not `PS(id)`.
- Reachability with default `post_max_size` is solved by amplification: duplicate
  6-byte multipart headers cost ~314 B of heap each, so a 2.57 MB body can OOM a
  128 M limit. That answers the "how do you exhaust memory with an 8 MB body"
  question my notes left open.
- Heap grooming parameters are per-build (`n=841, t=406, v=16` on the `bookworm`
  profile) and the RCE stage needs module offsets, so it is `amd64`-specific.

## Why it is not reproduced here

This host is `aarch64` with no Docker daemon and no root, so the shipped labs
(x86-64 images, offsets measured on `libphp.so`) cannot run unmodified. Porting
stage 3 means re-deriving `zif_system` / `zval_ptr_dtor` offsets and the grooming
fields for an arm64 build — a research task, not a config change. The leak stages
are architecture-independent in principle but still require the OOM placement
above.

## Status statement

Our verified results stand: pre-RINIT abort, worker behaviour per SAPI, and the
source-level defects. Our *absence* of a disclosure or RCE is a limitation of the
effort recorded here, not evidence against the vulnerability. Anyone evaluating
exposure should treat the public chains as the realistic ceiling.
