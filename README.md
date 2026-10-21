# php2shell-verify

Verification toolkit and source-level analysis for **CVE-2026-109618 / CVE-2026-109619** — state corruption when an out-of-memory `longjmp` escapes PHP's pre-RINIT `session.upload_progress` callback.

**What this is:** a probe that reproduces the trigger (an OOM that aborts the request before any application code runs), two local labs, and an analysis of the fix.
**What this is not:** an exploit. No shell, no weaponised chain.

| | Status |
|---|---|
| Paths to the pre-RINIT callback, OOM abort | **verified** (PHP 8.4.24, mod_php + php-cgi) |
| Worker survives on mod_php; CGI process exits 255 | **verified** |
| Source defects removed by 8.4.27 | **verified** against `ext/session/session.c` |
| Stale-session disclosure | probe implemented, **not reproduced here** |
| Remote code execution | **not reproduced here** — reproduced publicly, see [`docs/REPRODUCTIONS.md`](docs/REPRODUCTIONS.md) |

## Quick start

```bash
./lab/verify/run.sh start
python3 poc/verify.py --mode oom
./lab/verify/run.sh stop
```

```
[*] POST 4194558 bytes, progress key 4194304 bytes
[*] HTTP 500 in 0.00s, body=0B, Set-Cookie=None
[+] request aborted before any application code ran (empty response, no session cookie) -> pre-RINIT callback path
[*] worker still serving: True
```

Server side: `PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 4194336 bytes) in Unknown on line 0`. No script frame — the abort happens during request startup.

## The bug in 30 seconds

`session.upload_progress` initialises the session while the multipart body is parsed, **before RINIT**:

```c
/* ext/session/session.c, 8.4.24 */
3187  php_session_initialize();
3188  PS(session_status) = php_session_active;   /* forced even if init FAILED */
 445          zend_string_release_ex(PS(id), 0); /* freed, pointer left dangling */
 446          PS(id) = PS(mod)->s_create_sid(...);
```

If an allocation fails inside that path, `zend_bailout()` unwinds out of a half-initialised operation. The next request on the same worker can then use a pointer that was freed. Full detail, including what the fix changes: [`docs/MECHANISM.md`](docs/MECHANISM.md).

## Choose a lab

| Lab | Port | Demonstrates | Not |
|---|---|---|---|
| [`lab/verify/`](lab/verify) | 18090 | the CVE surface: abort, stale-session window | no execution |
| [`lab/mismatch/`](lab/mismatch) | 18092 | command execution via a **different** bug | not the CVE |
| [`lab/docker/`](lab/docker) | 8088 | reference target for the amd64 chains | not executed here |

```bash
./lab/mismatch/run.sh start
python3 poc/mismatch.py -c id      # uid=<the Apache user>
./lab/mismatch/run.sh stop
```

That `id` comes from two apps sharing `session.save_path` with different
`session.serialize_handler` values plus an application gadget — a configuration
bug that works on any PHP version. It is included as a control: it proves the
harness detects execution, which is why `verify` returning nothing means something.

## PoCs

| Script | Purpose |
|---|---|
| [`poc/verify.py`](poc/verify.py) | safe probe: `recon`, `oom`, `stale-sid`, `sweep` |
| [`poc/mismatch.py`](poc/mismatch.py) | lab-only command execution through the handler mismatch |

`verify.py` exits `0` on an observed symptom, `2` when the probe ran but saw
nothing, `1` on an unusable target. It never attempts execution.

## Why the disclosure was not reproduced here

The public chains place the OOM at a specific allocation inside
`php_session_send_cookie()`/`php_session_initialize()` and then shape the heap so
the stale pointer is reclaimed with controlled bytes. This repository reached the
abort but not the window; the experiments and their failure sizes are recorded in
[`analysis/ATTEMPT-stale-id.md`](analysis/ATTEMPT-stale-id.md). That is a limit of
this effort, not evidence against the vulnerability — see
[`docs/REPRODUCTIONS.md`](docs/REPRODUCTIONS.md) for the chains that did it.

## Affected and fixed

Affected: PHP 8.2.x < 8.2.35, 8.3.x < 8.3.36, 8.4.x < 8.4.27, 8.5.x < 8.5.12.
Fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (2026-10-21), upstream commit
`3584a98b`. Patch; `memory_limit=-1` and disabling `upload_progress` are partial
mitigations only.

## Repository map

```
poc/       verify.py (safe probe)   mismatch.py (lab command execution)
lab/       verify/  mismatch/  docker/
docs/      MECHANISM.md  REPRODUCTIONS.md
analysis/  FINDINGS.md  ATTEMPT-stale-id.md  patch-session.diff  verified-run.txt
REFERENCES.md
SECURITY.md
```

## References

Advisories, writeups, the upstream commit and the working public reproductions:
[`REFERENCES.md`](REFERENCES.md).

## Authorised use

Run the labs and probes only against systems you own or are explicitly authorised
to test. The CVE probe deliberately exhausts the request memory limit and can
terminate workers. See [`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE).
