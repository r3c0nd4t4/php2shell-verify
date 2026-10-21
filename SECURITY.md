# Security policy and scope

This repository contains **verification tooling**, not a weaponised exploit.
It does not contain a code-execution chain.

## If you are here because of CVE-2026-109618 / CVE-2026-109619

Patch to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12. Interim: set `memory_limit = -1`
where applications cannot override it (watch RSS), and treat configuration
switches such as disabling `session.upload_progress` as partial mitigations only.

## Running the probe

The probe deliberately exhausts the target's per-request memory limit:

- it can terminate PHP-FPM/CGI workers and Apache children (denial of service);
- it sends multi-megabyte multipart bodies, which may be logged;
- it will not work against a patched target by design.

Use it only on systems you own or have written authorisation to test.

## Reporting a problem with this repository

Open an issue for correctness bugs (wrong version ranges, probe false positives,
platform path differences). Do not attach production memory dumps or session
files that may contain credentials.

## Known limitation, stated up front

The stale-session-id disclosure is implemented but not reproduced by the author.
Reports claiming it works with a given `memory_limit` / heap layout are welcome
if they include the observed `Set-Cookie`, the PHP version, the SAPI and the
values of `memory_limit`, `post_max_size` and `max_input_vars`.
