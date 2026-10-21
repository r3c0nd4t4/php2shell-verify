# References

## Advisories

- CVE-2026-109618 — RCE via OOM corruption — https://www.cve.org/CVERecord?id=CVE-2026-109618
- CVE-2026-109619 — stale-state use-after-free — https://www.cve.org/CVERecord?id=CVE-2026-109619
- GHSA-w8hw-w9fx-j79w — https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- GHSA-6wmf-4rv5-p3rp — https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- Red Hat — https://access.redhat.com/security/cve/cve-2026-109618
- Unit 42 — https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/

## Upstream fix

- Commit `3584a98b` "Avoid state corruption via bailout" — https://github.com/php/php-src/commit/3584a98b
- Releases: PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 (2026-10-21)

## Analysis

- Wiz — https://www.wiz.io/blog/php2shell-php-rce
- Imperva — https://www.imperva.com/blog/php2shell-vulnerability-updates/
- Sansec — https://sansec.io/research/php2shell
- JFrog — https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/
- Rapid7 — https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/
- watchTowr — https://watchtowr.com/intelligence/php-cve-2026-109618-faq/

## Working public reproductions

- https://github.com/3em0/php2shell — full HTTP-only chain, Docker lab (amd64)
- https://github.com/dinosn/php-cve-2026-10961x-lab-poc — four-request chain, amplification study
- https://github.com/ikow/php2shell-poc — writeup and chains (A/B/C are other bugs)
- https://github.com/unlimit0118/CVE-2026-109619-php2shell-poc — minimal Docker lab

## Background

- PHP `session.upload_progress` — https://www.php.net/manual/en/session.upload-progress.php
- `session.serialize_handler` — https://www.php.net/manual/en/session.configuration.php#ini.session.serialize-handler
- `memory_limit` / OOM handling — https://www.php.net/manual/en/ini.core.php#ini.memory-limit
