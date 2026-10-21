# Reference target (amd64)

A stock `php:8.4.26-apache` container configured the way the published chains
expect: one prefork worker, `display_errors=On`, `memory_limit=8M`,
`post_max_size=64M`, `session.upload_progress` on, page content `OK`.

```bash
docker compose -f lab/docker/docker-compose.yml up -d
curl -s http://127.0.0.1:8088/          # OK
```

**Status: not executed by this repository.** The packaging host is `aarch64`
with no Docker daemon, so this configuration is here as a reference target, not
as a verified result. Treat it as a starting point for the amd64 labs listed in
[`../../docs/REPRODUCTIONS.md`](../../docs/REPRODUCTIONS.md), which ship their own
verified compose files and exploits.

What you should see if you point a chain at it: an OOM abort during request
startup (empty response, no `Set-Cookie`), then a `Set-Cookie: PHPSESSID=` whose
value is longer than any session id — the disclosure stage. Command execution
needs the offsets for the image's `libphp.so`; the referenced repos derive them
automatically.

Do not expose this container. It is a deliberately vulnerable target.
