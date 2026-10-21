# related/ — a different bug that keeps being labelled "php2shell"

`handler-mismatch/verify_handler_mismatch.py` demonstrates PHP's session
serializer delimiter mismatch: a session written by a `php_serialize` endpoint and
read by a `php` endpoint splits at the first `|` inside a string value, and the
remainder is unserialized — including `__destruct` on the injected object even when
decoding then fails on trailing data.

It is a **configuration bug** (two handlers sharing `session.save_path`) known long
before these CVEs, and it needs no memory exhaustion. It is included here only
because the widely shared "php2shell" PoC repository lists it as Chain 2.

What it does *not* show: the `Failed to decode session object` warning is also
emitted for a benign/empty session file, so that string is not evidence of an
injection. The script therefore runs a control request with a benign filename and
only reports injection if a target-side side effect is observed.

Verified there (PHP 8.4.24, Apache mod_php, two document roots):

```
session file: a:1:{s:4:"note";s:19:"x|O:6:"Marker":0:{}";}
php handler:  Failed to decode session object. Session has been destroyed
side effect:  Marker::__destruct ran
```

Usage — the reader endpoint must define a class with an observable destructor:

```bash
python3 verify_handler_mismatch.py --target http://127.0.0.1:18080 \
    --write-path /app/note.php --read-path /api/index.php --marker-url /marker.txt
```
