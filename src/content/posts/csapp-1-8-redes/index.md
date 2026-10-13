---
title: 'CSAPP §1.8 — Sistemas conversam pela rede: o hello em outra máquina'
description: 'Série CSAPP, parte 8: notas e reflexões sobre a seção 1.8 — a rede como mais um dispositivo de E/S, e o hello rodando através de um socket.'
date: 2026-10-13T11:52:00Z
lang: pt
tags: [csapp, systems, os, networking]
---

> **Série CSAPP** — notas de leitura de _Computer Systems: A Programmer's Perspective_, uma seção
> por vez. Todos os posts ficam em [#csapp](/tags/csapp/). Anterior:
> [§1.7 — O sistema operacional](/posts/csapp-1-7-o-sistema-operacional/).
> _[Read in English](/posts/csapp-1-8-networks/)._

Até aqui, a série tratou o computador como uma coisa isolada: um processador, uma memória, alguns
dispositivos e um sistema operacional. A seção 1.8 lembra o óbvio: quase nenhum computador hoje vive
sozinho. E a forma como o livro encaixa a rede no que já vimos é bem simples.

## O que o livro diz

Do ponto de vista de um sistema, **a rede é só mais um dispositivo de E/S**. Ela se liga ao
barramento de E/S por um adaptador de rede, como o disco se liga pelo controlador de disco. Quando o
sistema copia bytes da memória para o adaptador, esses bytes vão para outra máquina em vez de irem
para o disco. Quando lê da rede, copia para a memória bytes que vieram de fora.

Com a Internet, copiar informação de uma máquina para outra virou um dos usos mais importantes dos
computadores. Email, mensagens, a Web: tudo depende disso.

Para ilustrar, o livro roda o `hello` em outra máquina usando **telnet**:

1. O usuário digita `hello` no cliente telnet da máquina local.
2. O cliente envia a string ao servidor telnet da máquina remota.
3. O servidor passa a string ao shell remoto, que roda o `hello` e devolve a saída ao servidor.
4. O servidor envia `hello, world\n` pela rede de volta ao cliente.
5. O cliente imprime a string no terminal local.

Esse vai-e-volta entre **cliente e servidor** é o padrão de praticamente toda aplicação de rede. No
capítulo 11, o livro usa isso para construir um servidor Web.

A seção tem ainda um aside com o anúncio original do Linux, de 25 de agosto de 1991. Linus Torvalds,
um estudante finlandês, escreveu no grupo `comp.os.minix`: _"I'm doing a (free) operating system
(just a hobby, won't be big and professional like gnu) for 386(486) AT clones."_ O ponto de partida
foi o Minix, um sistema feito por Andrew Tanenbaum para ensino. Junto com as ferramentas do GNU, o
Linux virou um Unix completo.

## Conferindo na prática

### O hello pela rede

O telnet não é mais usado hoje, porque manda tudo em texto puro, inclusive senhas. Mas dá para
montar o mesmo esquema da Figura 1.15 com o `socat`. Para não abrir nada para fora, o servidor só
aceita conexões da própria máquina e só roda o `./hello`, nunca um shell:

```text
$ socat TCP-LISTEN:2323,bind=127.0.0.1,reuseaddr,fork EXEC:./hello &
$ socat - TCP:127.0.0.1:2323
hello, world
```

Para cada conexão, o servidor faz `fork`, roda o `hello` e liga a saída do programa ao socket. O
cliente lê do socket e imprime no terminal. Cada ida e volta completa levou cerca de **7 ms**,
incluindo criar os processos.

O detalhe mais interessante é que o `hello` não mudou nada. É o mesmo binário da
[seção 1.2](/posts/csapp-1-2-programas-traduzidos/). Ele continua chamando `write` no descritor 1,
sem saber que, desta vez, o descritor 1 é uma conexão TCP. Isso só funciona por causa da abstração
de arquivo da [seção 1.7](/posts/csapp-1-7-o-sistema-operacional/).

### A rede como arquivo

O mesmo vale do lado de quem lê. No bash, uma conexão TCP é um descritor de arquivo como outro
qualquer:

```text
$ exec 3<>/dev/tcp/1.1.1.1/80
$ printf 'GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n' >&3
$ head -1 <&3
HTTP/1.1 301 Moved Permanently
```

Um `write` mandou a requisição HTTP e um `read` trouxe a resposta. Os mesmos dois verbos usados para
ler e escrever arquivos em disco.

### Quão longe é "longe"

| Destino                                 | Tempo de ida e volta |
| --------------------------------------- | -------------------- |
| `127.0.0.1` (a própria máquina)         | ~0,08 ms             |
| `rt-00.github.io` (servidor deste blog) | ~11 ms               |

A mesma pilha de rede, com e sem o caminho físico até o outro lado: mais de 100 vezes de diferença.
Como vimos na [seção 1.6](/posts/csapp-1-6-hierarquia-de-memoria/), a rede é o degrau mais baixo da
hierarquia de memória. Se um acesso à L1 levasse um segundo, uma ida e volta até o GitHub levaria
quatro meses.

## A mesma interface, outro mundo

Esta é a parte filosófica.

A decisão de tratar a rede como mais um dispositivo de E/S é elegante. Um programa que escreve num
arquivo pode, sem mudar nada, escrever para alguém do outro lado do mundo. O `hello` de 1978 (o do
livro de Kernighan e Ritchie) roda hoje através de um socket sem saber disso.

Mas a interface igual esconde uma diferença enorme. Um disco local raramente desaparece no meio de
uma leitura. A rede pode ficar lenta, perder pacotes, entregar só parte dos dados ou ficar em
silêncio porque o outro lado morreu. A primeira das "falácias da computação distribuída", uma lista
famosa de suposições erradas sobre redes, é justamente achar que _a rede é confiável_.

Então a abstração de arquivo faz duas coisas ao mesmo tempo. Ela torna a rede fácil de usar, porque é
só `read` e `write`. E ela torna fácil esquecer que a rede é diferente de um arquivo. Boa parte dos
problemas de sistemas distribuídos vem desse esquecimento.

## Fechando o ciclo do hello

O lado pragmático, e um balanço.

Desde o primeiro post, a série acompanhou o mesmo programa de sete linhas. Ele começou como bytes
ASCII num arquivo ([1.1](/posts/csapp-1-1-bits-e-contexto/)), foi traduzido em código de máquina
([1.2](/posts/csapp-1-2-programas-traduzidos/)), rodou num processador
([1.4](/posts/csapp-1-4-o-processador/)) através do sistema operacional
([1.7](/posts/csapp-1-7-o-sistema-operacional/)) e agora roda numa máquina enquanto imprime em outra.

Olhando para trás, quase todo passo foi **copiar bytes de um lugar para outro**: do disco para a
memória, da memória para os registradores, dos registradores para a tela, da memória para o
adaptador de rede. A [seção 1.5](/posts/csapp-1-5-caches-importam/) já tinha dito que a maior parte
do trabalho de um computador é mover dados. A rede só estende essa distância.

Algumas consequências práticas:

- **Toda chamada pela rede tem um caso de falha.** Pense em _timeouts_ e em novas tentativas desde o
  começo, não depois do primeiro incidente.
- **A latência domina.** A 11 ms por ida e volta, cem chamadas em sequência já passam de um segundo.
  Junte as chamadas ou faça várias em paralelo.
- **A primeira conexão é a mais cara.** DNS, TCP e TLS somam dezenas de milissegundos. Reaproveite
  conexões.

## O que fica

1. A rede é E/S: `read` e `write` num descritor. Isso facilita escrever o código e não muda nada
   sobre a física do caminho.
2. Programas que escrevem em `stdout` e leem de `stdin` funcionam em qualquer lugar: terminal,
   arquivo, pipe ou socket. Vale a pena escrever ferramentas assim.
3. Trate a rede como o nível mais lento e menos confiável da hierarquia, porque é isso que ela é.

Próxima parada: 1.9, onde o livro reúne os temas importantes do capítulo.
