---
title: 'CSAPP §1.1 — Bits + contexto: o que o hello.c ensina sobre significado'
description: 'Série CSAPP, parte 1: notas e reflexões sobre a seção 1.1 — toda informação é só bits, e o que muda é a forma como lemos.'
date: 2026-10-07
lang: pt
tags: [csapp, systems, c]
---

> **Série CSAPP** — notas de leitura de _Computer Systems: A Programmer's Perspective_, uma seção
> por vez. Todos os posts ficam em [#csapp](/tags/csapp/).
> _[Read in English](/posts/csapp-1-1-bits-and-context/)._

Comecei a ler _Computer Systems: A Programmer's Perspective_ (Bryant & O'Hallaron, 3ª ed.). O livro
abre com o programa mais famoso da história da computação:

```c
#include <stdio.h>

int main()
{
    printf("hello, world\n");
    return 0;
}
```

A proposta do capítulo 1 é acompanhar a vida desse programa: do momento em que alguém o digita num
editor até ele imprimir uma linha e terminar. Ele é trivial, mas para rodar precisa de todas as
partes do sistema trabalhando juntas. A primeira parada, a seção 1.1, cabe em duas páginas e tem
um título que parece uma equação: **Information Is Bits + Context**.

## O que o livro diz

O `hello.c` é um arquivo de texto. Para o disco, isso significa uma sequência de **bits** agrupados
em **bytes** de 8 bits. Cada byte é um número inteiro, e o padrão **ASCII** diz qual caractere cada
número representa: `#` é 35, `i` é 105 e a quebra de linha invisível `\n` é 10.

Arquivos que contêm só caracteres ASCII são chamados de **arquivos de texto**. Todo o resto é
**arquivo binário**.

Daí vem a frase central da seção:

> All information in a system — including disk files, programs stored in memory, user data stored
> in memory, and data transferred across a network — is represented as a bunch of bits. The only
> thing that distinguishes different data objects is the context in which we view them.

A mesma sequência de bytes pode ser um inteiro, um número de ponto flutuante, uma string ou uma
instrução de máquina. O livro termina a seção com um aviso: os números da máquina **não são** os
inteiros e reais da matemática. São aproximações finitas, e às vezes se comportam de forma
estranha. Esse assunto fica para o capítulo 2.

## Conferindo na prática

Abri o `hello.c` com o `od`, que mostra cada byte como número:

```text
$ od -An -tu1 hello.c | head -2
  35 105 110  99 108 117 100 101  32  60 115 116 100 105 111  46
 104  62  10  10 105 110 116  32 109  97 105 110  40  41  10 123
```

São os mesmos números da Figura 1.2 do livro. Também dá para ver os dois `10` seguidos no fim de
`#include <stdio.h>`: são a quebra de linha e a linha em branco.

Depois peguei só os quatro primeiros bytes, `23 69 6e 63`, e li esses bytes de cinco jeitos
diferentes:

| Lidos como...               | Significam                      |
| --------------------------- | ------------------------------- |
| texto ASCII                 | `#inc`                          |
| `int32` little-endian (x86) | `1668180259`                    |
| `int32` big-endian (rede)   | `594112099`                     |
| `float32` little-endian     | `4.3979 × 10²¹`                 |
| instrução x86-64            | `and ebp, DWORD PTR [rcx+0x6e]` |

![Os mesmos quatro bytes, 23 69 6e 63, lidos em cinco contextos diferentes](./same-bytes.svg)

O último resultado veio do `objdump`, que aceitou o começo de um `#include` como código de máquina
válido:

```text
$ head -c 8 hello.c > b.bin
$ objdump -D -b binary -m i386:x86-64 -M intel b.bin
   0:  23 69 6e        and    ebp,DWORD PTR [rcx+0x6e]
   3:  63 6c 75 64     movsxd ebp,DWORD PTR [rbp+rsi*2+0x64]
```

Os quatro bytes são os mesmos em todas as linhas da tabela. A única coisa que mudou foi a forma de
ler.

## Os bits não carregam o próprio significado

Esta é a parte filosófica, e acho que é o que a seção tem de mais importante.

Um byte não sabe o que é. O número 35 não "é" um `#`. Ele só vira `#` porque eu, o meu editor e o
comitê que criou o ASCII em 1963 combinamos ler assim. O significado não está nos dados. Está num
acordo que fica **fora** deles: no tipo que o compilador conhece, na extensão do arquivo, no header
de um protocolo, na documentação, na cabeça de quem programa.

Isso lembra uma ideia antiga da linguística: o signo é arbitrário. Nada na palavra "árvore" lembra
uma árvore, e nada no padrão `00100011` lembra um `#`. A diferença é que, no computador, esse
acordo precisa ser explícito e exato. Uma pessoa lendo um texto com erros de digitação ainda
entende o sentido. Uma CPU executando bytes de texto não percebe que tem algo errado.

Até a divisão entre "texto" e "binário" é uma categoria nossa. Para a máquina tudo é binário.
"Texto" é só o binário que combinamos ler pela tabela ASCII.

## Muitos bugs são erros de contexto

O lado pragmático: quando você começa a pensar em "bits + contexto", reconhece o mesmo tipo de erro
em vários lugares.

- **Mojibake.** Um texto em UTF-8 lido como Latin-1 vira `informaÃ§Ã£o`. Os bytes estão certos e
  a tabela usada para lê-los está errada.
- **Endianness.** Se você mandar um `int` pela rede sem `htonl`, o outro lado lê `594112099`
  quando você mandou `1668180259`.
- **Ponto flutuante.** `0.1 + 0.2` dá `0.30000000000000004`. O valor real foi aproximado pelo
  formato IEEE 754.
- **Overflow.** Em `int32`, `2147483647 + 1` volta para `-2147483648`. Em C, com inteiros com
  sinal, isso é _undefined behavior_, o que é pior ainda.
- **Injeção de código.** Um buffer overflow funciona porque, na memória, dados e instruções são
  feitos da mesma coisa. Se o atacante faz a CPU tratar os dados dele como código, os bits passam
  a ser executados. Proteções como NX e W^X são uma forma de impor contexto à memória: "esta
  região é para ler, esta é para executar".

Em todos esses casos os bits estão corretos. O que está errado é a interpretação.

## Abstração é contexto em cima de contexto

Olhando assim, a pilha inteira de um sistema é uma sequência de contextos:

```text
bits → bytes → caracteres → tokens → árvore sintática → instruções → processo
```

Cada camada pega a camada de baixo e lê os dados dela de um jeito novo. O compilador, que aparece
na seção 1.2, é basicamente uma máquina que troca um contexto por outro: lê bytes como C e
escreve bytes como x86. Chamamos de **abstração** a camada em que um contexto fica estável o
bastante para a gente deixar de pensar na camada de baixo.

O livro existe porque essas abstrações às vezes falham. Quando um `float` não soma direito ou um
`int` vira negativo, é a camada de baixo aparecendo. O programador que só conhece a camada de cima
vê mágica, ou um bug "impossível". Quem conhece os bits embaixo vê só um contexto que mudou.

## O que fica

1. Dados sozinhos não dizem nada. Sempre pergunte qual é o contexto: tipo, codificação, ordem dos
   bytes, formato.
2. Torne o contexto explícito. Use tipos fortes, declare charset, documente formatos e escreva
   magic numbers no começo dos arquivos. Contexto implícito costuma virar bug mais tarde.
3. Desconfie das fronteiras. Rede, disco, FFI e `memcpy` são lugares onde os bits atravessam de um
   contexto para outro, e é ali que a interpretação costuma se perder.

Para uma seção de duas páginas, rendeu bastante. Próxima parada: [1.2](/posts/csapp-1-2-programas-traduzidos/), onde o `hello.c` é traduzido
por outros programas até virar um executável.
