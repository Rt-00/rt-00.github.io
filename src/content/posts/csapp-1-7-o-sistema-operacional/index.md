---
title: 'CSAPP §1.7 — O sistema operacional: processos, memória virtual e arquivos'
description: 'Série CSAPP, parte 7: notas e reflexões sobre a seção 1.7 — as três ilusões que o sistema operacional constrói, e quanto cada uma custa.'
date: 2026-10-13T11:51:00Z
lang: pt
tags: [csapp, systems, os, c]
---

> **Série CSAPP** — notas de leitura de _Computer Systems: A Programmer's Perspective_, uma seção
> por vez. Todos os posts ficam em [#csapp](/tags/csapp/). Anterior:
> [§1.6 — A hierarquia de memória](/posts/csapp-1-6-hierarquia-de-memoria/).
> _[Read in English](/posts/csapp-1-7-the-operating-system/)._

Na [seção 1.4](/posts/csapp-1-4-o-processador/), o shell carregou o `hello` e o `hello` imprimiu a
mensagem. Mas nenhum dos dois tocou no teclado, na tela, no disco ou na memória diretamente. Quem fez
isso por eles foi o **sistema operacional**. A seção 1.7 explica o que ele é, e este post cobre as
quatro subseções: processos, threads, memória virtual e arquivos.

## O que o livro diz

O sistema operacional é uma camada de software entre as aplicações e o hardware. Todo acesso ao
hardware passa por ele, e ele tem dois propósitos:

1. **Proteger** o hardware de aplicações que se comportam mal.
2. Dar às aplicações uma forma **simples e uniforme** de usar hardware complicado e muito variado.

Para isso, ele oferece três abstrações. **Arquivos** representam os dispositivos de E/S. A
**memória virtual** representa a memória principal e o disco. E os **processos** representam o
processador, a memória e a E/S juntos.

**Processos (1.7.1).** Quando o `hello` roda, o sistema operacional dá a ele a ilusão de ser o
único programa da máquina: a CPU, a memória e os dispositivos parecem exclusivos dele. Um processo é
a abstração de um programa em execução, e o livro o chama de uma das ideias mais importantes e
bem-sucedidas da computação. Vários processos rodam de forma **concorrente**, com as instruções de um
intercaladas com as de outro. Para alternar entre eles, o sistema faz uma **troca de contexto**:
salva o estado do processo atual (PC, registradores, memória), restaura o estado do próximo e passa o
controle para ele. Quem faz isso é o **kernel**, a parte do sistema que fica sempre na memória. Uma
aplicação pede algo ao kernel por uma **chamada de sistema** (_system call_). E um detalhe que o
livro faz questão de destacar: o kernel não é um processo. Ele é o código e as estruturas de dados
que gerenciam todos os processos.

**Threads (1.7.2).** Um processo pode ter várias linhas de execução, as **threads**, que rodam no
contexto do mesmo processo e compartilham o código e os dados globais. É mais fácil compartilhar
dados entre threads do que entre processos, e threads costumam ser mais leves.

**Memória virtual (1.7.3).** Cada processo tem a ilusão de usar a memória principal sozinho. Todos
enxergam o mesmo **espaço de endereçamento virtual**, organizado da mesma forma: de baixo para cima,
o código e os dados do programa, o heap (que cresce com `malloc`), as bibliotecas compartilhadas, a
pilha (que cresce a cada chamada de função) e, no topo, a memória do kernel, que a aplicação não pode
acessar. Por baixo, o hardware traduz cada endereço, e a memória principal funciona como cache do
disco.

**Arquivos (1.7.4).** Um arquivo é uma sequência de bytes, _nada mais, nada menos_. Todo dispositivo
de E/S (disco, teclado, monitor e até a rede) é tratado como arquivo, e toda E/S é feita com um
pequeno conjunto de chamadas de sistema: a **Unix I/O**.

A seção tem ainda um aside sobre a história do Unix. Ele nasceu em 1969, quando a Bell Labs saiu do
projeto Multics, considerado complexo demais. Ken Thompson, Dennis Ritchie, Doug McIlroy e Joe
Ossanna começaram um sistema mais simples num PDP-7, e em 1970 Brian Kernighan o batizou de "Unix",
um trocadilho com "Multics". Depois vieram o BSD, o System V e, para conter as incompatibilidades, o
padrão **Posix**.

## Conferindo na prática

### Mesmo endereço, valores diferentes

Este programa cria um processo filho com `fork`. O filho muda uma variável global e os dois
imprimem o endereço e o valor dela:

```c
int counter = 0;

pid_t pid = fork();
if (pid == 0) {
    counter = 7;
    printf("filho: &counter = %p, counter = %d\n", (void *)&counter, counter);
    _exit(0);
}
waitpid(pid, NULL, 0);
printf("pai:   &counter = %p, counter = %d\n", (void *)&counter, counter);
```

```text
filho: &counter = 0x5e8dd016a0e0, counter = 7
pai:   &counter = 0x5e8dd016a0e0, counter = 0
```

O **mesmo endereço** guarda **valores diferentes** em cada processo. É a memória virtual: cada
processo tem o seu próprio espaço de endereçamento, e o mesmo endereço virtual aponta para lugares
diferentes da memória física. Trocando o `fork` por uma thread que faz `counter = 42`, a `main`
passa a ver 42, porque threads compartilham a memória do processo.

### O espaço de endereçamento de verdade

O mesmo programa imprime onde estão algumas coisas na memória:

![O espaço de endereçamento virtual de um processo, de baixo para cima: código, dados, heap, bibliotecas compartilhadas, pilha e kernel, com os endereços reais medidos](./address-space.svg)

A ordem é exatamente a da Figura 1.13 do livro: código, dados, heap, bibliotecas, pilha. Os
endereços mudam a cada execução, porque o Linux sorteia as posições (ASLR) para dificultar ataques.
E a última linha do programa tenta ler um endereço do kernel:

```text
ler 0xffffffff81000000 -> SIGSEGV
```

O hardware recusa, e o kernel entrega um sinal de falha de segmentação ao processo. É a proteção do
primeiro propósito acontecendo.

### O fork copiou até o buffer

Uma surpresa: quando rodei o programa com a saída num pipe, as primeiras linhas apareceram
**duplicadas**. Na [seção 1.4](/posts/csapp-1-4-o-processador/) vimos que, num pipe, o `printf` só
enche um buffer da libc, e o texto só é escrito depois. O `fork` copia a memória inteira do
processo, e isso inclui esse buffer com o texto ainda não escrito. Pai e filho acabaram imprimindo o
mesmo texto. Um `fflush(stdout)` antes do `fork` resolve.

É um bom exemplo de como as abstrações se encostam. O buffer é um detalhe da libc, o `fork` é um
detalhe do kernel, e o bug só aparece quando os dois se encontram.

### Quanto custa a ilusão

| Operação                                                 | Custo       |
| -------------------------------------------------------- | ----------- |
| uma chamada de sistema vazia (`getppid`)                 | ~135 ns     |
| ida e volta entre dois processos no mesmo CPU, por pipes | ~4,4 µs     |
| criar um processo que roda o `hello` do começo ao fim    | ~700–900 µs |

Uma chamada de sistema custa o mesmo que umas 300 somas em registrador. É por isso que a libc junta
o texto num buffer antes de chamar `write`: menos chamadas, menos custo. E criar um processo custa
quase um milissegundo, o mesmo que umas oito leituras aleatórias no SSD.

### Tudo é arquivo

No bash, dá para abrir uma conexão TCP como se fosse um arquivo:

```text
$ exec 3<>/dev/tcp/1.1.1.1/80
$ ls -l /proc/$$/fd/3
/proc/13824/fd/3 -> socket:[42793]
$ printf 'GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n' >&3
$ head -1 <&3
HTTP/1.1 301 Moved Permanently
```

E não para na rede. O nível da bateria deste notebook é um arquivo
(`/sys/class/power_supply/BAT*/capacity` → `93`), o estado de um processo é um arquivo
(`/proc/self/status`), e números aleatórios também (`/dev/urandom`). Nenhum deles existe em disco.

## O sistema operacional fabrica ilusões

Esta é a parte filosófica.

As três abstrações do livro são três ilusões. O processo é a ilusão de ter a CPU só para si. A
memória virtual é a ilusão de ter a memória só para si. O arquivo é a ilusão de que todo dispositivo
é uma sequência de bytes. Neste momento, este notebook mantém 346 processos e 929 threads em 12 CPUs,
e cada um deles acredita estar sozinho.

São mentiras úteis, e o que as torna úteis é que elas são **consistentes**. Um programa escrito para
a ilusão funciona sem saber o que existe por baixo. O `hello` não sabe se está escrevendo num
terminal, num arquivo ou num pipe. Ele também não sabe em que endereço físico estão as suas
variáveis, nem quantos outros programas estão rodando.

Também chama atenção que **proteção e simplicidade são o mesmo mecanismo**. A chamada de sistema que
impede um programa de mexer no hardware de outro é a mesma porta que deixa o acesso ao hardware
simples. Não dá para ter uma coisa sem a outra.

E o Unix nasceu como uma reação à complexidade. O nome é uma piada sobre o Multics. Mais de 50 anos
depois, a ideia mais influente dele ainda é a mais simples: tratar tudo como arquivo, com quatro
operações (`open`, `read`, `write`, `close`). É por isso que um pipeline como
`cat log | grep erro | wc -l` funciona: cada programa lê e escreve bytes sem saber quem está do outro
lado.

## As ilusões também vazam

O lado pragmático: todas essas abstrações têm custo e têm bordas.

- **Trocas de contexto custam.** Um servidor com milhares de threads pode passar mais tempo trocando
  entre elas do que trabalhando. Isso explica modelos como _event loops_ e `io_uring`.
- **Chamadas de sistema custam.** Ler um arquivo um byte por vez é muito mais lento que ler em blocos.
  Buffers existem para isso.
- **`fork` copia tudo**, inclusive buffers e estado que você não esperava. Esvazie os buffers antes.
- **Endereços mudam a cada execução.** Nunca dependa de um endereço de memória entre execuções.

## O que fica

1. Toda chamada a `read`, `write`, `open` e afins atravessa a fronteira com o kernel. Junte o trabalho
   em menos chamadas quando o desempenho importar.
2. Processos isolam e threads compartilham. Escolha pensando no que você quer que seja comum.
3. "Tudo é arquivo" é uma ferramenta. `/proc`, `/sys` e `/dev` mostram muito sobre o sistema sem
   nenhuma ferramenta especial.

Próxima parada: [1.8](/posts/csapp-1-8-redes/), onde a rede vira só mais um dispositivo de E/S.
