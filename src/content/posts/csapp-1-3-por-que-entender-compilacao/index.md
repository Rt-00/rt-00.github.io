---
title: 'CSAPP §1.3 — Por que entender o compilador: desempenho, linker e segurança'
description: 'Série CSAPP, parte 3: notas e reflexões sobre a seção 1.3 — três motivos para olhar embaixo do C, testados na minha máquina.'
date: 2026-10-08T19:40:00Z
lang: pt
tags: [csapp, systems, c, compilers, performance]
---

> **Série CSAPP** — notas de leitura de _Computer Systems: A Programmer's Perspective_, uma seção
> por vez. Todos os posts ficam em [#csapp](/tags/csapp/). Anterior:
> [§1.2 — Programas que traduzem programas](/posts/csapp-1-2-programas-traduzidos/).
> _[Read in English](/posts/csapp-1-3-why-compilation-matters/)._

Na [seção anterior](/posts/csapp-1-2-programas-traduzidos/), o `hello.c` passou por quatro programas
até virar um executável. Para um programa desse tamanho, dá para confiar que o sistema de compilação
vai gerar código correto e eficiente. A seção 1.3 começa admitindo isso e, em seguida, explica por que
mesmo assim vale a pena entender o que acontece ali dentro.

A seção é curta e quase toda feita de **perguntas**. Peguei algumas delas e fui testar.

## O que o livro diz

São três motivos.

**1. Otimizar o desempenho.** Não é preciso conhecer o compilador por dentro, mas é preciso entender
o código de máquina e como cada construção de C é traduzida. O livro lista perguntas como: um `switch`
é sempre mais rápido que uma cadeia de `if-else`? Quanto custa uma chamada de função? Por que um loop
fica muito mais rápido se a soma for feita numa variável local em vez de num argumento passado por
referência? Como uma função pode ficar mais rápida só rearranjando os parênteses de uma expressão?

**2. Entender erros de ligação.** Segundo os autores, alguns dos erros mais confusos vêm do linker.
O que significa "não foi possível resolver uma referência"? O que acontece com duas variáveis globais
de mesmo nome em arquivos diferentes? Por que a ordem das bibliotecas na linha de comando importa? E,
o mais assustador, por que alguns erros de ligação só aparecem em tempo de execução?

**3. Evitar falhas de segurança.** Durante anos, **buffer overflows** foram responsáveis por boa
parte das falhas em servidores de rede. Elas existem porque pouca gente limita a quantidade e a forma
dos dados que aceita de fontes não confiáveis. O primeiro passo para programar com segurança é
entender como dados e informação de controle ficam guardados na pilha.

As respostas ficam para os capítulos 3, 5, 6 e 7. Mas algumas dá para ver hoje.

## Variável local ou argumento por referência?

Duas funções que fazem a mesma soma:

```c
void sum_ref(const long *a, long n, long *dest) {
    *dest = 0;
    for (long i = 0; i < n; i++)
        *dest += a[i];
}

void sum_local(const long *a, long n, long *dest) {
    long acc = 0;
    for (long i = 0; i < n; i++)
        acc += a[i];
    *dest = acc;
}
```

Somei um array de 128 KB vinte mil vezes, com `gcc -O1`, num i7-1255U:

| Função      | Tempo   |
| ----------- | ------- |
| `sum_ref`   | ~500 ms |
| `sum_local` | ~75 ms  |

Cerca de **7x**. O motivo aparece no assembly do loop interno:

```asm
# sum_ref                      # sum_local
.L7:                           .L11:
    movq  (%rax), %rcx             addq  (%rax), %rcx
    addq  %rcx, (%rdx)             addq  $8, %rax
    addq  $8, %rax                 cmpq  %rsi, %rax
    cmpq  %rsi, %rax               jne   .L11
    jne   .L7
```

O `sum_ref` lê e escreve `*dest` **na memória** a cada volta. O `sum_local` mantém a soma num
**registrador**. E o compilador não pode transformar um no outro sozinho, porque não sabe se `dest`
aponta para dentro de `a`. Se apontar, cada escrita muda os dados que o loop vai ler depois. Esse
problema se chama **aliasing**. Eu sei que os dois ponteiros não se sobrepõem; o compilador não sabe.

## Parênteses que valem 2x

Agora um produto de `double`, com a mesma conta escrita de dois jeitos:

```c
acc = (acc * x[i]) * x[i + 1];   // ~73 ms
acc = acc * (x[i] * x[i + 1]);   // ~36 ms
```

Na primeira linha, as duas multiplicações dependem de `acc`, então cada iteração tem duas operações
em fila. Na segunda, `x[i] * x[i + 1]` não depende de `acc`, e a CPU consegue calcular esse produto
em paralelo enquanto a iteração anterior termina. Resultado: **2x**.

Por que o compilador não faz isso sozinho? Porque ponto flutuante **não é associativo**:

```text
>>> (0.1 + 0.2) + 0.3
0.6000000000000001
>>> 0.1 + (0.2 + 0.3)
0.6
```

Mudar os parênteses muda o resultado. O compilador só reorganiza a conta se você deixar
explicitamente (`-ffast-math`). Os parênteses que você escreve são uma ordem, não uma sugestão.

## O linker que não reclama

Duas globais com o mesmo nome, em arquivos diferentes:

```c
/* a.c */                         /* b.c */
int x;                            double x;
int main(void) {                  void f(void) { x = 0.1; }
    f();
    printf("x = %d\n", x);
}
```

Com o gcc atual, isso dá erro de ligação (`multiple definition of 'x'`), o que é bom. Mas até o
gcc 9 o padrão era `-fcommon`, e com ele:

```text
$ gcc -fcommon a.c b.c -o ab && ./ab
x = -1717986918
```

Sem nenhum aviso. O linker juntou o `int` e o `double` no mesmo lugar. O `f` gravou `0.1`
(`0x3FB999999999999A`), e a `main` leu os 4 bytes de baixo como inteiro. É a
[seção 1.1](/posts/csapp-1-1-bits-e-contexto/) de novo: os mesmos bits, lidos em outro contexto.

A ordem das bibliotecas também importa:

```text
$ gcc -L. -lanswer m.c -o m
m.c:(.text+0x5): undefined reference to `answer'
$ gcc m.c -L. -lanswer -o m      # funciona
```

O linker lê os arquivos da esquerda para a direita. Quando ele passa pela `libanswer.a`, ainda não
existe nenhuma referência pendente a `answer`, então nada da biblioteca é aproveitado. Quando o `m.c`
pede `answer`, a biblioteca já ficou para trás.

## Abstrações vazam

Esta é a parte filosófica.

Em 2002, Joel Spolsky escreveu sobre a _Law of Leaky Abstractions_: toda abstração não trivial vaza
em algum grau. A seção 1.3 é praticamente uma lista de vazamentos do C. A linguagem diz que `*dest +=
a[i]` e `acc += a[i]` são a mesma coisa, e a máquina mostra que não são. A matemática diz que
`(a * b) * c` é igual a `a * (b * c)`, e o ponto flutuante discorda. O C diz que cada arquivo é uma
unidade separada, e o linker junta duas variáveis que nunca se viram.

O mais interessante é que o compilador não é "burro" nesses casos. Ele é **conservador por
obrigação**: só pode fazer uma otimização se conseguir provar que ela não muda o comportamento. Quem
programa sabe coisas que o compilador não sabe ("esses ponteiros não se sobrepõem", "não me importo
com o último bit desse `double`"). Entender o sistema de compilação é saber **como dizer essas coisas
pelo código**: usar uma variável local, escrever `restrict`, escolher os parênteses.

E tem um detalhe que só descobri depois. Rodei o mesmo `sum_ref` nos núcleos de eficiência do mesmo
chip, e a diferença de 7x **sumiu**. Volto a esse resultado na
[seção 1.4](/posts/csapp-1-4-o-processador/). Por enquanto, a lição é que nem o "vazamento" é
universal: depende da máquina.

## O que fica

1. Quando um trecho é crítico, olhe o assembly (`gcc -S` ou o
   [Compiler Explorer](https://godbolt.org)). É lá que aparecem leituras e escritas que você não
   escreveu.
2. Acumule em variáveis locais. É mais simples de ler e tira do compilador um problema que ele não
   consegue resolver sozinho.
3. Erro de ligação não é erro de sintaxe. Pergunte quem define o símbolo, quem usa e em que ordem os
   arquivos aparecem no comando.
4. Meça na máquina onde o código vai rodar. Sem medição, otimização é palpite.

Próxima parada: [1.4](/posts/csapp-1-4-o-processador/), onde o `hello` finalmente roda e a gente
olha para o hardware que o executa.
