---
title: 'CSAPP §1.9–1.10 — Temas importantes: Amdahl, paralelismo e abstrações'
description: 'Série CSAPP, partes 9 e 10: notas e reflexões sobre as seções 1.9 e 1.10 — a lei de Amdahl, os três níveis de paralelismo, as abstrações e o resumo do capítulo 1.'
date: 2026-10-26T12:00:00Z
lang: pt
tags: [csapp, systems, hardware, performance]
---

> **Série CSAPP** — notas de leitura de _Computer Systems: A Programmer's Perspective_, uma seção
> por vez. Todos os posts ficam em [#csapp](/tags/csapp/). Anterior:
> [§1.8 — Sistemas conversam pela rede](/posts/csapp-1-8-redes/).
> _[Read in English](/posts/csapp-1-9-important-themes/)._

O capítulo 1 termina com duas seções curtas. A 1.9 junta os temas que vão aparecer no livro inteiro,
e a 1.10 resume o capítulo. Este post cobre as duas: a lei de Amdahl (1.9.1), concorrência e
paralelismo (1.9.2), a importância das abstrações (1.9.3) e o resumo (1.10).

## O que o livro diz

A ideia que abre a seção é que um sistema é mais do que hardware. É um conjunto de hardware e
software de sistema que precisam **cooperar** para rodar programas. Os capítulos seguintes detalham
cada parte, e a 1.9 destaca três conceitos que atravessam todas elas.

**A lei de Amdahl (1.9.1).** Gene Amdahl, um dos pioneiros da computação, observou algo simples:
quando você acelera uma parte do sistema, o ganho total depende de quanto essa parte pesa e de quanto
ela ficou mais rápida. Se uma parte ocupa uma fração **α** do tempo e fica **k** vezes mais rápida, o
ganho total (_speedup_) é:

```text
S = 1 / ((1 - α) + α / k)
```

O exemplo do livro: uma parte que ocupa 60% do tempo (α = 0,6) fica 3 vezes mais rápida (k = 3). O
ganho total é 1 / (0,4 + 0,2) = **1,67×**. Bem menos que 3. E mesmo que essa parte ficasse
infinitamente rápida, o máximo seria 1 / 0,4 = **2,5×**. A lição: para acelerar muito um sistema, é
preciso acelerar uma fração muito grande dele.

**Concorrência e paralelismo (1.9.2).** O livro separa os dois termos. **Concorrência** é o conceito
geral de várias atividades acontecendo ao mesmo tempo. **Paralelismo** é usar a concorrência para
deixar o sistema mais rápido. E ele aparece em três níveis:

1. **Threads.** Antes, a concorrência era simulada: um único processador alternava rápido entre
   processos. Hoje, um chip tem vários núcleos (_multi-core_), cada um com seus caches L1 e L2,
   compartilhando a L3. Além disso, o **hyperthreading** deixa um mesmo núcleo rodar duas threads:
   ele tem duas cópias do PC e dos registradores, mas uma cópia só das unidades que fazem as contas.
   Quando uma thread fica esperando, a outra usa essas unidades.
2. **Instruções.** Os primeiros processadores, como o 8086, levavam de 3 a 10 ciclos por instrução.
   Os atuais executam de 2 a 4 instruções por ciclo, mesmo que cada instrução leve 20 ciclos ou mais
   do começo ao fim. Isso vem do _pipelining_ e dos processadores **superescalares**, que executam
   várias instruções independentes ao mesmo tempo. O capítulo 5 ensina a escrever código que
   aproveita isso.
3. **SIMD** (_single instruction, multiple data_). Uma única instrução faz a mesma operação em vários
   dados: por exemplo, somar 8 pares de números de ponto flutuante de uma vez. É usado sobretudo em
   imagem, som e vídeo.

**A importância das abstrações (1.9.3).** Boas abstrações são um dos conceitos mais importantes da
computação. Um bom exemplo é a **arquitetura do conjunto de instruções** (ISA). Ela descreve um
processador que executa uma instrução por vez, em ordem. O hardware real é muito mais complexo e
executa várias instruções em paralelo, mas sempre de um jeito que dá o mesmo resultado do modelo
simples. Assim, o mesmo código de máquina roda em processadores muito diferentes, dos mais baratos aos
mais caros. Do lado do sistema operacional, já vimos três abstrações: arquivos, memória virtual e
processos. O livro acrescenta uma quarta, a **máquina virtual**: a abstração do computador inteiro,
com sistema operacional, processador e programas. A IBM introduziu a ideia nos anos 1960.

**O resumo (1.10).** Um sistema de computação é hardware e software de sistema cooperando para rodar
programas. A informação são bits interpretados conforme o contexto. Programas são traduzidos por
outros programas, de texto ASCII para executáveis binários. O processador lê e interpreta instruções
guardadas na memória. Como o computador passa a maior parte do tempo copiando dados, os dispositivos
de armazenamento formam uma hierarquia de caches. O kernel do sistema operacional é o intermediário
entre as aplicações e o hardware, com três abstrações. E a rede permite trocar dados entre máquinas.

## Conferindo na prática

Todas as medições são deste notebook, um Intel Core i7-1255U. Ele tem 12 threads, mas não são 12
núcleos iguais: são 2 núcleos rápidos (P-cores) com hyperthreading, que dão 4 threads, mais 8 núcleos
menores e mais econômicos (E-cores).

### Amdahl na minha máquina

Escrevi um programa com uma parte serial, que só roda numa thread, e uma parte paralela, dividida
entre várias threads. A parte serial é 10% do tempo com uma thread, então α = 0,9:

| Threads | Tempo  | Speedup medido | Amdahl (α = 0,9) |
| ------- | ------ | -------------- | ---------------- |
| 1       | 1,66 s | 1,0×           | 1,0×             |
| 2       | 0,93 s | 1,8×           | 1,8×             |
| 4       | 0,58 s | 2,9×           | 3,1×             |
| 8       | 0,39 s | 4,3×           | 4,7×             |
| 12      | 0,32 s | 5,2×           | 5,7×             |
| ∞       | —      | —              | 10×              |

A fórmula acerta bem. A parte serial levou 0,15 s em todas as linhas, e com 12 threads ela já é quase
metade do tempo total. Daqui para frente, mais threads quase não ajudam: nem com infinitas threads o
programa ficaria mais de 10 vezes mais rápido.

O medido fica um pouco abaixo da fórmula por causa da máquina. Sem nenhuma parte serial, 12 threads
deram 8,7×, e não 12×, porque os E-cores são mais lentos e duas threads no mesmo P-core dividem o
núcleo.

### Hyperthreading: duas threads, um núcleo

Para ver o hyperthreading, rodei dois tipos de laço. Cada thread faz o mesmo trabalho, então o ideal
é que duas threads levem o mesmo tempo que uma:

| Laço                                | 1 thread | 2 threads, mesmo núcleo | 2 threads, núcleos diferentes |
| ----------------------------------- | -------- | ----------------------- | ----------------------------- |
| uma cadeia de somas dependentes     | 0,51 s   | 0,50 s                  | 0,55 s                        |
| oito cadeias de somas independentes | 0,12 s   | 0,25 s                  | 0,14 s                        |

No primeiro laço, cada soma espera a anterior terminar. A unidade de soma passa a maior parte do tempo
parada, e a segunda thread usa esse tempo livre: duas threads no mesmo núcleo saíram de graça. No
segundo, as somas são independentes e uma thread sozinha já ocupa todas as unidades de soma. A segunda
thread não tem onde rodar, e o tempo dobra.

Ou seja: o hyperthreading não dobra o núcleo, ele aproveita o que sobra. Quanto mais eficiente o
código, menos ele ajuda.

### Paralelismo de instruções e SIMD

Agora numa thread só. A função soma 4.096 números `double`, primeiro com um acumulador, depois
dividindo a soma entre vários:

```c
double sum1(const double *x, int n) {
    double s = 0;
    for (int i = 0; i < n; i++)
        s += x[i];
    return s;
}

double sum4(const double *x, int n) {
    double s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    for (int i = 0; i < n; i += 4) {
        s0 += x[i];
        s1 += x[i + 1];
        s2 += x[i + 2];
        s3 += x[i + 3];
    }
    return (s0 + s1) + (s2 + s3);
}
```

| Versão                                    | ns por elemento | Ganho |
| ----------------------------------------- | --------------- | ----- |
| 1 acumulador                              | 0,45            | 1×    |
| 4 acumuladores                            | 0,116           | 3,9×  |
| 8 acumuladores                            | 0,115           | 3,9×  |
| 8 acumuladores com AVX2 (`-march=native`) | 0,057           | 7,9×  |

Com um acumulador, cada soma depende da anterior. A 0,45 ns por elemento, perto de 4,7 GHz, são uns 2
ciclos por soma: o tempo de uma soma de ponto flutuante do começo ao fim. O processador fica
esperando.

Com 4 acumuladores, as somas viram 4 cadeias independentes, e o processador superescalar executa
várias ao mesmo tempo. Fica 3,9 vezes mais rápido, com as mesmas instruções. Com 8 acumuladores, não
melhora mais nada: o núcleo tem duas unidades de soma, e elas já estão ocupadas.

O último passo é SIMD. Deixando o compilador usar AVX2, ele trocou as somas por `vaddpd`, uma
instrução que soma 4 `double` de uma vez. São 7,9× sobre a primeira versão, sem nenhuma thread.

Um detalhe curioso: o compilador não faz a troca de um para vários acumuladores sozinho. Somas de
ponto flutuante não são associativas (`(a + b) + c` pode dar diferente de `a + (b + c)`), e mudar a
ordem pode mudar o resultado. Só com `-ffast-math`, que dá permissão para isso, a versão com um
acumulador caiu para 0,11 ns.

### A mesma função em três processadores

E a abstração da ISA. A mesma função em C, compilada para três arquiteturas diferentes:

```c
long add(long a, long b) {
    return a + b;
}
```

```text
x86-64:   leaq (%rdi,%rsi), %rax
          retq
AArch64:  add  x0, x1, x0
          ret
RISC-V:   add  a0, a0, a1
          ret
```

O C é uma abstração acima das três ISAs. Cada ISA, por sua vez, é uma abstração acima de muitos
processadores diferentes. O meu Intel e um AMD entendem o mesmo `leaq`, mesmo sendo máquinas
completamente diferentes por dentro.

## Os números do capítulo

Esta é a parte filosófica.

A lei de Amdahl parece uma fórmula de desempenho, mas ela diz algo mais geral: **o que você não
melhora acaba dominando**. No meu teste, a parte serial começou como 10% do tempo e terminou como
quase metade. Ela não ficou mais lenta. Todo o resto é que ficou mais rápido.

E os três níveis de paralelismo seguem o mesmo padrão. Em cada um, o hardware oferece capacidade
extra: núcleos, unidades de soma, vetores. Mas só um programa que tem trabalho independente consegue
usar essa capacidade. Um acumulador só, uma parte serial grande, uma cadeia de dependências: em
qualquer nível, é a dependência entre os passos que limita o paralelismo.

As abstrações têm o efeito oposto: escondem essa complexidade. A ISA diz "uma instrução por vez, em
ordem", e o processador executa dezenas fora de ordem, em paralelo. O sistema operacional diz "você
está sozinho na máquina", e roda centenas de processos ao mesmo tempo. A regra é que o resultado tem que ser o mesmo
do modelo simples. É isso que permite escrever programas sem pensar em nada disso. E, como os testes
acima mostram, o desempenho é justamente o que essa regra não garante.

## O que muda no dia a dia

O lado pragmático, e um balanço do capítulo.

- **Meça antes de otimizar, e meça a fração.** Uma melhoria de 10× numa parte que pesa 5% do tempo
  rende menos de 5%. Um profiler mostra onde está o α grande.
- **Mais threads não é de graça.** A parte serial, a sincronização e os núcleos desiguais limitam o
  ganho. No meu notebook, "12 threads" valem uns 9 núcleos.
- **Dependências custam mais que instruções.** Quebrar uma cadeia longa em várias independentes pode
  dar 4× sem mudar o algoritmo.
- **Deixe o compilador trabalhar.** Flags como `-O3 -march=native` ligam o SIMD, mas o código precisa
  permitir: laços simples, sem dependências entre as iterações.

O capítulo 1 todo foi uma visita guiada ao `hello`: dos bytes no arquivo
([1.1](/posts/csapp-1-1-bits-e-contexto/)) à tradução ([1.2](/posts/csapp-1-2-programas-traduzidos/)),
do processador ([1.4](/posts/csapp-1-4-o-processador/)) à hierarquia de memória
([1.6](/posts/csapp-1-6-hierarquia-de-memoria/)), do sistema operacional
([1.7](/posts/csapp-1-7-o-sistema-operacional/)) à rede ([1.8](/posts/csapp-1-8-redes/)). Cada
capítulo seguinte aprofunda uma dessas paradas.

## O que fica

1. Speedup = 1 / ((1 − α) + α / k). O teto é 1 / (1 − α), e ele chega rápido.
2. Paralelismo existe em três níveis: threads, instruções e SIMD. Em todos, o limite é o trabalho que
   não depende de outro.
3. Abstrações garantem que o resultado é o mesmo, não que o tempo é o mesmo. Para entender o
   desempenho, é preciso olhar por baixo delas, e é isso que o resto do livro faz.

Próxima parada: capítulo 2, sobre como bits representam números, e por que `(a + b) + c` nem sempre é
igual a `a + (b + c)`.
