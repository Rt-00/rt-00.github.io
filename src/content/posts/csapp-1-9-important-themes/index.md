---
title: 'CSAPP §1.9–1.10 — Important themes: Amdahl, parallelism and abstractions'
description: "CSAPP series, parts 9 and 10: notes and reflections on sections 1.9 and 1.10 — Amdahl's law, the three levels of parallelism, abstractions and the chapter 1 summary."
date: 2026-10-26T11:59:00Z
lang: en
tags: [csapp, systems, hardware, performance]
---

> **CSAPP series** — reading notes on _Computer Systems: A Programmer's Perspective_, one section
> at a time. Every post lives under [#csapp](/tags/csapp/). Previous:
> [§1.8 — Systems talk over networks](/posts/csapp-1-8-networks/).
> _[Leia em português](/posts/csapp-1-9-temas-importantes/)._

Chapter 1 ends with two short sections. Section 1.9 gathers the themes that show up throughout the
book, and 1.10 summarizes the chapter. This post covers both: Amdahl's law (1.9.1), concurrency and
parallelism (1.9.2), the importance of abstractions (1.9.3) and the summary (1.10).

## What the book says

The idea that opens the section is that a system is more than hardware. It is a collection of
hardware and systems software that must **cooperate** to run programs. The following chapters go
into each part, and 1.9 highlights three concepts that run through all of them.

**Amdahl's law (1.9.1).** Gene Amdahl, one of the pioneers of computing, made a simple observation:
when you speed up one part of a system, the overall gain depends on how much that part weighs and how
much faster it got. If a part takes a fraction **α** of the time and becomes **k** times faster, the
overall speedup is:

```text
S = 1 / ((1 - α) + α / k)
```

The book's example: a part that takes 60% of the time (α = 0.6) becomes 3 times faster (k = 3). The
overall speedup is 1 / (0.4 + 0.2) = **1.67×**. Far less than 3. And even if that part became
infinitely fast, the maximum would be 1 / 0.4 = **2.5×**. The lesson: to speed up a system a lot, you
have to speed up a very large fraction of it.

**Concurrency and parallelism (1.9.2).** The book separates the two terms. **Concurrency** is the
general concept of several activities happening at the same time. **Parallelism** is using
concurrency to make a system run faster. And it shows up at three levels:

1. **Threads.** Concurrency used to be simulated: a single processor switched quickly between
   processes. Today a chip has several cores (_multi-core_), each with its own L1 and L2 caches,
   sharing the L3. On top of that, **hyperthreading** lets a single core run two threads: it has two
   copies of the PC and the registers, but only one copy of the units that do the arithmetic. When one
   thread is waiting, the other uses those units.
2. **Instructions.** Early processors, like the 8086, took 3 to 10 cycles per instruction. Current
   ones execute 2 to 4 instructions per cycle, even though each instruction takes 20 cycles or more
   from start to finish. That comes from _pipelining_ and from **superscalar** processors, which
   execute several independent instructions at the same time. Chapter 5 teaches how to write code
   that takes advantage of this.
3. **SIMD** (_single instruction, multiple data_). A single instruction performs the same operation on
   several pieces of data: for example, adding 8 pairs of floating-point numbers at once. It is used
   mostly for images, sound and video.

**The importance of abstractions (1.9.3).** Good abstractions are one of the most important concepts
in computing. A good example is the **instruction set architecture** (ISA). It describes a processor
that executes one instruction at a time, in order. The real hardware is far more complex and
executes several instructions in parallel, but always in a way that gives the same result as the
simple model. That way, the same machine code runs on very different processors, from the cheapest
to the most expensive. On the operating system side, we have already seen three abstractions: files,
virtual memory and processes. The book adds a fourth, the **virtual machine**: an abstraction of the
whole computer, including the operating system, the processor and the programs. IBM introduced the
idea in the 1960s.

**The summary (1.10).** A computer system is hardware and systems software cooperating to run
programs. Information is bits interpreted according to context. Programs are translated by other
programs, from ASCII text into binary executables. The processor reads and interprets instructions
stored in memory. Since the computer spends most of its time copying data, storage devices form a
hierarchy of caches. The operating system kernel is the intermediary between applications and
hardware, with three abstractions. And networks let machines exchange data.

## Checking it myself

Every measurement is from this laptop, an Intel Core i7-1255U. It has 12 threads, but they are not
12 equal cores: there are 2 fast cores (P-cores) with hyperthreading, giving 4 threads, plus 8
smaller, more efficient cores (E-cores). `lscpu -e` shows which is which:

```text
$ lscpu -e=CPU,CORE,MAXMHZ
CPU CORE    MAXMHZ
  0    0 4700.0000
  1    0 4700.0000
  2    1 4700.0000
  3    1 4700.0000
  4    2 3500.0000
...
 11    9 3500.0000
```

CPUs 0 and 1 are the same physical core (CORE 0), and so are 2 and 3. From 4 to 11, each CPU is an
E-core. This will matter, because `taskset` lets you choose which CPUs a program runs on.

### How I measured

The programs are in C, compiled with GCC 16.2. They all measure time the same way, with a monotonic
clock read before and after the part that matters:

```c
static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}
```

The laptop was plugged in, but on the `powersave` governor, so the frequency varies and the numbers
move by a few percent from one run to the next. I ran each test at least twice and only used results
that repeated. The goal isn't exact numbers, it's seeing the proportions.

### Amdahl on my machine

To test Amdahl's law, I needed a program where I could control α. The work is a chain of arithmetic in
which each step depends on the previous one. That way the compiler can't skip or simplify anything:

```c
static double work(long n, double x) {
    for (long i = 0; i < n; i++)
        x = x * 1.0000001 + 1e-9;
    return x;
}
```

The parallel part splits that work into 4,000 chunks. Each thread takes the next free chunk from an
atomic counter until they run out:

```c
static atomic_int next_chunk;

static void *worker(void *arg) {
    double s = 0;
    int c;
    while ((c = atomic_fetch_add(&next_chunk, 1)) < CHUNKS)
        s += work(CHUNK_ITERS, c);
    *(double *)arg = s; /* use the result so the compiler doesn't throw the work away */
    return NULL;
}
```

Splitting into small chunks matters on a hybrid CPU. If each thread got a fixed slice, the threads on
the P-cores would finish first and sit waiting for the ones on the E-cores. With the counter, whoever
is faster simply takes more chunks.

`main` first runs the serial part, on a single thread, sized to be 10% of the total. Then it creates
the threads, waits for all of them with `pthread_join` and prints the times:

```text
$ gcc -O2 -pthread amdahl.c -o amdahl
$ for t in 1 2 4 8 12; do ./amdahl $t 0.1; done
T= 1 serial=0.149s parallel=1.510s total=1.659s
T= 2 serial=0.164s parallel=0.767s total=0.931s
T= 4 serial=0.145s parallel=0.433s total=0.578s
T= 8 serial=0.149s parallel=0.240s total=0.389s
T=12 serial=0.146s parallel=0.170s total=0.316s
```

The measured speedup is the time with 1 thread divided by the time with T threads. The Amdahl column
is the formula with α = 0.9 and k = T:

| Threads | Time   | Measured speedup | Amdahl (α = 0.9) |
| ------- | ------ | ---------------- | ---------------- |
| 1       | 1.66 s | 1.0×             | 1.0×             |
| 2       | 0.93 s | 1.8×             | 1.8×             |
| 4       | 0.58 s | 2.9×             | 3.1×             |
| 8       | 0.39 s | 4.3×             | 4.7×             |
| 12      | 0.32 s | 5.2×             | 5.7×             |
| ∞       | —      | —                | 10×              |

The formula is pretty accurate. The serial part took 0.15 s in every row, and with 12 threads it is
already almost half of the total time. From here on, more threads barely help: not even infinite
threads would make the program more than 10 times faster.

The measured numbers are a bit below the formula because of the machine. Running with no serial part
at all (`./amdahl 12`), 12 threads gave 8.7×, not 12×, because the E-cores are slower and two threads
on the same P-core share the core.

### Hyperthreading: two threads, one core

To see hyperthreading at work, I wrote two loops with the same number of additions, one billion. In
the first, each addition depends on the previous one. In the second, the additions are split into
eight independent chains:

```c
/* one chain: each addition waits for the previous one */
double x = 1;
for (long i = 0; i < R; i++)
    x = x + d;

/* eight independent chains */
double s0 = 0, s1 = 1, s2 = 2, s3 = 3, s4 = 4, s5 = 5, s6 = 6, s7 = 7;
for (long i = 0; i < R / 8; i++) {
    s0 += d; s1 += d; s2 += d; s3 += d;
    s4 += d; s5 += d; s6 += d; s7 += d;
}
```

The value of `d` comes from the command line, so the compiler can't compute anything before the
program runs. And the first version played a trick on me: all eight accumulators started at zero.
Since the eight computations were identical, the compiler did just one and reused the result, and the
loop "added" a billion numbers in 0.06 s. Starting each accumulator at a different value fixed it. To
be sure, I checked with `objdump -d` that the loop had all eight `addsd` instructions, each on a
different register.

I compiled without vectorization, so the compiler wouldn't turn the eight chains into SIMD (that's
for the next test). Each thread runs the whole loop, and `taskset` chooses where:

```text
$ gcc -O2 -fno-tree-vectorize -fno-tree-slp-vectorize -pthread ht.c -o ht
$ taskset -c 0 ./ht 1 ...     # 1 thread
$ taskset -c 0,1 ./ht 2 ...   # 2 threads on the same core (CPUs 0 and 1)
$ taskset -c 0,2 ./ht 2 ...   # 2 threads on different cores (CPUs 0 and 2)
```

Since each thread does the same work, ideally two threads take the same time as one:

| Loop                              | 1 thread | 2 threads, same core | 2 threads, different cores |
| --------------------------------- | -------- | -------------------- | -------------------------- |
| one chain of dependent additions  | 0.51 s   | 0.50 s               | 0.55 s                     |
| eight independent addition chains | 0.12 s   | 0.25 s               | 0.14 s                     |

In the first loop, each addition waits for the previous one to finish. The adder sits idle most of the
time, and the second thread uses that idle time: two threads on the same core came for free. In the
second, the additions are independent and a single thread already keeps every adder busy. The second
thread has nowhere to run, and the time doubles.

In other words: hyperthreading doesn't double the core, it uses what is left over. The more efficient
the code, the less it helps.

### Instruction-level parallelism and SIMD

Now on a single thread. The function adds up 4,096 `double` values, first with one accumulator, then
splitting the sum across several:

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

The 8-accumulator version follows the same pattern. The 4,096 `double` values take 32 KiB and fit in
the core's L1 cache, so the test measures the processor, not memory
([section 1.5](/posts/csapp-1-5-caches-matter/) shows what happens when the data doesn't fit).

A single sum is too fast for the clock, so the program calls each function 200,000 times in a row and
divides the time by the number of elements added. It repeats that five times and keeps the smallest
time, which is the one with the least interference from the rest of the system. The functions are
marked `__attribute__((noinline))` and the result goes into a `volatile` variable, so the compiler
can't merge or drop the calls.

I compiled twice. The first three rows of the table come from a binary without vectorization,
because at `-O2` GCC already uses a bit of SIMD and would mix the two effects. The last one comes from
a binary built with `-O3 -march=native`, which lets the compiler use every instruction this processor
has, AVX2 included. Everything ran pinned to CPU 2, a P-core:

```text
$ gcc -O2 -fno-tree-vectorize -fno-tree-slp-vectorize ilp.c -o ilp_scalar
$ gcc -O3 -march=native ilp.c -o ilp_simd
$ taskset -c 2 ./ilp_scalar
1 acc: 0.450 ns/elem
4 acc: 0.116 ns/elem
8 acc: 0.115 ns/elem
$ taskset -c 2 ./ilp_simd
...
8 acc: 0.057 ns/elem
```

| Version                                    | ns per element | Gain |
| ------------------------------------------ | -------------- | ---- |
| 1 accumulator                              | 0.45           | 1×   |
| 4 accumulators                             | 0.116          | 3.9× |
| 8 accumulators                             | 0.115          | 3.9× |
| 8 accumulators with AVX2 (`-march=native`) | 0.057          | 7.9× |

With one accumulator, each addition depends on the previous one. At 0.45 ns per element, around
4.7 GHz, that is about 2 cycles per addition: the time a floating-point addition takes from start to
finish. The processor sits waiting.

With 4 accumulators, the additions become 4 independent chains, and the superscalar processor runs
several at the same time. It gets 3.9 times faster, with the same instructions. With 8 accumulators,
nothing improves: the core has two adders, and they are already busy.

The last step is SIMD. To see what the compiler did, just look for the instructions in the binary:

```text
$ objdump -d ilp_simd | grep vaddpd
    14c3:	vaddpd (%rdi),%ymm1,%ymm1
    14c7:	vaddpd 0x20(%rdi),%ymm2,%ymm2
```

`vaddpd` adds 4 `double` values at once, using the 256-bit `ymm` registers. That is 7.9× over the
first version, without a single extra thread.

A curious detail: the compiler doesn't switch from one accumulator to several on its own.
Floating-point addition is not associative (`(a + b) + c` can differ from `a + (b + c)`), and changing
the order can change the result. Only when compiled with `-ffast-math`, which grants permission for
that, did the one-accumulator version drop to 0.11 ns.

### The same function on three processors

And the ISA abstraction. Unlike GCC, Clang is a cross-compiler by default: the same binary generates
code for several architectures, chosen with `--target`. With `-S`, it stops at assembly, so no
libraries for the other architecture need to be installed:

```c
long add(long a, long b) {
    return a + b;
}
```

```text
$ clang --target=x86_64-linux-gnu -O2 -S -o - add.c
$ clang --target=aarch64-linux-gnu -O2 -S -o - add.c
$ clang --target=riscv64-linux-gnu -O2 -S -o - add.c
```

Leaving out the assembler directives (the lines starting with `.`), this is what remains:

```text
x86-64:   leaq (%rdi,%rsi), %rax
          retq
AArch64:  add  x0, x1, x0
          ret
RISC-V:   add  a0, a0, a1
          ret
```

C is an abstraction above all three ISAs. Each ISA, in turn, is an abstraction above many different
processors. My Intel and an AMD both understand the same `leaq`, even though they are completely
different machines on the inside.

## The chapter's numbers

This is the philosophical part.

Amdahl's law looks like a performance formula, but it says something more general: **whatever you
don't improve ends up dominating**. In my test, the serial part started as 10% of the time and ended
as almost half. It didn't get slower. Everything else got faster.

And the three levels of parallelism follow the same pattern. At each one, the hardware offers extra
capacity: cores, adders, vectors. But only a program with independent work can use that capacity. A
single accumulator, a large serial part, a chain of dependencies: at any level, it is the dependency
between steps that limits parallelism.

Abstractions have the opposite effect: they hide that complexity. The ISA says "one instruction at a
time, in order", and the processor executes dozens out of order, in parallel. The operating system
says "you are alone on the machine", and it runs hundreds of processes at the same time. The rule is
that the result must be the same as the simple model's. That is what lets us write programs without
thinking about any of this. And, as the tests above show, performance is exactly what that rule
doesn't guarantee.

## What changes day to day

The pragmatic side, and a recap of the chapter.

- **Measure before optimizing, and measure the fraction.** A 10× improvement in a part that takes 5%
  of the time gains less than 5%. A profiler shows where the big α is.
- **More threads aren't free.** The serial part, synchronization and uneven cores limit the gain. On
  my laptop, "12 threads" are worth about 9 cores.
- **Dependencies cost more than instructions.** Breaking a long chain into several independent ones
  can give 4× without changing the algorithm.
- **Let the compiler do its job.** Flags like `-O3 -march=native` turn on SIMD, but the code has to
  allow it: simple loops, with no dependencies between iterations.

All of chapter 1 was a guided tour of `hello`: from the bytes in the file
([1.1](/posts/csapp-1-1-bits-and-context/)) to the translation
([1.2](/posts/csapp-1-2-programs-translated/)), from the processor
([1.4](/posts/csapp-1-4-the-processor/)) to the memory hierarchy
([1.6](/posts/csapp-1-6-memory-hierarchy/)), from the operating system
([1.7](/posts/csapp-1-7-the-operating-system/)) to the network ([1.8](/posts/csapp-1-8-networks/)).
Each of the following chapters digs deeper into one of these stops.

## Takeaways

1. Speedup = 1 / ((1 − α) + α / k). The ceiling is 1 / (1 − α), and you hit it fast.
2. Parallelism exists at three levels: threads, instructions and SIMD. At all of them, the limit is
   the work that doesn't depend on other work.
3. Abstractions guarantee that the result is the same, not that the time is the same. To understand
   performance you have to look beneath them, and that is what the rest of the book does.

Next stop: chapter 2, on how bits represent numbers, and why `(a + b) + c` isn't always equal to
`a + (b + c)`.
