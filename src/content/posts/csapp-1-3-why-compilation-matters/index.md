---
title: 'CSAPP §1.3 — Why understand the compiler: performance, linking and security'
description: 'CSAPP series, part 3: notes and reflections on section 1.3 — three reasons to look under C, tested on my machine.'
date: 2026-10-08T19:40:00Z
lang: en
tags: [csapp, systems, c, compilers, performance]
---

> **CSAPP series** — reading notes on _Computer Systems: A Programmer's Perspective_, one section
> at a time. Every post lives under [#csapp](/tags/csapp/). Previous:
> [§1.2 — Programs that translate programs](/posts/csapp-1-2-programs-translated/).
> _[Leia em português](/posts/csapp-1-3-por-que-entender-compilacao/)._

In the [previous section](/posts/csapp-1-2-programs-translated/), `hello.c` went through four
programs on its way to becoming an executable. For a program that small, you can trust the
compilation system to produce correct and efficient code. Section 1.3 starts by admitting that, and
then explains why it is still worth understanding what goes on inside.

The section is short and made almost entirely of **questions**. I picked a few and went to test
them.

## What the book says

There are three reasons.

**1. Optimizing program performance.** You don't need to know the compiler's internals, but you do
need to understand machine code and how each C construct gets translated. The book lists questions
like: is a `switch` always faster than a chain of `if-else`? How much does a function call cost? Why
does a loop run much faster if we sum into a local variable instead of an argument passed by
reference? How can a function get faster just by rearranging the parentheses in an expression?

**2. Understanding link-time errors.** According to the authors, some of the most confusing errors
come from the linker. What does it mean when it cannot resolve a reference? What happens with two
global variables of the same name in different files? Why does the order of libraries on the command
line matter? And, scariest of all, why do some linker errors only show up at run time?

**3. Avoiding security holes.** For years, **buffer overflows** accounted for many of the security
holes in network servers. They exist because too few programmers limit the amount and form of data
they accept from untrusted sources. The first step toward secure programming is understanding how
data and control information are stored on the stack.

The answers are in chapters 3, 5, 6 and 7. But some of them can be seen today.

## Local variable or argument by reference?

Two functions that compute the same sum:

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

I summed a 128 KB array twenty thousand times, with `gcc -O1`, on an i7-1255U:

| Function    | Time    |
| ----------- | ------- |
| `sum_ref`   | ~500 ms |
| `sum_local` | ~75 ms  |

About **7x**. The reason shows up in the assembly of the inner loop:

```asm
# sum_ref                      # sum_local
.L7:                           .L11:
    movq  (%rax), %rcx             addq  (%rax), %rcx
    addq  %rcx, (%rdx)             addq  $8, %rax
    addq  $8, %rax                 cmpq  %rsi, %rax
    cmpq  %rsi, %rax               jne   .L11
    jne   .L7
```

`sum_ref` reads and writes `*dest` **in memory** on every iteration. `sum_local` keeps the sum in a
**register**. And the compiler cannot turn one into the other by itself, because it doesn't know
whether `dest` points into `a`. If it does, every write changes data the loop will read later. This
problem is called **aliasing**. I know the two pointers don't overlap; the compiler doesn't.

## Parentheses worth 2x

Now a product of `double`s, with the same math written two ways:

```c
acc = (acc * x[i]) * x[i + 1];   // ~73 ms
acc = acc * (x[i] * x[i + 1]);   // ~36 ms
```

In the first line, both multiplications depend on `acc`, so each iteration has two operations in a
row. In the second, `x[i] * x[i + 1]` doesn't depend on `acc`, and the CPU can compute that product in
parallel while the previous iteration finishes. Result: **2x**.

Why doesn't the compiler do this itself? Because floating point is **not associative**:

```text
>>> (0.1 + 0.2) + 0.3
0.6000000000000001
>>> 0.1 + (0.2 + 0.3)
0.6
```

Changing the parentheses changes the result. The compiler only reorganizes the math if you
explicitly allow it (`-ffast-math`). The parentheses you write are an order, not a suggestion.

## The linker that doesn't complain

Two globals with the same name, in different files:

```c
/* a.c */                         /* b.c */
int x;                            double x;
int main(void) {                  void f(void) { x = 0.1; }
    f();
    printf("x = %d\n", x);
}
```

With today's gcc, this is a link error (`multiple definition of 'x'`), which is good. But up to gcc 9
the default was `-fcommon`, and with it:

```text
$ gcc -fcommon a.c b.c -o ab && ./ab
x = -1717986918
```

No warning at all. The linker put the `int` and the `double` in the same place. `f` wrote `0.1`
(`0x3FB999999999999A`), and `main` read the low 4 bytes as an integer. It is
[section 1.1](/posts/csapp-1-1-bits-and-context/) all over again: the same bits, read in another
context.

Library order matters too:

```text
$ gcc -L. -lanswer m.c -o m
m.c:(.text+0x5): undefined reference to `answer'
$ gcc m.c -L. -lanswer -o m      # works
```

The linker reads files from left to right. When it goes through `libanswer.a`, there is no pending
reference to `answer` yet, so nothing from the library is used. By the time `m.c` asks for `answer`,
the library is already behind.

## Abstractions leak

This is the philosophical part.

In 2002, Joel Spolsky wrote about the _Law of Leaky Abstractions_: all non-trivial abstractions leak
to some degree. Section 1.3 is basically a list of C's leaks. The language says `*dest += a[i]` and
`acc += a[i]` are the same thing, and the machine shows they are not. Math says `(a * b) * c` equals
`a * (b * c)`, and floating point disagrees. C says each file is a separate unit, and the linker
merges two variables that never met.

The interesting part is that the compiler isn't "dumb" in these cases. It is **conservative by
obligation**: it can only apply an optimization if it can prove the behavior won't change. The
programmer knows things the compiler doesn't ("these pointers don't overlap", "I don't care about the
last bit of this `double`"). Understanding the compilation system means knowing **how to say those
things through code**: use a local variable, write `restrict`, choose the parentheses.

And there is a detail I only found later. I ran the same `sum_ref` on the efficiency cores of the
same chip, and the 7x gap **disappeared**. I come back to this in
[section 1.4](/posts/csapp-1-4-the-processor/). For now, the lesson is that even the "leak" isn't
universal: it depends on the machine.

## Takeaways

1. When a piece of code is critical, look at the assembly (`gcc -S` or
   [Compiler Explorer](https://godbolt.org)). That is where you see reads and writes you never wrote.
2. Accumulate into local variables. It is simpler to read and takes away a problem the compiler
   cannot solve by itself.
3. A link error is not a syntax error. Ask who defines the symbol, who uses it and in what order the
   files appear on the command line.
4. Measure on the machine where the code will run. Without measurement, optimization is a guess.

Next stop: [1.4](/posts/csapp-1-4-the-processor/), where `hello` finally runs and we look at the
hardware that executes it.
