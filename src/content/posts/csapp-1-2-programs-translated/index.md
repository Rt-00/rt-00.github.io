---
title: 'CSAPP §1.2 — Programs that translate programs: from hello.c to an executable'
description: 'CSAPP series, part 2: notes and reflections on section 1.2 — the four phases of compilation, and what changes when your code goes through them.'
date: 2026-10-07T18:11:00Z
lang: en
tags: [csapp, systems, c, compilers]
---

> **CSAPP series** — reading notes on _Computer Systems: A Programmer's Perspective_, one section
> at a time. Every post lives under [#csapp](/tags/csapp/). Previous:
> [§1.1 — Bits + context](/posts/csapp-1-1-bits-and-context/).
> _[Leia em português](/posts/csapp-1-2-programas-traduzidos/)._

In the [previous section](/posts/csapp-1-1-bits-and-context/), `hello.c` was just a sequence of
ASCII bytes in a file. It is written in C because, in that form, a person can read it and understand
what it does. The CPU does not understand C. To run, the program has to be **translated by other
programs** into machine instructions, packaged in an **executable**.

Section 1.2 is about that translation. It fits in one command:

```text
$ gcc -o hello hello.c
```

## What the book says

`gcc` is a **compiler driver**: it does not do the work by itself, it calls four programs in a row.
Together they make up the **compilation system**:

![The compilation pipeline: hello.c goes through cpp, cc1, as and ld (which also reads printf.o from libc) to become the hello executable](./pipeline.svg)

1. **Preprocessing (`cpp`).** Handles the lines that start with `#`. `#include <stdio.h>` is
   replaced by the contents of `stdio.h`. The result, `hello.i`, is still a C program.
2. **Compilation (`cc1`).** Translates C into **assembly**, `hello.s`: a text file with one machine
   instruction per line. The book points out that assembly works as a common output language: C and
   Fortran compilers produce the same assembly.
3. **Assembly (`as`).** Translates assembly into machine code and stores it in a **relocatable
   object**, `hello.o`. This file is already binary: in a text editor it looks like garbage.
4. **Linking (`ld`).** `hello.c` calls `printf`, which is not in it. It comes from the C standard
   library, in a precompiled object, `printf.o`. The **linker** merges the two and produces the `hello`
   executable, ready to be loaded into memory.

The section also has an aside on the **GNU project**, started by Richard Stallman in 1984 to build a
Unix-like system that is completely free. GNU built everything except the kernel (which came from
Linux): emacs, gcc, gdb, the assembler, the linker. The book notes that the open source movement owes
its intellectual origins to this idea of free software, _"free as in free speech, not free beer"_.

## Checking it myself

You can stop `gcc` after each phase and look at the result. I did it with gcc 16 on x86-64 Linux:

```text
$ gcc -E hello.c -o hello.i       # preprocess only
$ gcc -S -Og hello.c -o hello.s   # stop at assembly
$ gcc -c -Og hello.c              # stop at the relocatable object
$ gcc -Og hello.o -o hello        # link only
```

The size of each form already tells a story:

| File      | Size   | What it is                                         |
| --------- | ------ | -------------------------------------------------- |
| `hello.c` | 79 B   | 7 lines of C                                       |
| `hello.i` | 20 KB  | 845 lines: all of `stdio.h` pasted at the top      |
| `hello.s` | 423 B  | assembly as text                                   |
| `hello.o` | 1.5 KB | relocatable ELF; `main` takes 26 bytes             |
| `hello`   | 16 KB  | ELF executable (837 KB when linked with `-static`) |

The assembly is almost the same as the book's:

```asm
main:
    subq    $8, %rsp
    leaq    .LC0(%rip), %rdi
    call    puts@PLT
    movl    $0, %eax
    addq    $8, %rsp
    ret
```

Looking closely, four things show up that the book simplifies or that changed since 2016.

**`printf` became `puts`.** I wrote `printf("hello, world\n")`, but the assembly calls `puts`. The
compiler knows that a `printf` with no `%` that ends in `\n` does the same as a `puts` of the string
without the `\n`, and `puts` is cheaper. The swap happens even at `-O0`. Only with `-fno-builtin`
does the call stay as `printf`.

**`cpp` does not show up as a process.** `gcc -v` shows every program the driver calls. Today the
list is `cc1` → `as` → `collect2` (which calls `ld`). Preprocessing happens inside `cc1`. The four
phases still exist, but as logical steps, not necessarily as separate programs.

**`main` is 26 bytes, not 17.** Executables on modern Linux are **PIE** (_position-independent
executables_) by default. That is why the string is addressed relative to `%rip`:
`leaq .LC0(%rip)` takes 7 bytes, against 5 for the book's `movl $.LC0`.

**No `printf.o` gets copied in.** The executable is **dynamically** linked:

```text
$ nm hello | grep puts
                 U puts@GLIBC_2.2.5
$ ldd hello
        libc.so.6 => /usr/lib/libc.so.6
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2
```

`U` means _undefined_. Even after `ld`, `puts` is still not in the file. It is resolved by
`ld-linux` when the program is loaded. Linking got split into two steps, one at build time and one
at `exec` time. The book leaves this detail for chapter 7.

## Zeros waiting for meaning

My favorite part was seeing relocation. In `hello.o`, the instructions that depend on addresses have
**zeros** in place:

```text
$ objdump -d -r hello.o
   4:  48 8d 3d 00 00 00 00   lea    0x0(%rip),%rdi
                      7: R_X86_64_PC32   .LC0-0x4
   b:  e8 00 00 00 00         call   10 <main+0x10>
                      c: R_X86_64_PLT32  puts-0x4
```

The assembler does not know where the string and `puts` will end up, so it leaves a blank and writes
down a **relocation record**: "at byte 7, put the address of `.LC0`; at byte 12, the address of
`puts`". In the executable, the linker filled those fields in:

```text
$ objdump -d hello
  113d:  48 8d 3d c0 0e 00 00   lea    0xec0(%rip),%rdi
  1144:  e8 e7 fe ff ff         call   1030 <puts@plt>
```

It is the idea from [section 1.1](/posts/csapp-1-1-bits-and-context/) again: `00 00 00 00` means
nothing until something gives it context. The difference is that here the context arrives **later**,
in a later phase of the pipeline.

## Each form has a reader

This is the philosophical part.

The same program exists in five forms, and each one is made for a different reader. The `.c` is for
people. The `.i` is for the compiler, which doesn't want to deal with `#include`. The `.s` is for
people who want to see the machine. The `.o` is for the linker. The executable is for the loader and
the CPU. Compiling means rewriting the same text for a new audience at each step.

Every translation loses something and adds something. A book translator picks words the author never
wrote, and so does the compiler: I asked for `printf` and got `puts`. The compiler's promise is not "I
will do what you wrote", but "the **observable behavior** will be the same". Most of the time that is
enough. When you need to understand performance, a strange bug or a security hole, the question
becomes "what is actually running?", and the only reliable answer is to read the translated form.

This also has an uncomfortable side. The executable you run was produced by a compiler that was, in
turn, compiled by another compiler. You have never read most of that code. Ken Thompson showed in
_Reflections on Trusting Trust_ (1984) that a compiler can insert a backdoor that appears in no
source code at all: not in the program, not in the compiler itself. Using a computer means trusting a
chain of translators. The book does not get into this, but it is hard not to think about it after
watching `printf` disappear.

## Errors that are not in your code

The pragmatic side: splitting compilation from linking is what makes **separate compilation**
possible. Each `.c` becomes a `.o` on its own, and only what changed needs to be recompiled.
Libraries exist because of this.

The cost is a new class of error, where every file is correct and the problem is in how they fit
together:

```text
$ cat m.c
int answer(void);
int main(void) { return answer(); }
$ gcc -c m.c        # compiles without complaint
$ gcc m.c -o m
m.c:(.text+0x5): undefined reference to `answer'
collect2: error: ld returned 1 exit status
```

The compiler accepted it because `answer` was declared. The complaint came from `ld`, because nobody
defined it. Knowing which phase an error comes from already tells you a lot about where to look:

- **Preprocessor error** (`No such file or directory` on an `#include`): header search paths.
- **Compiler error**: syntax or types, inside one file.
- **Linker error** (`undefined reference`, `multiple definition`): between files and libraries.
- **Loader error** (`cannot open shared object file`): the build passed, but the library is not on
  the machine where the program runs.

## Takeaways

1. Use `-E`, `-S`, `-c` and `-v`. Seeing each intermediate form takes a lot of the magic away.
2. The code that runs is not the code you wrote. When the difference matters, read the assembly
   (`gcc -S` or [Compiler Explorer](https://godbolt.org)).
3. Read error messages looking for the phase. `ld returned 1 exit status` says the problem is not
   the syntax, but how the pieces fit together.

Next stop: 1.3, which explains why it pays to understand how the compilation system works.
