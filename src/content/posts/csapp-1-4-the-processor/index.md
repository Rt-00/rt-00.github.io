---
title: 'CSAPP §1.4 — The processor reads and interprets: the hardware that runs hello'
description: 'CSAPP series, part 4: notes and reflections on section 1.4 — buses, memory, the CPU and the path of hello from keyboard to screen.'
date: 2026-10-08T19:41:00Z
lang: en
tags: [csapp, systems, hardware]
---

> **CSAPP series** — reading notes on _Computer Systems: A Programmer's Perspective_, one section
> at a time. Every post lives under [#csapp](/tags/csapp/). Previous:
> [§1.3 — Why understand the compiler](/posts/csapp-1-3-why-compilation-matters/).
> _[Leia em português](/posts/csapp-1-4-o-processador/)._

So far, `hello` has been a file: first text, then an executable stored on disk. In section 1.4 it
finally runs:

```text
$ ./hello
hello, world
$
```

The command is received by the **shell**, a command-line interpreter. It prints a prompt, waits for
you to type and runs the command. If the first word is not a shell built-in, the shell assumes it is
the name of an executable, loads the program, runs it and waits for it to finish.

To explain what happens in between, the book stops and describes the hardware. This post covers the
whole of section 1.4, including subsections 1.4.1 (hardware organization) and 1.4.2 (running
`hello`).

## What the book says

![Hardware organization: CPU, I/O bridge, main memory and devices on the I/O bus, with the three steps of hello numbered](./hardware.svg)

**Buses** are the conduits that carry bytes between components. They transfer fixed-size chunks
called **words**. Today a word is 4 bytes (32 bits) or 8 bytes (64 bits).

**I/O devices** connect the system to the outside world: keyboard, mouse, display and the **disk**,
where `hello` is stored. Each one connects to the I/O bus through a **controller** (a chip) or an
**adapter** (a card). The difference is only physical: both move data between the bus and the
device.

**Main memory** holds the program and its data while it runs. Physically it is DRAM chips.
Logically, it is an **array of bytes**, each with an address starting at zero.

The **processor** (CPU) interprets the instructions stored in memory. At its core is the **PC**
(_program counter_), a register that holds the address of the next instruction. From the moment the
computer powers on until it shuts down, the CPU repeats the same cycle: read the instruction the PC
points to, interpret its bits, perform a simple operation and update the PC. There are only a few
operations: **load** (memory → register), **store** (register → memory), **operate** (two registers →
ALU → register) and **jump** (a value from the instruction → PC).

The book makes an important distinction here. The **ISA** (_instruction set architecture_) describes
the effect of each instruction, in a simple model where everything happens in sequence. The
**microarchitecture** is how the processor is actually built, and it is far more complex. The CPU
_appears_ to be a simple implementation of the ISA, but it isn't.

With that, running `hello` happens in three steps (the numbers in the figure):

1. As you type `./hello`, the shell reads each character from the keyboard into a register and
   stores it in memory.
2. On Enter, the shell loads the executable: code and data go from disk to memory. With **DMA**
   (_direct memory access_), the bytes go straight from disk to memory without passing through the
   CPU.
3. The CPU runs `main`: the bytes of `hello, world\n` go from memory to registers and from there to
   the display.

## Checking it myself

### The PC moving

With `gdb` you can watch the PC (on x86-64, the `%rip` register) advance one instruction at a time:

```text
(gdb) x/3i $pc
=> 0x555555555139 <main>:     sub    $0x8,%rsp
   0x55555555513d <main+4>:   lea    0xec0(%rip),%rdi
   0x555555555144 <main+11>:  call   0x555555555030 <puts@plt>
(gdb) stepi     # $pc: 0x...139 → 0x...13d   (+4)
(gdb) stepi     # $pc: 0x...13d → 0x...144   (+7)
(gdb) x/s $rdi
0x555555556004: "hello, world"
```

The PC moves by exactly the size of each instruction: 4 bytes, then 7. It is the book's "interpret
and update the PC" happening right in front of us.

### What "loading" means

The book describes loading as a copy from disk to memory. I measured it a different way, counting
_page faults_ with `getrusage` at the start of `main`:

```text
start of main       minor=82 major=0
after printf        minor=88 major=0
```

The kernel does not copy the whole executable before starting. It **maps** the file into the
process's memory, and each page is only brought in when the CPU first tries to access it. Each of
those first accesses is a _page fault_. There were 82 before reaching `main`. And **zero** were
_major_, meaning not a single byte came from the disk: the file was still in the kernel's page
cache, because I had just compiled it. The memory map shows the result, with each part of the
executable in a region with its own permissions:

```text
0x555555555000-0x555555556000 r-xp  hello      ← code (the only executable part)
0x555555556000-0x555555557000 r--p  hello      ← "hello, world" (read-only)
0x7ffff7c24000-0x7ffff7d9f000 r-xp  libc.so.6
```

### The path to the screen

The last step also has more layers than the figure shows. I asked `gdb` to stop at the `write`
system call:

```text
(gdb) catch syscall write
(gdb) run
Catchpoint 1 (call to syscall write), write () from /usr/lib/libc.so.6
(gdb) p $rdi            →  1                    (stdout)
(gdb) x/s $rsi          →  0x555555559010: "hello, world\n"
(gdb) p $rdx            →  13                   (bytes)
(gdb) bt
#4  _IO_flush_all ()
#7  exit ()
```

Two surprises. First, the string doesn't go from the read-only area straight to the screen: libc
copies the bytes into a **buffer on the heap** (`0x555555559010`) and only then asks the kernel to
write. Second, since the output here was a pipe and not a terminal, `write` only happened **inside
`exit()`**. `printf` just filled the buffer, and program shutdown is what flushed it. After that
there is still the kernel, the terminal emulator (which is another process) and the graphics card.

### Same ISA, two machines

This laptop has an i7-1255U, which is a **hybrid** processor: 2 performance cores (P-cores) and 8
efficiency cores (E-cores), with different internal designs. Both run exactly the same binary,
because they implement the same ISA.

I took `sum_ref` and `sum_local` from [section 1.3](/posts/csapp-1-3-why-compilation-matters/) and
ran them on each kind of core with `taskset`:

| Core   | `sum_ref` | `sum_local` |
| ------ | --------- | ----------- |
| P-core | ~510 ms   | ~75 ms      |
| E-core | ~131 ms   | ~130 ms     |

On the "strong" core, accumulating through memory costs 7x. On the "weak" core it costs nothing, and
`sum_ref` runs **4x faster** than on the P-core. I haven't dug into which detail of the E-core causes
this. But the point is clear: the cost is not in C or in the ISA. It is in the microarchitecture.

## The computer is an interpreter

This is the philosophical part.

"Read the next instruction, interpret it, execute it, move on" is the same cycle as a shell, a REPL,
a virtual machine. The CPU is the interpreter at the bottom of all the others. The shell that
interprets `./hello` is itself a sequence of instructions being interpreted by the CPU.

And instructions live in the same memory as data. That is the **stored-program** model (the von
Neumann architecture), and it ties back to [section 1.1](/posts/csapp-1-1-bits-and-context/): what
makes a byte an instruction, and not data, is the PC pointing at it.

The ISA vs microarchitecture split is the same idea as
[section 1.2](/posts/csapp-1-2-programs-translated/), now in hardware. The compiler promises that the
observable behavior is the same, even while swapping `printf` for `puts`. The CPU promises that the
result is **as if** instructions ran one at a time, in order, even while running several at once, out
of order and even running ahead on paths that may never be taken. The ISA is a contract. The
microarchitecture is how the contract is fulfilled.

And contracts leak. In 2018, the **Spectre** and **Meltdown** attacks showed that microarchitectural
effects (what was left in the cache after speculative execution) can reveal data that, according to
the ISA, should be inaccessible. The abstraction was correct, and still the implementation detail
was observable.

## Models simplify

The pragmatic side: the book warns that it will leave out details, and it is good to keep that in
mind. "Loading the program" is really mapping the file and handling page faults. "Copying the string
to the display" is really a libc buffer, a system call, the kernel, the terminal and the GPU. The
three-step model is not wrong. It is at the right resolution for a first contact.

Knowing there is a higher resolution helps with debugging. When a `printf` "doesn't show up" before a
crash, the reason is usually the buffer: the program died before flushing it. When the first read of
a big file is slow and the second is fast, the difference is usually the page cache.

## Takeaways

1. Use `gdb` to look at the machine: `x/i $pc`, `stepi`, `info proc mappings`, `catch syscall`. It
   shows the book's model at work.
2. The ISA says what happens. The microarchitecture says what it costs. For performance, the second
   matters as much as the first.
3. Buffered output is the most common explanation for "my print disappeared". Use `fflush` or write
   to `stderr` when ordering matters.

Next stop: [1.5](/posts/csapp-1-5-caches-matter/), about the fact that most of all this work is
moving data from one place to another.
