---
title: 'CSAPP §1.5 — Caches matter: most of the work is moving data'
description: 'CSAPP series, part 5: notes and reflections on section 1.5 — the cache hierarchy, measured on my machine, from 1 ns to 100 ns.'
date: 2026-10-08T19:42:00Z
lang: en
tags: [csapp, systems, c, hardware, performance]
---

> **CSAPP series** — reading notes on _Computer Systems: A Programmer's Perspective_, one section
> at a time. Every post lives under [#csapp](/tags/csapp/). Previous:
> [§1.4 — The processor reads and interprets](/posts/csapp-1-4-the-processor/).
> _[Leia em português](/posts/csapp-1-5-caches-importam/)._

In the [previous section](/posts/csapp-1-4-the-processor/), `hello` ran: the code went from disk to
memory and from memory to the CPU, and the string `hello, world\n` went from disk to memory and from
memory to the screen. Section 1.5 draws a lesson from that trip: **a system spends a lot of time
moving information from one place to another**.

## What the book says

From the programmer's point of view, these copies are overhead: they slow down the "real work" of the
program. That is why making them fast is one of the main goals of system designers.

The problem is physics. Larger storage devices are slower, and faster devices cost more. The book
gives the scale:

- The disk might be 1,000 times larger than main memory, but reading a word from disk can take
  **10 million times** longer.
- The register file holds a few hundred bytes, against billions in memory, but the CPU reads from it
  about **100 times** faster.

And this processor–memory gap keeps growing, because it is easier and cheaper to make processors
faster than to make memory faster.

The answer is **caches**: smaller, faster memories that hold what the CPU is likely to need soon. The
**L1** sits on the chip itself, holds tens of thousands of bytes and is almost as fast as the
registers. The **L2** is larger (hundreds of thousands to millions of bytes) and about 5 times slower
than L1, but still 5 to 10 times faster than main memory. Newer systems have an **L3**. Caches use
SRAM; main memory uses DRAM.

What makes this work is **locality**: the tendency of programs to access data and code in nearby
regions. With caches, the system gets the effect of a memory that is both large and fast.

The section ends with what the authors call one of the most important lessons in the book:
programmers who understand caches can make their programs **an order of magnitude** faster.

## Measuring the steps

I wanted to see this hierarchy on my machine. The test is a linked list in random order, one node per
cache line (64 bytes). Each read depends on the previous one, because the next address is only known
once the current node arrives. So the CPU cannot get ahead, and the time per step is pure memory
latency. I varied the list size from 4 KiB to 512 MiB, on a P-core of the i7-1255U (48 KiB L1,
1.25 MiB L2, 12 MiB L3):

![Latency per access as a function of data size: about 1 ns up to 32 KiB, 3 ns up to 512 KiB, rising through L3 and reaching about 100 ns in DRAM](./latency.svg)

| Size        | ns per access | Where the data fits |
| ----------- | ------------- | ------------------- |
| 4–32 KiB    | ~1.1          | L1                  |
| 64–512 KiB  | ~3.3          | L2                  |
| 2–8 MiB     | 13–39         | L3                  |
| 16 MiB      | 85            | DRAM                |
| 128–512 MiB | 100–126       | DRAM                |

The steps appear exactly at the cache sizes. From L1 to DRAM, the same `p = p->next` becomes **about
100 times** slower. The climb inside L3 (from 13 to 39 ns) I can't fully explain yet. My guess is
address translation (the TLB), which is a chapter 9 topic.

## Rows and columns

The second test is the classic one. A 4096 × 4096 matrix of `int` (64 MiB), summed two ways:

```c
for (int i = 0; i < N; i++)        // by rows
    for (int j = 0; j < N; j++)
        s += m[i][j];

for (int j = 0; j < N; j++)        // by columns
    for (int i = 0; i < N; i++)
        s += m[i][j];
```

In C, rows are contiguous in memory. Summing by rows reads the bytes in the order they are stored.
Summing by columns jumps 16 KiB on every access, and each jump lands on a different cache line.

| Flags | By rows | By columns | Gap    |
| ----- | ------- | ---------- | ------ |
| `-O1` | ~6 ms   | ~205 ms    | ~35x   |
| `-O2` | ~4 ms   | ~60 ms     | ~8–15x |

The same 16 million additions, the same result. Only the order changes. The book promises "an order
of magnitude", and here it was more than that.

## Computing is cheap, moving is expensive

This is the philosophical part.

An addition takes less than a nanosecond. Fetching the operand from DRAM takes a hundred. When we
picture "the computer working", we imagine calculation, but most of the time it is **waiting for data
to arrive**. It is like a very fast reader who has to walk to the library for every page.

The hierarchy is not an engineering choice that could have gone differently. It comes from physics:
signals take time to travel, large memories take up area, and area ends up far from the core. A large
memory _has_ to be far away, and what is far away is slow.

A cache, then, is a **bet that the past predicts the future**. It keeps what was just used (temporal
locality) and the neighbors of what was used (spatial locality), betting you will come back to them.
And the bet usually pays off, because programs, like people, have habits. The desk holds the open
books, the shelf holds this week's, the library holds the rest. Nobody walks to the library for every
sentence.

This also says something about the abstractions we have seen so far. In
[section 1.4](/posts/csapp-1-4-the-processor/), memory was "an array of bytes, each with its
address". It is a useful abstraction, but it hides that an address can cost 1 ns or 100 ns depending
on where the data is. All addresses look the same. They aren't.

## Big-O doesn't tell the whole story

The pragmatic side: both matrix sums are O(n²). By complexity analysis, they are the same algorithm.
In practice, one is 35 times slower than the other. The constant the notation hides is, very often,
memory.

Some everyday consequences:

- **Arrays usually beat linked lists**, even when theory says otherwise, because arrays are contiguous
  and lists scatter their nodes across memory.
- **Loop order matters.** Walk the data in the order it is stored.
- **Struct of arrays vs array of structs.** If a loop only uses one field, storing that field
  contiguously brings into the cache only what will be used.
- **Smaller data is faster data.** An `int32` instead of an `int64` fits twice as many values in each
  cache line.

## Takeaways

1. Think about how much data your loop touches and where it fits: L1, L2, L3 or DRAM. Performance
   changes in steps, not smoothly.
2. Access memory in order. Sequential access is the case all of the hardware was built to speed up.
3. Measure. The numbers in this post are from my machine. Yours will differ, but the steps will be
   there.

Next stop: 1.6, where the idea of a cache turns into a whole hierarchy of storage devices.
