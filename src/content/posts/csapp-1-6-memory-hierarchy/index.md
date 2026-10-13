---
title: 'CSAPP §1.6 — The memory hierarchy: each level caches the next'
description: 'CSAPP series, part 6: notes and reflections on section 1.6 — from register to network, nine orders of magnitude measured on my machine.'
date: 2026-10-13T11:50:00Z
lang: en
tags: [csapp, systems, hardware, performance]
---

> **CSAPP series** — reading notes on _Computer Systems: A Programmer's Perspective_, one section
> at a time. Every post lives under [#csapp](/tags/csapp/). Previous:
> [§1.5 — Caches matter](/posts/csapp-1-5-caches-matter/).
> _[Leia em português](/posts/csapp-1-6-hierarquia-de-memoria/)._

In the [previous section](/posts/csapp-1-5-caches-matter/), we saw that a small, fast memory between
the CPU and a large, slow one (a cache) changes performance by an order of magnitude. Section 1.6 is
short and takes one step further: the idea is not just about caches. It organizes **all** of a
computer's storage.

## What the book says

Every system organizes its storage devices in a **memory hierarchy**. Going down the hierarchy,
devices get slower, larger and cheaper per byte:

| Level | Device                                      |
| ----- | ------------------------------------------- |
| L0    | registers                                   |
| L1    | L1 cache (SRAM)                             |
| L2    | L2 cache (SRAM)                             |
| L3    | L3 cache (SRAM)                             |
| L4    | main memory (DRAM)                          |
| L5    | local secondary storage (disks)             |
| L6    | remote secondary storage (network, servers) |

And the main idea fits in one sentence: **each level serves as a cache for the level below**.
Registers cache L1. L1 caches L2, which caches L3, which caches main memory. Main memory caches the
disk. And the local disk can cache data stored on other machines.

The book closes by saying that, just as you can exploit caches, you can exploit the whole hierarchy.
Chapter 6 covers this in detail.

## Measuring the whole ladder

In [section 1.5](/posts/csapp-1-5-caches-matter/) I measured levels L1 to L4. Now I wanted to
complete the ladder, from register to network:

- **L0:** a loop of register additions, each depending on the previous one.
- **L1 to L4:** the same linked-list test from the previous section.
- **L5:** random 4 KiB reads from a 1 GiB file on the SSD, with `O_DIRECT` to bypass the kernel's
  cache.
- **L6:** `ping` to the GitHub Pages server that hosts this blog.

![Latency measured at each level of the hierarchy, from 0.46 ns in registers to 11 ms over the network, with the human scale if an L1 access took 1 second](./hierarchy.svg)

| Level | What I measured                            | Latency  | If L1 took 1 s |
| ----- | ------------------------------------------ | -------- | -------------- |
| L0    | register addition (including loop control) | ~0.46 ns | 0.4 s          |
| L1    | linked list, 4–32 KiB                      | ~1.1 ns  | 1 s            |
| L2    | linked list, 64–512 KiB                    | ~3.3 ns  | 3 s            |
| L3    | linked list, 4 MiB                         | ~20 ns   | 19 s           |
| L4    | linked list, 128 MiB or more               | ~100 ns  | 1.5 min        |
| L5    | random 4 KiB read from the SSD             | ~97 µs   | 1 day          |
| L6    | round trip to GitHub Pages                 | ~11 ms   | 4 months       |

From the first level to the last there are almost **nine orders of magnitude**. The right column
helps to feel it: if fetching from L1 took a second, fetching from the SSD would take a day, and
sending a packet to this blog's server and getting the answer back would take four months.

## Memory as a cache for the disk

The book says main memory is a cache for the disk. You can see it directly. I repeated the same
random 4 KiB reads, now without `O_DIRECT`, after reading the blocks once:

```text
SSD (O_DIRECT)     97.48 us
page cache          0.82 us
```

On the second run, the data came from the **page cache**: the part of main memory that Linux uses
to keep recently read pieces of files. The read became about **100 times** faster, and the
remaining microsecond or so is basically the cost of the system call and the copy.

## Caches even on the network

The lower levels have caches too. I requested this blog's home page three times with `curl`:

```text
dns=0.013611 connect=0.021448 tls=0.037118 total=0.213989
dns=0.002084 connect=0.011932 tls=0.026914 total=0.039806
dns=0.002032 connect=0.012793 tls=0.028956 total=0.041266
```

The first request took **214 ms**, and the next ones about **40 ms**. DNS resolution dropped from
13.6 ms to 2 ms, because the answer was kept by the local resolver. And GitHub Pages itself serves the
blog through a CDN, which is a network of caches spread around the world in front of the origin
server.

## Cache is a relationship, not a device

This is the philosophical part.

DRAM is "the memory" when we look from the CPU, and "the cache" when we look from the disk. The SSD
is "storage" for your laptop and "the cache" for the remote server. No device is a cache by nature.
Being a cache is a **relationship** between one level and the level below: "I keep a copy of what you
have, because I am faster and someone will ask for it again".

And the same relationship repeats at every scale. The pattern "small and fast in front of large and
slow" shows up in registers, CPU caches, the page cache, the DNS cache, the CDN, the browser cache.
It is a structure that repeats itself at every level, like a fractal. Understand one level and you
already understand the others.

## The same idea above the hardware

The pragmatic side: the architecture of a lot of software follows the same rule.

- A **Redis** in front of a database is L3 in front of DRAM.
- A **CDN** in front of the origin server is memory in front of the disk.
- **Memoization** in front of an expensive function is the register in front of L1.

And two numbers are worth memorizing: **DRAM ≈ 100 ns** and **SSD ≈ 100 µs**. That is a thousand
times apart. Any code that does a disk read or a network call inside a loop that "should be fast" is
paying that difference on every iteration.

## Takeaways

1. Each level caches the next. When something is slow, ask which level the data is in and whether it
   could be one level up.
2. The first time is always the most expensive. Honest measurements separate the cold case (no
   cache) from the warm case (cached).
3. Know the orders of magnitude: ~1 ns, ~100 ns, ~100 µs, ~10 ms. They decide more about
   performance than most code choices.

Next stop: [1.7](/posts/csapp-1-7-the-operating-system/), about the operating system, the layer that
manages all of this.
