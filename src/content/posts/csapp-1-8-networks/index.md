---
title: 'CSAPP §1.8 — Systems talk over networks: hello on another machine'
description: 'CSAPP series, part 8: notes and reflections on section 1.8 — the network as just another I/O device, and hello running through a socket.'
date: 2026-10-13T11:52:00Z
lang: en
tags: [csapp, systems, os, networking]
---

> **CSAPP series** — reading notes on _Computer Systems: A Programmer's Perspective_, one section
> at a time. Every post lives under [#csapp](/tags/csapp/). Previous:
> [§1.7 — The operating system](/posts/csapp-1-7-the-operating-system/).
> _[Leia em português](/posts/csapp-1-8-redes/)._

So far, this series has treated the computer as an isolated thing: a processor, memory, a few
devices and an operating system. Section 1.8 points out the obvious: almost no computer today lives
alone. And the way the book fits the network into what we have already seen is quite simple.

## What the book says

From a system's point of view, **the network is just another I/O device**. It connects to the I/O
bus through a network adapter, just like the disk connects through the disk controller. When the
system copies bytes from memory to the adapter, those bytes go to another machine instead of to the
disk. When it reads from the network, it copies into memory bytes that came from outside.

With the Internet, copying information from one machine to another became one of the most important
uses of computers. Email, messaging, the Web: all of it depends on that.

To illustrate, the book runs `hello` on another machine using **telnet**:

1. The user types `hello` into the telnet client on the local machine.
2. The client sends the string to the telnet server on the remote machine.
3. The server passes the string to the remote shell, which runs `hello` and returns the output to the
   server.
4. The server sends `hello, world\n` back over the network to the client.
5. The client prints the string on the local terminal.

This back-and-forth between **client and server** is the pattern of practically every network
application. In chapter 11, the book uses it to build a Web server.

The section also has an aside with the original Linux announcement, from August 25, 1991. Linus
Torvalds, a Finnish student, wrote to the `comp.os.minix` newsgroup: _"I'm doing a (free) operating
system (just a hobby, won't be big and professional like gnu) for 386(486) AT clones."_ His starting
point was Minix, a system Andrew Tanenbaum wrote for teaching. Together with the GNU tools, Linux
became a complete Unix.

## Checking it myself

### hello over the network

Nobody uses telnet anymore, because it sends everything in plain text, passwords included. But you
can build the same setup as Figure 1.15 with `socat`. To avoid exposing anything, the server only
accepts connections from the same machine and only runs `./hello`, never a shell:

```text
$ socat TCP-LISTEN:2323,bind=127.0.0.1,reuseaddr,fork EXEC:./hello &
$ socat - TCP:127.0.0.1:2323
hello, world
```

For each connection, the server forks, runs `hello` and wires the program's output to the socket. The
client reads from the socket and prints to the terminal. Each full round trip took about **7 ms**,
including creating the processes.

The most interesting detail is that `hello` didn't change at all. It is the same binary from
[section 1.2](/posts/csapp-1-2-programs-translated/). It still calls `write` on descriptor 1, without
knowing that, this time, descriptor 1 is a TCP connection. That only works because of the file
abstraction from [section 1.7](/posts/csapp-1-7-the-operating-system/).

### The network as a file

The same goes for the reading side. In bash, a TCP connection is a file descriptor like any other:

```text
$ exec 3<>/dev/tcp/1.1.1.1/80
$ printf 'GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n' >&3
$ head -1 <&3
HTTP/1.1 301 Moved Permanently
```

One `write` sent the HTTP request and one `read` brought back the response. The same two verbs used to
read and write files on disk.

### How far is "far"

| Destination                            | Round-trip time |
| -------------------------------------- | --------------- |
| `127.0.0.1` (the same machine)         | ~0.08 ms        |
| `rt-00.github.io` (this blog's server) | ~11 ms          |

The same network stack, with and without the physical path to the other side: more than 100 times
apart. As we saw in [section 1.6](/posts/csapp-1-6-memory-hierarchy/), the network is the lowest rung
of the memory hierarchy. If an L1 access took a second, a round trip to GitHub would take four
months.

## Same interface, different world

This is the philosophical part.

The decision to treat the network as just another I/O device is elegant. A program that writes to a
file can, without changing anything, write to someone on the other side of the world. The `hello`
from 1978 (the one in Kernighan and Ritchie's book) runs today through a socket without knowing it.

But the identical interface hides a huge difference. A local disk rarely disappears in the middle of
a read. The network can get slow, drop packets, deliver only part of the data or go silent because
the other side died. The first of the "fallacies of distributed computing", a famous list of wrong
assumptions about networks, is precisely believing that _the network is reliable_.

So the file abstraction does two things at once. It makes the network easy to use, because it is just
`read` and `write`. And it makes it easy to forget that the network is different from a file. A good
share of distributed systems problems come from that forgetting.

## Closing the hello loop

The pragmatic side, and a recap.

Since the first post, this series has followed the same seven-line program. It started as ASCII bytes
in a file ([1.1](/posts/csapp-1-1-bits-and-context/)), was translated into machine code
([1.2](/posts/csapp-1-2-programs-translated/)), ran on a processor
([1.4](/posts/csapp-1-4-the-processor/)) through the operating system
([1.7](/posts/csapp-1-7-the-operating-system/)) and now runs on one machine while printing on another.

Looking back, almost every step was **copying bytes from one place to another**: from disk to memory,
from memory to registers, from registers to the screen, from memory to the network adapter.
[Section 1.5](/posts/csapp-1-5-caches-matter/) had already said that most of a computer's work is
moving data. The network just stretches the distance.

Some practical consequences:

- **Every network call has a failure case.** Think about timeouts and retries from the start, not
  after the first incident.
- **Latency dominates.** At 11 ms per round trip, a hundred sequential calls already add up to more
  than a second. Batch calls or run them in parallel.
- **The first connection is the most expensive.** DNS, TCP and TLS add up to tens of milliseconds.
  Reuse connections.

## Takeaways

1. The network is I/O: `read` and `write` on a descriptor. That makes the code easy to write and
   changes nothing about the physics of the path.
2. Programs that write to `stdout` and read from `stdin` work anywhere: terminal, file, pipe or
   socket. Tools written that way are worth it.
3. Treat the network as the slowest and least reliable level of the hierarchy, because that is what
   it is.

Next stop: [1.9](/posts/csapp-1-9-important-themes/), where the book gathers the chapter's important themes.
