---
layout: post
title: CTF Writeup - 0CTF 2022 - vintage - part1+2
date: 2022-09-19 21:13:37 +0000
tags:
    - ctf
    - emulation
    - reversing
    - tracing
---

{% include custom.html %}

# Introduction

For these 2 tasks, we are given a binary targeting a console system that uses an 8-bit processor, although it also supports 16-bit addressing. Despite this lesser known target, we can still apply general approaches to understand its internals.

# Part 1

> Back to 1980s

Download: [game.bin]({{ site.url }}{{ site.baseurl }}/assets/writeups/0CTF2022/game.bin)

Let's look at the first bytes with `xxd -l $((0x20)) game.bin`:

```
00000000: 6720 4743 4520 3230 3232 80fd 0df8 50f0  g GCE 2022....P.
00000010: b856 4543 544f 525f 4741 4d45 8000 ce00  .VECTOR_GAME....
```

Searching for "g GCE" shows us that this is a Vectrex game.

## Tooling

After getting an [overview of this system](http://vectrexmuseum.com/share/coder/), we can pick some appropriate tools:

* [Ghidra supports the CPU](https://github.com/NationalSecurityAgency/ghidra/pull/1201), which is a [Motorola 6809](https://ia902906.us.archive.org/18/items/bitsavers_motorola68_13419254/M6809PM.rev0_May83_text.pdf);
* I didn't find any Vectrex loader, but we can lookup a [tutorial](https://wrongbaud.github.io/posts/writing-a-ghidra-loader/) and [write our own loader](https://github.com/nevesnunes/ghidra-vectrex-loader);
* MAME emulates this console and features [extensive debugging functions](https://docs.mamedev.org/debugger/index.html), along with save states, allowing us to freely edit memory and easily rollback changes;

Our loader doesn't need to do anything fancy, just lay out the [memory map](http://vectrexmuseum.com/share/coder/html/appendixa.htm#Reference)
 to allow us to follow cross-references, and also apply labels for [I/O ports](http://vectrexmuseum.com/share/coder/html/appendixb.htm), so that we can easily tell when e.g. the input controller is being read.

The entry point of the game ROM seems to depend on the length of the strings that preceed it. Looking at some [example disassembly](http://vectrexmuseum.com/share/coder/DIS/TAFT/NEW/ART.ASM), these strings are delimited by byte `\x80`, and the last string ends with `\x80\x00`. This was also the case with our game, so I used that pattern to start disassembling.

## Finding flag checks

My first step was to collect an instruction trace, so that we can [highlight in Ghidra](https://github.com/0ffffffffh/dragondance/issues/23#issuecomment-826111520) reachable boilerplate, but more importantly, **not** highlight some conditions that may be related to flag checks.

Let's load the game ROM in MAME, while also launching the built-in debugger:

`mame vectrex -cart ./game.bin -debug`

Let's start tracing with `trace mame.tr,,noloop`. We get a typical password prompt, 8 characters selected with arrow buttons, then submitted by pressing "stick 1 button 1" (mapped to LeftCtrl):

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/pass.png" alt=""/>
</div>

I stopped the trace after submitting and getting a "NO" displayed. We can remove duplicate entries with `<mame.tr sed 's/:.*//g' | sort -u > mame.sort.tr` then load the [resulting trace log]({{ site.url }}{{ site.baseurl }}/assets/writeups/0CTF2022/mame.sort.tr) in the Ghidra script mentioned before.

The entry point calls `FUN_2f3c()`, where we see the joystick being read:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/dis1.png" alt=""/>
</div>

We also see this unreached block:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/dis2.png" alt=""/>
</div>

If we look inside the called `FUN_1a63()`, there are some interesting checks, where the first one was reached, but the other 7 were not:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/dis3.png" alt=""/>
</div>

We also see some xor operations being done before those checks, so likely the password has some simple obfuscation.

Let's place a breakpoint at the start of these checks, to see which address is loaded in `puVar6`. The first check's disassembly shows that we can break at `bpset 1bf7` and inspect the stack register `S`:

```
1bef e6 e9 02 15     LDB        0x215,S
1bf3 e1 e9 01 15     CMPB       0x115,S
1bf7 10 26 00 4e     LBNE       LAB_1c49
```

After submitting password "AAAAAAAA", we hit the breakpoint and get `S = C995`, therefore `puVar6 = C995`. Let's check the memory contents being compared under MAME (Debug > New Memory Window):

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/mem1.png" alt=""/>
</div>

Is the obfuscation done on a character-by-character basis? Let's confirm with "BAAAAAAA":

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/mem2.png" alt=""/>
</div>

Indeed, only the first byte changed, and it matches on both addresses. Recall in the decompilation that 4 shorts are being compared, so 8 bytes at these addresses. Since the xor operation is commutative, associative, and its own inverse, we can directly extract the expected password:

```python
>>> # c995+215
>>> cbaa=b"\x77\xE5\xAF\x8B\xCD\x04\xD0\xA5"
>>> # c995+115
>>> caaa=b"\x74\xE8\xAF\x89\xC7\x0E\xD4\xBD"
>>> "".join(chr(cbaa[i] ^ caaa[i] ^ ord('A')) for i in range(8))
'BLACKKEY'
```

We got the first flag!

Turns out that the decompilation was misleading about those addresses `c995+10b` and `c995+8b`. If we look at the disassembly, we confirm that only 8 bytes are being compared, one at a time:

```
1bef e6 e9 02 15     LDB        0x215,S
1bf3 e1 e9 01 15     CMPB       0x115,S
1bf7 10 26 00 4e     LBNE       LAB_1c49
1bfb e6 e9 02 16     LDB        0x216,S
1bff e1 e9 01 16     CMPB       0x116,S
1c03 26 44           BNE        LAB_1c49
1c05 e6 e9 02 17     LDB        0x217,S
1c09 e1 e9 01 17     CMPB       0x117,S
1c0d 26 3a           BNE        LAB_1c49
1c0f e6 e9 02 18     LDB        0x218,S
1c13 e1 e9 01 18     CMPB       0x118,S
1c17 26 30           BNE        LAB_1c49
1c19 e6 e9 02 19     LDB        0x219,S
1c1d e1 e9 01 19     CMPB       0x119,S
1c21 26 26           BNE        LAB_1c49
1c23 e6 e9 02 1a     LDB        0x21a,S
1c27 e1 e9 01 1a     CMPB       0x11a,S
1c2b 26 1c           BNE        LAB_1c49
1c2d e6 e9 02 1b     LDB        0x21b,S
1c31 e1 e9 01 1b     CMPB       0x11b,S
1c35 26 12           BNE        LAB_1c49
1c37 e6 e9 02 1c     LDB        0x21c,S
1c3b e1 e9 01 1c     CMPB       0x11c,S
1c3f 26 08           BNE        LAB_1c49
1c41 c6 01           LDB        #0x1
1c43 32 e9 02 2c     LEAS       0x22c,S
1c47 35 e0           PULS        Y U PC
```

# Part 2

> Find all easter eggs and not to get caught cheating! Wrap what you get with "flag{}" as flag. Attachment is the same as part1.

After submitting the correct password, we are now in the actual game:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/start.png" alt=""/>
</div>

It's a platformer where we move to the right until we reach the flag (shown at the left, since the screen wraps around). We can collect up to 5 balls along the way by jumping around, but the last ball appears to be unreachable, since we can only fall to a bottomless pit:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/4.png" alt=""/>
</div>

Let's start by taking [another trace log]({{ site.url }}{{ site.baseurl }}/assets/writeups/0CTF2022/mame2b.sort.tr), where we collect one ball, then get a "GAME OVER" after falling off a platform. If we run into the flag without collecting the easter eggs, we get a "TRY HARDER". If the actual flag also uses the same message display function, we should have some non-highlighted branches in the caller function.

## Easter egg 1: Collecting all 5 balls

There's lots of options here, such as finding how the map is represented in data and place a platform under the ball, or even change the ball position. I choose to just **edit the player's position** to overlap the ball, then edit it again to return to a platform.

* We can run a fixed number of instruction steps at a time until the game registers the ball as captured, but before the player falls to the bottomless pit. I choose MAME's "Run to next VBlank" (F8), which gave a similar result, with the advantage of running up to a rendered screen frame.
* To locate the player's position in memory, there's also various options, but with the same underlying concept: we know that a variable increases if e.g. we move to the right, and decreases if we move to the left, so we just need to observe memory addresses that have such changes. We can monitor memory in real-time with some tool like Cheat Engine, or take various memory dumps and write a script to compare values at each address across dumps. I decided to be lazy and just eyeball the memory, since the work RAM address range was fairly small (`0xc800..0xcbff`).

So if we jump a few times, we see that the acceleration is stored at `c891` (positive when going up, negative when going down), and the y-position is 2 bytes stored at `c896`. To collect the ball:

1. Move the character to the platform right above the 5th ball (y-position = `000e`);
2. Break into the debugger by pressing "backtick";
3. Edit the position in the memory view to `fffe`;
4. Run a few frames with "F8";
5. Once the ball is collected (the easter egg counter now reads "1/3"), edit the position back to `000e`;
6. Resume with "F5";

To figure out the other eggs, we can **lookup variables updated after activating the 1st egg**. Let's go back to take a few memory dumps with `dump mame.dmp,0xc800,0x400`: Before collecting the last ball, we take a baseline (./egg0.dmp), then take another one after moving around and jumping (./egg0b.dmp), and another one after collecting the final ball (./egg1.dmp). The differences between ./egg0.dmp and ./egg0b.dmp can be disregarded, since we are only interested in differences exclusive to ./egg1.dmp.

```diff
--- egg0.dmp
+++ egg0b.dmp
@@ -1,23 +1,23 @@
 C800:  00 00 00 00 00 00 00 3F 00 00 00 00 00 00 00 00  .......?........
 C810:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................
-C820:  03 00 00 00 00 05 31 3F 05 CC F8 50 CA 50 00 00  ......1?...P.P..
+C820:  03 00 00 00 00 08 D6 3F 05 33 F8 50 CA 50 00 00  .......?.3.P.P..
 C830:  00 00 00 00 00 00 00 00 0B 00 00 01 00 30 75 00  .............0u.
 C840:  00 00 00 00 00 3F 00 00 00 00 00 00 00 FC 8D FE  .....?..........
 C850:  E8 FE B6 FD 1C 02 00 00 04 00 03 00 06 00 1F 1F  ................
 C860:  00 00 78 00 A0 01 66 00 00 00 00 00 00 00 00 00  ..x...f.........
 C870:  00 00 00 00 00 00 00 00 00 00 00 C8 7D 01 F3 BF  ............}...
-C880:  00 2E 01 00 00 00 03 03 00 00 07 06 05 04 29 00  ..............).
-C890:  00 00 00 00 00 00 FF EE 00 00 00 EE 01 00 02 00  ................
-C8A0:  00 00 00 00 2E 01 01 01 00 00 00 00 00 00 C2 0A  ................
-C8B0:  04 2D 33 FB 61 47 00 00 2E 02 00 32 02 08 00 02  .-3.aG.....2....
+C880:  00 2E 00 00 40 00 03 03 00 00 07 06 05 04 29 00  ....@.........).
+C890:  0E 00 00 00 00 00 FF EE 00 00 00 EE 01 00 02 03  ................
+C8A0:  00 00 00 00 2E 01 01 01 00 00 00 00 00 00 C5 B5  ................
+C8B0:  8A 5C 33 FB 61 47 00 00 2E 02 00 32 02 08 00 02  .\3.aG.....2....
 C8C0:  00 CE 00 00 D2 00 F8 00 01 00 00 00 00 00 00 00  ................
-C8D0:  00 00 00 00 02 00 2E 00 00 32 00 08 00 00 00 CE  .........2......
-C8E0:  02 00 D2 02 F8 00 01 00 00 00 00 00 00 00 00 00  ................
-C8F0:  00 00 00 00 40 00 00 1E 02 00 02 02 08 00 02 00  ....@...........
-C900:  FE 00 00 E2 00 F8 00 01 00 00 00 00 00 00 00 00  ................
+C8D0:  00 00 00 00 00 00 2E 00 00 12 00 00 20 00 08 00  ............ ...
+C8E0:  00 00 E0 00 F8 00 01 00 00 00 00 00 00 00 00 00  ................
+C8F0:  00 00 00 00 5E 02 00 02 02 08 00 02 00 FE 00 00  ....^...........
+C900:  A2 00 F8 00 01 F8 00 01 00 00 00 00 00 00 00 00  ................
 C910:  02 00 5E 00 00 02 00 08 00 00 00 FE 02 00 A2 02  ..^.............
 C920:  F8 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
-C930:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
+C930:  00 00 00 00 00 00 00 01 01 01 00 00 00 00 00 00  ................
 C940:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 C950:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

```diff
--- egg0.dmp
+++ egg1.dmp
@@ -1,21 +1,21 @@
 C800:  00 00 00 00 00 00 00 3F 00 00 00 00 00 00 00 00  .......?........
 C810:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................
-C820:  03 00 00 00 00 59 54 3F 05 CC F8 50 CA 50 00 00  .....YT?...P.P..
+C820:  03 00 00 00 00 5F 7D 3F 05 33 F8 50 CA 50 00 00  ....._}?.3.P.P..
 C830:  00 00 00 00 00 00 00 00 0B 00 00 01 00 30 75 00  .............0u.
 C840:  00 00 00 00 00 3B 1E 01 99 00 00 00 00 FC 8D FE  .....;..........
 C850:  E8 FE B6 FD 1C 02 00 00 04 00 03 00 06 00 1F 1F  ................
 C860:  00 00 78 00 A0 01 66 00 00 00 00 00 00 00 00 00  ..x...f.........
 C870:  00 00 00 00 00 00 00 00 00 00 00 C8 7D 01 F3 BF  ............}...
-C880:  00 1F 01 00 00 00 03 01 00 00 07 06 05 04 29 00  ..............).
-C890:  18 00 00 00 00 04 00 2E 00 00 00 2E 01 00 02 FE  ................
-C8A0:  0C 00 60 00 1F 01 01 01 00 00 00 00 00 00 C0 C4  ..`.............
-C8B0:  BC BB 94 92 23 35 00 00 1F 02 00 41 02 08 00 02  ....#5.....A....
-C8C0:  00 BF 00 00 E1 00 F8 00 01 00 00 00 00 00 00 00  ................
-C8D0:  00 00 00 00 02 00 1F 00 00 41 00 08 00 00 00 BF  .........A......
-C8E0:  02 00 E1 02 F8 00 01 00 00 00 00 00 00 00 00 00  ................
-C8F0:  00 00 00 00 40 00 00 0F 02 00 11 02 08 00 02 00  ....@...........
-C900:  EF 00 00 F1 00 F8 00 01 00 00 00 00 00 00 00 00  ................
-C910:  02 00 4F 00 00 11 00 08 00 00 00 EF 02 00 B1 02  ..O.............
+C880:  00 1D 01 00 00 00 03 02 00 00 07 06 05 04 29 00  ..............).
+C890:  26 00 00 01 01 05 00 0E 00 00 00 0E 01 00 02 FC  &...............
+C8A0:  0E 00 62 00 1D 01 01 01 00 00 00 00 00 00 B9 03  ..b.............
+C8B0:  42 3E 96 C9 1E B5 00 00 1D 02 00 43 02 08 00 02  B>.........C....
+C8C0:  00 BD 00 00 E3 00 F8 00 01 00 00 00 00 00 00 00  ................
+C8D0:  00 00 00 00 02 00 1D 00 00 43 00 08 00 00 00 BD  .........C......
+C8E0:  02 00 E3 02 F8 00 01 00 00 00 00 00 00 00 00 00  ................
+C8F0:  00 00 00 00 4D 02 00 13 02 08 00 02 00 ED 00 00  ....M...........
+C900:  B3 00 F8 00 01 F8 00 01 00 00 00 00 00 00 00 00  ................
+C910:  02 00 4D 00 00 13 00 08 00 00 00 ED 02 00 B3 02  ..M.............
 C920:  F8 00 01 F8 00 01 00 00 00 00 00 00 00 00 00 00  ................
 C930:  00 00 00 00 00 00 00 01 01 01 01 01 01 01 01 01  ................
 C940:  01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01  ................
@@ -33,11 +33,11 @@
 CA00:  01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01  ................
 CA10:  01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01  ................
 CA20:  01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01  ................
-CA30:  01 01 01 01 01 01 01 07 01 07 07 07 07 10 00 00  ................
-CA40:  D0 20 D0 E0 40 28 A2 C2 F0 0A 4D 01 01 01 01 00  . ..@(....M.....
-CA50:  30 2F 33 80 7F 91 FC E4 B0 87 64 64 64 64 20 80  0/3.......dddd .
-CA60:  8C AA 51 49 3F 66 0D F4 DB 42 33 D0 DE 3E E5 00  ..QI?f...B3..>..
-CA70:  01 02 03 04 00 00 00 00 00 00 00 13 62 2D 6F 6B  ............b-ok
+CA30:  01 01 01 01 01 01 07 07 01 07 01 07 07 F0 10 10  ................
+CA40:  00 00 D0 20 40 28 A2 C2 F0 0A 4D 01 01 01 01 01  ... @(....M.....
+CA50:  31 2F 33 80 7F 91 FC E4 B0 87 64 64 64 64 64 80  1/3.......ddddd.
+CA60:  8C AA 51 49 3F 9A 0D F4 DB 42 33 D0 DE 3E E5 00  ..QI?....B3..>..
+CA70:  01 00 03 00 00 00 00 00 00 00 00 13 62 2D 6F 6B  ............b-ok
 CA80:  AC 33 F8 DD 61 F2 DC DA 30 BA 3D 2F 7B 9F 77 44  .3..a...0.=/{.wD
 CA90:  67 C3 5E 7D CC 2B 20 5B 5F FA EF C9 5A FE 54 D9  g.^}.+ [_...Z.T.
 CAA0:  9C 0C 39 BF 4B 59 49 21 1A FF 74 E8 AF 89 C7 0E  ..9.KYI!..t.....
@@ -54,11 +54,11 @@
 CB50:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 CB60:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 CB70:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
-CB80:  00 00 6C 9D 31 12 20 AB C1 4C BD 6C 73 10 E0 11  ..l.1. ..L.ls...
-CB90:  45 A2 B8 0A 1C 3F A5 BF 03 8D 25 F8 B9 21 C4 10  E....?....%..!..
-CBA0:  BA 00 0F 48 F3 00 BB 79 83 08 CD 00 BC C5 A5 75  ...H...y.......u
-CBB0:  0D D0 BD C7 9E 60 19 00 4B 00 CB D1 2D 4E 00 A0  .....`..K...-N..
-CBC0:  0C 29 00 F2 F0 32 5D 00 00 00 00 00 61 07 00 07  .)...2].....a...
+CB80:  00 00 71 F1 B3 86 1E D7 14 38 B8 71 75 10 20 13  ..q......8.qu. .
+CB90:  46 A3 B6 07 59 33 9F 00 7E 8B 60 00 B7 E4 C8 F0  F...Y3..~.`.....
+CBA0:  B8 A2 45 11 0A 10 B9 A5 3F 1C 03 10 0B 00 00 15  ..E.....?.......
+CBB0:  58 0E 9C 00 00 26 04 00 00 20 00 12 CB DB 10 2D  X....&... .....-
+CBC0:  3D 29 00 F2 F0 32 5D 00 00 00 00 00 61 07 00 07  =)...2].....a...
 CBD0:  07 20 20 20 20 20 20 20 63 80 80 42 4C 41 43 4B  .       c..BLACK
 CBE0:  4B 45 59 80 CA 7B 41 5C 00 50 00 20 20 20 20 20  KEY..{A\.P.
 CBF0:  30 80 00 00 00 00 00 00 00 00 00 00 00 00 73 21  0.............s!
```

Something interesting appears at address `ca50`: the characters used for the easter egg display. Let's go through each one of the cross-references for this address:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/eggdis1.png" alt=""/>
</div>

* `FUN_2f3c()` is the main function we saw before, it's just initializing the display with "0/3":
    <div class="c-container-center">
        <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/eggdis2.png" alt=""/>
    </div>
* `FUN_2851()` has 5 references, and guess what, increments `ca50` when the balls counter at `c895` has reached value 5. Since the trace was taken when only one ball was collected, the highlights in one of the references goes up to the branch instruction:
    <div class="c-container-center">
        <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/eggdis3.png" alt=""/>
    </div>
* `FUN_14d7()` has 2 references, and each one leads to the remaining eggs.

## Easter egg 2: Input button sequence

One of the references ends up on an unreached block that compares `c894` with value `0x8` before incrementing the easter egg counter:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/eggdis5.png" alt=""/>
</div>

By following the branch cross-references, there's a block that is checking for player input:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/eggdis6.png" alt=""/>
</div>

With some experimentation, we see that `c894` **increases with a certain sequence of button presses**, but goes back to value 0 otherwise. So we just need to figure out the right sequence, which goes up to 8 buttons. We can use save states by pressing "F7", going back to the last known good state whenever the counter is reset. We get a "2/3" after pressing "Left Right Up Down LCtrl LCtrl LAlt LAlt"!

## Easter egg 3: "Jump-based PRNG"

The last reference points to a partial reached block, where variables `c8b3, c8b4, c8b5` are compared against fixed values. These variables are set in the called `FUN_3577()` and appear to be part of some pseudorandom number generator:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/eggdis4.png" alt=""/>
</div>

These values are updated whenever we jump. Also, `c8b2` appears to be a counter incremented on each jump, but ignored in these checks.

### Solution attempt: Find PRNG win state via constraint solving

So, we can just **patch the PRNG state that comes before the state resulting in the checked values**. With a [Z3 script]({{ site.url }}{{ site.baseurl }}/assets/writeups/0CTF2022/prng.py) to generate it based on `FUN_3577()` we get the solution `ff 8b fb 08`. After patching these values and jumping, the state becomes `00 70 78 bf` and we pass these checks.

The counter now reads "3/3", so we are done right? Not quite... If we run to the flag, we get the message "DONT CHEAT". Most of the time I wasted with these challenges starts right about now!

### Oh, patching the win state doesn't give a unique solution

At first, it wasn't clear what was triggering this anti-cheat. I was fairly confident in the 2nd egg, since it was activated with just input keys. But what if the 1st egg required you to jump before patching the position, in case the game checked if you were in the middle of a jump? What if the 3rd egg required you to patch the state that comes before the win state, in case some intermediate variable was being updated and checked? But none of these variants gave a different result, except one.

Eventually, I tried jumping a different number of times before patching the PRNG state, and **one of the variables checked by the anti-cheat was ending up with different values** on each try.

### Disassembling the anti-cheat

Rather than guessing, let's confirm which variables are being checked and if they are being updated as expected.

If we search for the string "DONT CHEAT", we see it's stored at `253d`. We can search for bytes `25 3d` and find a reference in `FUN_2549()` (it didn't have a cross-reference since it wasn't recognized as a data address):

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/cheatdis1.png" alt=""/>
</div>

`FUN_1470()` likely is the message display function. We see that a stack relative address is used instead of "DONT CHEAT" depending on the value of `c936`. It's a pointer to a table that gets filled at the start of the function with values `0x00..0xff`:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/cheatdis2.png" alt=""/>
</div>

These values are then scrambled using the value of address `ca60`:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/cheatdis3.png" alt=""/>
</div>

If we go back to the disassembly of the 1st easter egg activation, we see this same address being xor'd with value 3 at `2b37`. In fact, all checks manipulate this value, including the PRNG state checks:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/cheatdis4.png" alt=""/>
</div>

So what's going on? Well, there's this variable that is also set:

```
1825 f8 c8 a1        EORB       DAT_c8a1
1828 f7 ca 66        STB        DAT_ca66
```

`c8a1` is a counter also updated by the PRNG. `ca66` is read with a relative offset during the anti-cheat scrambling. We can confirm this by setting a memory read breakpoint with `wp ca66,1,r`, which is hit inside the anti-cheat function:

```
25bd e6 89 ca 60     LDB        DAT_ca60,X
```

This is why our previous patch didn't work, we weren't considering the value of `c8a1`.

### Solution: Keep generating PRNG values via debugger script

What if we just need to, you know, **generate values to win**? That's exactly what we do with the following debugger script. The idea is to break at each of the 3 PRNG state checks, then if the check against register `B` isn't satisfied, we set the program counter back to the PRNG generator call. We also set a breakpoint at `1809` after these checks, just to make sure we eventually stop.

```
>bpset 17f1, (B != 70) ,{pc=178a ; g}
Breakpoint 37 set
>bpset 17fa, (B != 78) ,{pc=178a ; g}
Breakpoint 38 set
>bpset 1803, (B != b7) ,{pc=178a ; g}
Breakpoint 39 set
>bpset 1809
Breakpoint 3A set
```

Eventually...

```
Stopped at breakpoint 3A
>bpclear
Cleared all breakpoints
>go
```

And the PRNG state:

```
C8A0  1F 05 39 00 07 01 01 01 00 00 00 00 01 00 C1 5A   ..9...........�Z
C8B0  60 53 6D 70 78 B7 00 00 07 00 00 39 02 00 20 02   `Smpx�.....9.. .
```

Look at `c8a1`, we had to jump 1337 times... Is this it? Yes, if we run to the flag, we now get the actual second flag!

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/0CTF2022/flag2.png" alt=""/>
</div>
