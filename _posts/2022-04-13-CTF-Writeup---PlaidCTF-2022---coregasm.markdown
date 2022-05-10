---
layout: post
title: CTF Writeup - PlaidCTF 2022 - coregasm
date: 2022-04-13 00:00:00 +0000
tags:
    - ctf
    - reversing
    - file formats
---

{% include custom.html %}

# Introduction

We are given an executable and a core dump generated near the end of its execution. If we run the executable run multiple times, we see that it prints out 4 different flags, so we need to figure out the random bytes that were used to build the flags of the given core dump.

# Description

> When you get a core file, you're usually pretty sad. Hopefully this one makes you happy.

Download: [bin]({{ site.url }}{{ site.baseurl }}/assets/writeups/PlaidCTF2022/coregasm/coregasm), [core]({{ site.url }}{{ site.baseurl }}/assets/writeups/PlaidCTF2022/coregasm/core)

# Analysis

Symbols were not stripped, so we can open Ghidra and jump right into `main()`:

```c
undefined[16] main(undefined8 param_1,char **param_2,undefined8 param_3,ulong param_4) {
  int iVar1;
  ssize_t sVar2;
  uint __line;
  char *__assertion;

  puts("Would you like to see a magic trick?");
  puts("Printing all the flags...");
  fflush((FILE *)0x0);
  iVar1 = open("/dev/urandom",0);
  sVar2 = read(iVar1,globalbuf,0x40);
  if (sVar2 == 0x40) {
    close(iVar1);
    flag4(globalbuf);
    flag3(globalbuf);
    flag2(globalbuf);
    flag1(globalbuf);
    puts("///time for core///");
    fflush((FILE *)0x0);
    iVar1 = strcmp("///time for core///",*param_2);
    if (iVar1 == 0) {
      return ZEXT816(param_4) << 0x40;
    }
    __line = 0xc5;
    __assertion = "strcmp(\"///time for core///\", argv[0]) == 0";
  }
  else {
    __line = 0xbb;
    __assertion = "x == 64";
  }
  __assert_fail(__assertion,"./main.c",__line,(char *)&__PRETTY_FUNCTION__.3855);
}
```

We see that 0x40 random bytes are stored in `globalbuf`, which has address `0x001040a0` (base address `0x00100000` + offset `0x40a0`), located in section `.bss`, so indeed a static / global variable. It is then passed as argument on each flag function call. Each of these functions can be seen as a self-contained task.

We start with `flag1()`, since the global buffer state present in the core dump should reflect the operations done in that last function call.

## Task 1: co

```c
void flag1(ulong *param_1) {
  long i;

  *param_1 = *param_1 ^ 0x80083ed7e794313b;
  param_1[1] = param_1[1] ^ 0x75136ebbbf60734f;
  param_1[2] = param_1[2] ^ 0x6c46a704af4d8380;
  param_1[3] = param_1[3] ^ 0xc1991ab8c1674bbf;
  param_1[4] = param_1[4] ^ 0xdc0b819132401105;
  param_1[5] = param_1[5] ^ 0xaf4464465d7d4dc0;
  param_1[6] = param_1[6] ^ 0x9ead54bd51956632;
  param_1[7] = param_1[7] ^ 0xc4d2c981312f974;
  puts("Flag 1:");
  puts((char *)param_1);
  fflush((FILE *)0x0);
  i = 0;
  do {
    *(byte *)((long)param_1 + i) = *(byte *)((long)param_1 + i) ^ 0xa5;
    i = i + 1;
  } while (i != 0x40);
  return;
}
```

We see that whatever state `flag2()` left in the global buffer, it is xor'd with some constants, a flag is printed, then the buffer is again xor'd with a single byte. Doing the reverse operation should be straightforward, but first we need to find the buffer's bytes in the core dump.

### Solution 1: Finding bytes using surrounding addresses

Let's debug the executable. We place a break at the end of `flag1()`, take note of the random bytes we obtain, then take our own core dump. We should be able to find these bytes, then extrapolate the location in the provided core dump:

```
pwndbg> b *(0x555555554000 + 0x1342)
pwndbg> r
...
pwndbg> x/20wx 0x5555555580a0
0x5555555580a0: 0xa27718b2      0xa583e99c      0xb3fd791d      0x9db0e59c
0x5555555580b0: 0x53ebe960      0xf1d42dd2      0x335f11f8      0xe1bdc001
0x5555555580c0: 0x47b6b7a7      0x21da16a8      0x40a05792      0x15f31778
0x5555555580d0: 0x6a53548b      0xa196f2c5      0x1d003010      0x4c6df0b1
0x5555555580e0: 0x00000000      0x00000000      0x00000000      0x00000000
pwndbg> generate-core-file
```

To find the offset of one of the 64bit words:

```sh
binwalk -R '\xb2\x18\x77\xa2\x9c\xe9\x83\xa5' core.1
# 0x3508
```

Let's look at a hex dump near this offset:

```
000034b0: 5038 e3f7 ff7f 0000 70ef eaf7 ff7f 0000  P8......p.......
000034c0: b650 5555 5555 0000 0000 0000 0000 0000  .PUUUU..........
000034d0: 6880 5555 5555 0000 0000 0000 0000 0000  h.UUUU..........
000034e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000034f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00003500: 0000 0000 0000 0000 b218 77a2 9ce9 83a5  ..........w.....
00003510: 1d79 fdb3 9ce5 b09d 60e9 eb53 d22d d4f1  .y......`..S.-..
00003520: f811 5f33 01c0 bde1 a7b7 b647 a816 da21  .._3.......G...!
00003530: 9257 a040 7817 f315 8b54 536a c5f2 96a1  .W.@x....TSj....
00003540: 1030 001d b1f0 6d4c 0000 0000 0000 0000  .0....mL........
```

Before the 0x40 buffer bytes, there seems to be some addresses for our process image map (base address `0x555555554000`) and also some libc addresses (base address `0x7ffff7dbe000`). The process image base address seems to be present at offset `0x88` in our core dump, and we do find a similar base address at the same offset in the provided core dump (`0x55fa6cf06000`).

Although the buffer is at offset `0x3508` in our core dump, that offset does not match the provided core dump. However, we can expect the buffer to be placed after a similar set of addresses we identify earlier. Let's take the high bytes of the process image base address and check those offsets:

```sh
binwalk -R '\xf0\x6c\xfa\x55' core
```

Eventually we bump into the buffer bytes at `0x30a0`:

```
00003040: 0011 d82e 567f 0000 909c c92e 567f 0000  ....V.......V...
00003050: d03e d12e 567f 0000 e0a1 c92e 567f 0000  .>..V.......V...
00003060: 0000 0000 0000 0000 68a0 f06c fa55 0000  ........h..l.U..
00003070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00003080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00003090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000030a0: f5e6 f1e3 dec7 c4cb c4cb c4fa c7c4 cbc4  ................
000030b0: cbc4 d8a5 8585 8585 8585 8585 8585 8585  ................
000030c0: 8585 8585 8585 8585 8585 8585 8585 8585  ................
000030d0: 8585 8585 8585 8585 8585 8585 8585 8585  ................
```

We can now extract and apply the last xor operation to these bytes:

```python
>>> v = open('core','rb').read()
>>> ''.join([chr(x ^ 0xa5) for x in v[0x30a0 : 0x30a0 + 0x40]])
'PCTF{banana_banana}\x00                                            '
```

Before moving on to the next task, let's calculate the expected buffer bytes when `flag1()` gets called:

```python
v2=b''
v2+=s.pack('>Q', s.unpack('<Q',v[0x8 * 0 : 0x8 * 1])[0] ^ 0x80083ed7e794313b)
v2+=s.pack('>Q', s.unpack('<Q',v[0x8 * 1 : 0x8 * 2])[0] ^ 0x75136ebbbf60734f)
v2+=s.pack('>Q', s.unpack('<Q',v[0x8 * 2 : 0x8 * 3])[0] ^ 0x6c46a704af4d8380)
v2+=s.pack('>Q', s.unpack('<Q',v[0x8 * 3 : 0x8 * 4])[0] ^ 0xc1991ab8c1674bbf)
v2+=s.pack('>Q', s.unpack('<Q',v[0x8 * 4 : 0x8 * 5])[0] ^ 0xdc0b819132401105)
v2+=s.pack('>Q', s.unpack('<Q',v[0x8 * 5 : 0x8 * 6])[0] ^ 0xaf4464465d7d4dc0)
v2+=s.pack('>Q', s.unpack('<Q',v[0x8 * 6 : 0x8 * 7])[0] ^ 0x9ead54bd51956632)
v2+=s.pack('>Q', s.unpack('<Q',v[0x8 * 7 : 0x8 * 8])[0] ^ 0xc4d2c981312f974)
```

A quick and dirty way to check these are the correct bytes is to rerun the executable, breaking before the call at `b *(0x555555554000 + 0x116e)`, then setting the buffer with these bytes, confirming that the flag is printed as expected. To generate gdb commands that set the buffer:

```python
def chunks(lst, n):
   return [lst[i - n : i] for i in range(n, len(lst) + n, n)]

def mapx(x):
    global i
    s=f'set *(char**)($rdi+{i}) = 0x'+x
    i+=8
    return s

i=0
print(*map(mapx, chunks(v2.hex(), 16)), sep='\n')
```

Output:

```
set *(char**)($rdi+0) = 0xee695caca1c0726b
set *(char**)($rdi+8) = 0x147d0fd9e0011d2e
set *(char**)($rdi+16) = 0x4c668724af30e2ee
set *(char**)($rdi+24) = 0xe1b93a98e1476b9f
set *(char**)($rdi+32) = 0xfc2ba1b112603125
set *(char**)($rdi+40) = 0x8f6444667d5d6de0
set *(char**)($rdi+48) = 0xbe8d749d71b54612
set *(char**)($rdi+56) = 0x2c6d0cb83332d954
```

### Solution 2: Reading buffer from core dump in debugger

There's a more direct way to extract the buffer bytes, without having to locate their offset in the file: after finding the process image base address, we can load the core dump in the debugger and just read the bytes at the image base plus the offset of the global buffer:

```
gdb coregasm core
...
pwndbg> x/20wx (0x55fa6cf06000 + 0x40a0)
0x55fa6cf0a0a0: 0xe3f1e6f5      0xcbc4c7de      0xfac4cbc4      0xc4cbc4c7
0x55fa6cf0a0b0: 0xa5d8c4cb      0x85858585      0x85858585      0x85858585
0x55fa6cf0a0c0: 0x85858585      0x85858585      0x85858585      0x85858585
0x55fa6cf0a0d0: 0x85858585      0x85858585      0x85858585      0x85858585
0x55fa6cf0a0e0: 0x00000000      0x00000000      0x00000000      0x00000000
```

## Task 2: re

```c
void flag2(ulong *param_1) {
  FILE *__stream;
  size_t sVar1;
  long i;
  byte otpbuf [64];
  byte otpbuf2 [72];

  __stream = fopen("./otp","r");
  sVar1 = fread(otpbuf,0x80,1,__stream);
  if (sVar1 != 1) {
    __assert_fail("items == 1","./main.c",0x2a,"flag2");
  }
  i = 0;
  do {
    *(byte *)((long)param_1 + i) = *(byte *)((long)param_1 + i) ^ otpbuf[i];
    i = i + 1;
  } while (i != 0x40);
  *param_1 = *param_1 ^ 0x6301641f2866c34b;
  param_1[1] = param_1[1] ^ 0x1eb4def5ac740dcf;
  param_1[2] = param_1[2] ^ 0x4f490b1c93df4671;
  param_1[3] = param_1[3] ^ 0x9f82c6ec691ca0b0;
  param_1[4] = param_1[4] ^ 0xc2d142fcaf5dca6b;
  param_1[5] = param_1[5] ^ 0xfa68305eb42fcb00;
  param_1[6] = param_1[6] ^ 0x62212646a9e04b61;
  param_1[7] = param_1[7] ^ 0xbb73ad9a9992c6b;
  puts("Flag 2:");
  puts((char *)param_1);
  fflush((FILE *)0x0);
  i = 0;
  do {
    *(byte *)((long)param_1 + i) = *(byte *)((long)param_1 + i) ^ otpbuf2[i];
    i = i + 1;
  } while (i != 0x40);
  return;
}
```

This time, xor operations are done with 0x80 bytes read from a file. However, note that the local variables for `./otp` aren't zero'd, so their contents should still be resident in the core dump.

### Solution 1: Bruteforcing for candidates

What do we know about the input? That the first 8 bytes are `0xee695caca1c0726b` (calculated in the previous task), that when xor'd with `0x6301641f2866c34b` and the first 8 bytes of `./otp`, the resulting bytes should contain `PCTF{` in little endian (`0x7b46544350`). We can simply scan the whole core dump for byte patterns that satisfy these conditions:

```python
for i in range(len(v) - 0x8):
    chunk1 = s.unpack("<Q", v[i : i + 0x8])[0]
    candidate = chunk1 ^ 0xEE695CACA1C0726B
    candidate_5c = candidate & 0xFFFFFFFFFF
    if candidate_5c == 0x7B46544350:
        print(hex(i))
        # 0xde4
        # 0xff8
        # 0x54e0
        # 0x53d70
```

Out of these results, offset `0x54e0` seems to be the only one surrounded by 0x80 initialized bytes:

```
000054a0: 1b80 32da 788c 0df2 65c6 a032 97bf da7f  ..2.x...e..2....
000054b0: 1f27 fbf1 7d65 28de d181 7e08 82a7 ec01  .'..}e(...~.....
000054c0: 0a40 10f5 3817 6367 ea4e ba20 7f10 48da  .@..8.cg.N. ..H.
000054d0: 406b c089 6e86 2472 4b0c b989 814c a339  @k..n.$rK....L.9
000054e0: 3b31 94e7 d73e 0880 4f73 60ca bb6e 1375  ;1...>..Os`..n.u
000054f0: 8083 14cd 45e9 0722 fe4a 2580 f65b d780  ....E..".J%..[..
00005500: 5831 4032 9181 0bdc c04d 7d5d 4664 44af  X1@2.....M}]FdD.
00005510: 3266 9551 bd54 ad9e 74f9 1213 982c 4d0c  2f.Q.T..t....,M.
```

Now we extract these bytes and apply the xor operations:

```python
flag1_input_Qs = [
    0xEE695CACA1C0726B,
    0x147D0FD9E0011D2E,
    0x4C668724AF30E2EE,
    0xE1B93A98E1476B9F,
    0xFC2BA1B112603125,
    0x8F6444667D5D6DE0,
    0xBE8D749D71B54612,
    0x2C6D0CB83332D954,
]
flag2_xor_Qs = [
    0x6301641F2866C34B,
    0x1EB4DEF5AC740DCF,
    0x4F490B1C93DF4671,
    0x9F82C6EC691CA0B0,
    0xC2D142FCAF5DCA6B,
    0xFA68305EB42FCB00,
    0x62212646A9E04B61,
    0xBB73AD9A9992C6B,
]

with open(sys.argv[1], "rb") as f:
    v = f.read()

pbuf = 0x54E0
with open('./otp', 'wb') as f:
    f.write(v[pbuf - 0x40 : pbuf + 0x40])

v2 = b""
for i in range(0, 0x40, 8):
    otp1 = s.unpack("<Q", v[pbuf - 0x40 + i : pbuf - 0x40 + i + 0x8])[0]
    otp2 = s.unpack("<Q", v[pbuf + i : pbuf + i + 0x8])[0]

    flag2_Q = flag1_input_Qs[i // 8]
    candidate = otp2 ^ flag2_Q
    v2 += s.pack("<Q", candidate)
    print(
        f'set *(char**)($rbx+{i}) = 0x{ s.pack(">Q", candidate ^ flag2_xor_Qs[i // 8] ^ otp1).hex() }'
    )
print(v2)
```

Output:

```
set *(char**)($rbx+0) = 0xff6d8a1cb4000000
set *(char**)($rbx+8) = 0x00000000b4b5a5cb
set *(char**)($rbx+16) = 0xff00000000000000
set *(char**)($rbx+24) = 0xff00000000000000
set *(char**)($rbx+32) = 0x859275e47a6d8a1c
set *(char**)($rbx+40) = 0x00000001b4b5a5ca
set *(char**)($rbx+48) = 0x3025800800000001
set *(char**)($rbx+56) = 0x1234567800000000
b'PCTF{banana*banana$banana!banana}\x00                              '
```

### Solution 2: Parsing the `./otp` `FILE` structure

Since we are dealing with an open file, the handle should be present in the core dump. It is represented by the [`_IO_FILE` structure](https://sourceware.org/git/?p=glibc.git;a=blob;f=libio/bits/types/struct_FILE.h;h=1eb429888c459fcd443d78fdea4f3c95a026e269;hb=45a8e05785a617683bbaf83f756cada7a4a425b9), which contains the following pointers:

```c
struct _IO_FILE
{
  int _flags;           /* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;   /* Current read pointer */
  char *_IO_read_end;   /* End of get area. */
  char *_IO_read_base;  /* Start of putback+get area. */
  char *_IO_write_base; /* Start of put area. */
  char *_IO_write_ptr;  /* Current put pointer. */
  char *_IO_write_end;  /* End of put area. */
  char *_IO_buf_base;   /* Start of reserve area. */
  char *_IO_buf_end;    /* End of reserve area. */
  /* ... */
}
```

We can use as signature the [magic bytes of field `_flags`](https://sourceware.org/git/?p=glibc.git;a=blob;f=libio/libio.h;h=d0184df878422d7495367007dcbce85d309e2a81;hb=HEAD):

```c
/* Magic number and bits for the _flags field.  The magic number is
   mostly vestigial, but preserved for compatibility.  It occupies the
   high 16 bits of _flags; the low 16 bits are actual flag bits.  */

#define _IO_MAGIC         0xFBAD0000 /* Magic number */
```

Let's find these handles and print out the corresponding pointers:

```python
#!/usr/bin/env python3

import re
import sys
import struct

with open(sys.argv[1], 'rb') as f:
    data = f.read()

matches = [x.start() for x in re.finditer(b'\xad\xfb', data)]
for match in matches:
    offset = match - 2 # include 2 bytes for low-bits of actual flag bits.
    print(hex(offset), [hex(x) for x in struct.unpack('<QQQQQQQQQQQQ', data[offset : offset + 8 * 12])])
```

The first result ends up being the one we are interested in:

```
0x5270 ['0xfbad2488', '0x55fa6d305520', '0x55fa6d305520', '0x55fa6d3054a0', '0x55fa6d3054a0', '0x55fa6d3054a0', '0x55fa6d3054a0', '0x55fa6d3054a0', '0x55fa6d3064a0', '0x0', '0x0', '0x0']
```

Just for fun, we see that `_IO_read_ptr` is at `_IO_read_end`, since we read the full contents, starting at `_IO_read_base` (`0x55fa6d305520 = 0x55fa6d3054a0 + 0x80`). In gdb, we can read the bytes at `_IO_read_base` and confirm they match the ones we saw earlier in the hex dump:

```
pwndbg> x/20gx 0x55fa6d3054a0
0x55fa6d3054a0: 0xf20d8c78da32801b      0x7fdabf9732a0c665
0x55fa6d3054b0: 0xde28657df1fb271f      0x01eca782087e81d1
0x55fa6d3054c0: 0x67631738f510400a      0xda48107f20ba4eea
0x55fa6d3054d0: 0x7224866e89c06b40      0x39a34c8189b90c4b
0x55fa6d3054e0: 0x80083ed7e794313b      0x75136ebbca60734f
0x55fa6d3054f0: 0x2207e945cd148380      0x80d75bf680254afe
0x55fa6d305500: 0xdc0b819132403158      0xaf4464465d7d4dc0
0x55fa6d305510: 0x9ead54bd51956632      0x0c4d2c981312f974
0x55fa6d305520: 0x0000000000000000      0x0000000000000000
0x55fa6d305530: 0x0000000000000000      0x0000000000000000
```

## Task 3: ga

```c
ulong flag3(ulong *param_1) {
  uint uVar0;
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  ulong ulVar1;

  *param_1 = *param_1 ^ 0x2f01d6f7c8701da9;
  param_1[1] = param_1[1] ^ 0x230ed5e2ec453098;
  param_1[2] = param_1[2] ^ 0x2f01dae2ef4a3f97;
  param_1[3] = param_1[3] ^ 0x2301dae2ec45309b;
  param_1[4] = param_1[4] ^ 0x230ed5e2ec4a3f97;
  param_1[5] = param_1[5] ^ 0x2002d5e2ec4a3f97;
  param_1[6] = param_1[6] ^ 0x200ed5e2ef4a3f97;
  param_1[7] = param_1[7] ^ 0x6140948cf3453c97;
  puts("Flag 3:");
  puts((char *)param_1);
  fflush((FILE *)0x0);
  *(int *)((long)param_1 + 0x3c) = 0x12345678;
  uVar1 = *(int *)param_1 + *(int *)((long)param_1 + 4);
  uVar4 = *(int *)(param_1 + 2) - *(int *)((long)param_1 + 0xc);
  ulVar1 = (ulong)*(uint *)(param_1 + 5) / (ulong)*(uint *)((long)param_1 + 0x24);
  *(uint *)(param_1 + 1) = uVar1;
  uVar3 = *(int *)((long)param_1 + 0x1c) * *(int *)(param_1 + 3);
  uVar2 = *(uint *)((long)param_1 + 0x34) ^ *(uint *)(param_1 + 6);
  *(uint *)((long)param_1 + 0x14) = uVar4;
  *(uint *)(param_1 + 4) = uVar3;
  *(uint *)(param_1 + 7) = uVar2;
  uVar0 = (uint)ulVar1;
  *(uint *)((long)param_1 + 0x2c) = uVar0;
  *(uint *)param_1 = uVar1 & uVar4;
  *(uint *)((long)param_1 + 4) = uVar4 | uVar3;
  *(uint *)(param_1 + 2) = uVar0 * uVar2;
  *(int *)((long)param_1 + 0xc) = (int)((ulong)uVar3 % ulVar1);
  *(uint *)(param_1 + 3) = uVar2 / uVar1;
  *(uint *)((long)param_1 + 0x1c) = uVar4 + uVar2;
  *(uint *)((long)param_1 + 0x24) = uVar2 - uVar3;
  *(uint *)(param_1 + 5) = uVar1 ^ uVar0;
  *(uint *)((long)param_1 + 0x34) = uVar1 & uVar3;
  *(int *)(param_1 + 6) = (int)(ulVar1 % (ulong)uVar4);
  return ulVar1 / uVar4;
}
```

If these operations make you think about symbolic execution... well, let's see how that goes.

### Solution attempt: Solving with symbolic execution?

On a [previous writeup](http://nevesnunes.github.io/blog/2021/10/03/CTF-Writeup-TSG-CTF-2021-2-Reversing-Tasks.html), I described the steps in setting up an angr script to run over a set of instructions, without having to start at the binary's entrypoint. The approach here is the same, with the main difference being the constraints: the printed flag should start with `PCTF{`, and we want the `flag2()` input bytes in the global buffer when we arrive at the end of this function.

```python
#!/usr/bin/env python3

from pwn import *
import angr
import claripy
import sys
import struct

BE = angr.archinfo.Endness.BE
LE = angr.archinfo.Endness.LE

start = 0x16CC
end = 0x1757
base = 0x555555554000
addr_flag = 0x5555555580A0


def char(state, c):
    return state.solver.Or(c == 0, state.solver.And(c <= "~", c >= " "))

def apply_constraints(state):
    if state.addr < base + end - 1:
        return False

    flag2_input_Qs = [
        0xFF6D8A1CB4000000,
        0x00000000B4B5A5CB,
        0xFF00000000000000,
        0xFF00000000000000,
        0x859275E47A6D8A1C,
        0x00000001B4B5A5CA,
        0x3025800800000001,
        0x1234567800000000,
    ]
    for i, q in enumerate(flag2_input_Qs):
        expr = state.memory.load(addr_flag + i * 8, 8, endness=BE)
        state.solver.add(expr == struct.pack('<Q', q))

    return state.satisfiable()


def main():
    with open(sys.argv[1], "rb") as f:
        asm = f.read()[start:end+1]

    project = angr.load_shellcode(
        asm,
        "x86_64",
        start_offset=0,
        load_address=base + start,
        support_selfmodifying_code=False,
    )
    state = project.factory.entry_state()

    # Taken at `b *(0x555555554000 + 0x16cc)`
    mems = [
        [0x555555554000, 4],
        [0x555555555000, 5],
        [0x555555556000, 4],
        [0x555555557000, 4],
        [0x555555558000, 6],
        [0x7FFFFFFDC000, 6],
    ]
    for mem_pair in mems:
        addr = mem_pair[0]
        perm = mem_pair[1]
        memory = open(f"out.{hex(addr)}.mem", "rb").read()
        state.memory.store(addr, memory, disable_actions=True, inspect=False)
        state.memory.permissions(addr, perm)

    state.regs.rax = 0x0
    state.regs.rbx = addr_flag
    state.regs.rcx = 0x7FFFF7F8E580
    state.regs.rdx = 0x0
    state.regs.rdi = 0x7FFFF7F844E0
    state.regs.rsi = 0x1
    state.regs.r8 = 0x41
    state.regs.r9 = 0x7FFFF7F81A60
    state.regs.r10 = 0x7FFFF7DD0178
    state.regs.r11 = 0x246
    state.regs.r12 = 0x5555555551C0
    state.regs.r13 = 0x0
    state.regs.r14 = 0x0
    state.regs.r15 = 0x0
    state.regs.rbp = 0x7FFFFFFFC9B8
    state.regs.rsp = 0x7FFFFFFFC8A0
    state.regs.rip = 0x5555555556CC

    sym_data = state.solver.BVS("v1", 0x40*8)
    for c in sym_data.chop(8):
        state.solver.add(char(state, c))
    state.solver.add(sym_data.chop(8)[0] == ord("P"))
    state.solver.add(sym_data.chop(8)[1] == ord("C"))
    state.solver.add(sym_data.chop(8)[2] == ord("T"))
    state.solver.add(sym_data.chop(8)[3] == ord("F"))
    state.solver.add(sym_data.chop(8)[4] == ord("{"))

    state.memory.store(addr_flag, sym_data, disable_actions=True, inspect=False)

    # Sanity checking the start address instruction
    assert project.factory.block(base + start).bytes[0] == 0x31
    assert project.factory.block(base + start).bytes[1] == 0xd2

    queue = [state, ]
    while len(queue) > 0:
        state = queue.pop()
        state2 = state.copy()

        sm = project.factory.simgr(state)
        sm.explore(find=apply_constraints, avoid=lambda s: s.addr > base+end+1)

        for p in sm.active:
            queue.append(p)

        if sm.found:
            for found in sm.found:
                found_flag = found.solver.eval(sym_data, cast_to=bytes)
                print(found_flag)
                print(hex(found.solver.eval(sym_data)))

                # Add found solutions as constraints to the solver, so that
                # we start exploring again but arrive at different solutions.
                more_constraints = []
                for ic in range(64):
                    more_constraints.append(sym_data.chop(8)[ic] == found_flag[ic])
                state2.solver.add(
                    state2.solver.Not(
                        state2.solver.And(
                            *more_constraints
                        )
                    )
                )
            queue.append(state2)

    print(sm)


if __name__ == "__main__":
    main()
```

While we get the expected `PCTF{ban`, we also end up with multiple junk solutions, since our conditions are too unconstrained. At this point, it's better to step back and look for other clues...

### Solution 1: Checking input bytes

If we break right before calling `flag3()`, we notice something odd in the global buffer: the previous function call filled it with the same repeated 64bit pattern:

```
► 0x55555555514f <main+127>    lea    rdi, [rip + 0x2f4a]           <0x5555555580a0>
  0x555555555156 <main+134>    call   flag3                <flag3>

pwndbg> x/10gx 0x5555555580a0
0x5555555580a0 <globalbuf>:     0x41619aa7a689d4f3      0x41619aa7a689d4f3
0x5555555580b0 <globalbuf+16>:  0x41619aa7a689d4f3      0x41619aa7a689d4f3
0x5555555580c0 <globalbuf+32>:  0x41619aa7a689d4f3      0x41619aa7a689d4f3
0x5555555580d0 <globalbuf+48>:  0x41619aa7a689d4f3      0x41619aa7a689d4f3
0x5555555580e0 <flag1ptr>:      0x0000000000000000      0x0000000000000000
```

Since we already know that the flag starts with `PCTF{ban`, we can just xor it with the first constant (`0x2f01d6f7c8701da9`) to get the expected repeated byte pattern. Then we can take that pattern and apply it for the other constants:

```python
>>> hex(struct.unpack('<Q', b'PCTF{ban')[0])
'0x6e61627b46544350'
>>> struct.pack('>Q', 0x6e61627b46544350 ^ 0x2f01d6f7c8701da9).hex()
'4160b48c8e245ef9'
>>> struct.pack('<Q', 0x4160b48c8e245ef9 ^ 0x2f01d6f7c8701da9)
b'PCTF{ban'
>>> struct.pack('<Q', 0x4160b48c8e245ef9 ^ 0x230ed5e2ec453098)
b'anabnanb'
>>> struct.pack('<Q', 0x4160b48c8e245ef9 ^ 0x2f01dae2ef4a3f97)
b'nanannan'
>>> struct.pack('<Q', 0x4160b48c8e245ef9 ^ 0x2301dae2ec45309b)
b'bnabnnab'
>>> struct.pack('<Q', 0x4160b48c8e245ef9 ^ 0x230ed5e2ec4a3f97)
b'nanbnanb'
>>> struct.pack('<Q', 0x4160b48c8e245ef9 ^ 0x2002d5e2ec4a3f97)
b'nanbnaba'
>>> struct.pack('<Q', 0x4160b48c8e245ef9 ^ 0x200ed5e2ef4a3f97)
b'nananana'
>>> struct.pack('<Q', 0x4160b48c8e245ef9 ^ 0x6140948cf3453c97)
b'nba}\x00   '
```

### Solution 2: Checking leftover strings

When calling these flag functions, allocated strings also aren't zero'd, so we can actually find the last part of these flags in the core dump. Running `strings` will bring up this pile of bananas:

```
00004260: 2f2f 2f74 696d 6520 666f 7220 636f 7265  ///time for core
00004270: 2f2f 2f0a 6261 6e61 6e61 7d0a 616e 616e  ///.banana}.anan
00004280: 6121 6261 6e61 6e61 7d0a 6e62 6e61 6e62  a!banana}.nbnanb
00004290: 6e61 6e62 6e61 6261 6e61 6e61 6e61 6e61  nanbnabanananana
000042a0: 6e62 617d 0a00 0000 0000 0000 0000 0000  nba}............
```

If we break `nbnanbnanbnabanananana}` into 64bit chunks, at least two of them could be xor'd with the previously seen constants, resulting in the same input byte sequence, thus hinting at the rest of the flag.

## Task 4: sm

```c
void flag4(ulong *param_1) {
  ushort uVar1;
  uint uVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  long i;

  *param_1 = *param_1 ^ 0xbc019ee23a6bf6bf;
  param_1[1] = param_1[1] ^ 0xe9483020414b589c;
  param_1[2] = param_1[2] ^ 0x217b7d11e6c9a8a3;
  param_1[3] = param_1[3] ^ 0x3b3924ce775a8541;
  param_1[4] = param_1[4] ^ 0x6bbdb2171bad0ec8;
  param_1[5] = param_1[5] ^ 0xb0b0429f1f0242e9;
  param_1[6] = param_1[6] ^ 0x5de514ab5abe8132;
  param_1[7] = param_1[7] ^ 0x50789e90a63c152e;
  puts("Flag 4:");
  puts((char *)param_1);
  fflush((FILE *)0x0);
  dVar9 = (double)((ulong)*(uint *)param_1 | 0x3fff000000000000 |
                  (ulong)*(ushort *)((long)param_1 + 4) << 0x20);
  dVar3 = (double)((ulong)*(uint *)((long)param_1 + 6) | 0x3fff000000000000 |
                  (ulong)*(ushort *)((long)param_1 + 10) << 0x20) + dVar9;
  dVar4 = (double)((ulong)*(uint *)((long)param_1 + 0xc) | 0x3fff000000000000 |
                  (ulong)*(ushort *)(param_1 + 2) << 0x20) + dVar3;
  dVar5 = (double)((ulong)*(uint *)((long)param_1 + 0x12) | 0x3fff000000000000 |
                  (ulong)*(ushort *)((long)param_1 + 0x16) << 0x20) + dVar4;
  dVar6 = (double)((ulong)*(uint *)(param_1 + 3) | 0x3fff000000000000 |
                  (ulong)*(ushort *)((long)param_1 + 0x1c) << 0x20) + dVar5;
  dVar7 = (double)((ulong)*(uint *)((long)param_1 + 0x1e) | 0x3fff000000000000 |
                  (ulong)*(ushort *)((long)param_1 + 0x22) << 0x20) + dVar6;
  uVar2 = *(uint *)((long)param_1 + 0x2a);
  dVar8 = (double)((ulong)*(uint *)((long)param_1 + 0x24) | 0x3fff000000000000 |
                  (ulong)*(ushort *)(param_1 + 5) << 0x20) + dVar7;
  uVar1 = *(ushort *)((long)param_1 + 0x2e);
  i = 0;
  do {
    param_1[i] = (ulong)(((double)((ulong)uVar2 | 0x3fff000000000000 | (ulong)uVar1 << 0x20) + dVar8
                         ) * dVar8 * dVar7 * dVar6 * dVar5 * dVar4 * dVar3 * dVar9);
    i = i + 1;
  } while (i != 8);
  return;
}
```

The decompilation only tells part of the story. There are some floating-point variables being juggled until a final result is stored 8 times in the global buffer. But what's special about these variables?

Let's look in the disassembly for instructions specific to floating-point calculation:

```
00101544 dd 44 24 08     FLD        qword ptr [RSP + local_10]
...
00101566 dd 44 24 08     FLD        qword ptr [RSP + local_10]
0010156a d8 c1           FADD       ST0,ST1
```

Wait, `ST0`? Aren't the used registers usually like `XMM0`?

Usually yes, but there is more than one instruction subset dedicated to floating-point calculations. XMM registers are used by Streaming SIMD Extensions (SSE) instructions. But before those came along, calculations were done with the floating-point unit (FPU) instructions, which uses ST registers.

Is there any reason why these FPU instructions are being used here instead?

Turns out that these registers map to a [stack of 8 extended floating point numbers](https://www.csee.umbc.edu/courses/undergraduate/313/fall04/burt_katz/lectures/Lect12/stack.html). See where this is going? Most likely the stack is also present in the core dump.

Let's see how we can recover the individual values of each float variable:

- We start with a push of the first value (`FLD`);
- Then we push a second value, [sum them and store in ST0](https://c9x.me/x86/html/file_module_x86_id_81.html) (`FLD` + `FADD ST0,ST1`)
    - Repeated 7 times;
- Then we multiply ST1 by ST0, store result in ST1, and pop the register stack (`FMULP`);
    - Repeated 7 times;
- Finally, this result gets copied to all 8 64bit offsets in the global buffer (`FST qword ptr [RBX + RAX*0x8]`);

Intermediate results are persisted in the stack, so we should be to apply these operations in reverse.

Now, regarding how these floats are packed. Since we are dealing with extended precision floats, recall the [difference in precision formats](https://home.deec.uc.pt/~jlobo/tc/artofasm/ch14/ch141.htm):

- **single precision**: 32-bits = one's complement 24-bit mantissa, 8-bit excess-128 exponent
- **double precision**: 64-bits = 53-bit mantissa (with an implied H.O. bit of one), 11-bit excess-1023 exponent, 1-bit sign
- **extended precision**: 80-bits = 64-bit mantissa, 15 bit excess-16383 exponent, 1-bit sign

Therefore, we should expect 10 bytes for each packed float, possibly aligned to 16 bytes with nulls.

Again, we can take our own core dumps before and after some of these operations, take note of the values, and find out how the stack gets changed.

We start with a `diff -u <(xxd core.4a) <(xxd core.4b)` before and after the first store, and we see a value pop up containing the or'd `0x3fff000000000000`:

```diff
 000ae630: 0500 0000 0002 0000 0200 0000 434f 5245  ............CORE
-000ae640: 0000 0000 7f03 0000 0000 0000 0000 0000  ................
-000ae650: 0000 0000 0000 0000 0000 0000 801f 0000  ................
-000ae660: 0000 0000 0000 0000 0000 0000 0000 0000  ................
+000ae640: 0000 0000 7f03 0038 8000 0000 c251 5555  .......8.....QUU
+000ae650: 5555 0000 a8c8 ffff ff7f 0000 801f 0000  UU..............
+000ae660: 0000 0000 00b0 197e b193 96fd ff3f 0000  .......~.....?..
```

The second value is also stored:

```diff
 000ae630: 0500 0000 0002 0000 0200 0000 434f 5245  ............CORE
-000ae640: 0000 0000 7f03 0038 8000 0000 c251 5555  .......8.....QUU
+000ae640: 0000 0000 7f03 0030 c000 0000 c251 5555  .......0.....QUU
 000ae650: 5555 0000 a8c8 ffff ff7f 0000 801f 0000  UU..............
-000ae660: 0000 0000 00b0 197e b193 96fd ff3f 0000  .......~.....?..
-000ae670: 0000 0000 0000 0000 0000 0000 0000 0000  ................
+000ae660: 0000 0000 0028 55c8 a1ce 8ffd ff3f 0000  .....(U......?..
+000ae670: 0000 0000 00b0 197e b193 96fd ff3f 0000  .......~.....?..
```

And the sum is computed:

```diff
 000ae630: 0500 0000 0002 0000 0200 0000 434f 5245  ............CORE
-000ae640: 0000 0000 7f03 0030 c000 0000 c251 5555  .......0.....QUU
+000ae640: 0000 0000 7f03 0030 c000 0000 4855 5555  .......0....HUUU
 000ae650: 5555 0000 a8c8 ffff ff7f 0000 801f 0000  UU..............
-000ae660: 0000 0000 0028 55c8 a1ce 8ffd ff3f 0000  .....(U......?..
+000ae660: 0000 0000 006c 37a3 2931 93fd 0040 0000  .....l7.)1...@..
 000ae670: 0000 0000 00b0 197e b193 96fd ff3f 0000  .......~.....?..
```

After all the sums:

```diff
 000ae630: 0500 0000 0002 0000 0200 0000 434f 5245  ............CORE
-000ae640: 0000 0000 7f03 0030 c000 0000 4855 5555  .......0....HUUU
+000ae640: 0000 0000 7f03 0000 ff00 0000 c251 5555  .............QUU
 000ae650: 5555 0000 a8c8 ffff ff7f 0000 801f 0000  UU..............
-000ae660: 0000 0000 006c 37a3 2931 93fd 0040 0000  .....l7.)1...@..
-000ae670: 0000 0000 00b0 197e b193 96fd ff3f 0000  .......~.....?..
-000ae680: 0000 0000 0000 0000 0000 0000 0000 0000  ................
-000ae690: 0000 0000 0000 0000 0000 0000 0000 0000  ................
-000ae6a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
-000ae6b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
-000ae6c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
-000ae6d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
+000ae660: 0000 0000 004d 6ea9 9e7a 0afc 0240 0000  .....Mn..z...@..
+000ae670: 0000 0000 001e 69b6 7bb9 3adc 0240 0000  ......i.{.:..@..
+000ae680: 0000 0000 0044 d1be 2061 d3bc 0240 0000  .....D.. a...@..
+000ae690: 0000 0000 0091 4e42 d8ca 819d 0240 0000  ......NB.....@..
+000ae6a0: 0000 0000 0012 4ee0 c281 4cfc 0140 0000  ......N...L..@..
+000ae6b0: 0000 0000 0044 f05d a3f0 dfbd 0140 0000  .....D.].....@..
+000ae6c0: 0000 0000 006c 37a3 2931 93fd 0040 0000  .....l7.)1...@..
+000ae6d0: 0000 0000 00b0 197e b193 96fd ff3f 0000  .......~.....?..
```

After all the multiplications:

```diff
 000ae630: 0500 0000 0002 0000 0200 0000 434f 5245  ............CORE
-000ae640: 0000 0000 7f03 0000 ff00 0000 c251 5555  .............QUU
+000ae640: 0000 0000 7f03 203a 8000 0000 2856 5555  ...... :....(VUU
 000ae650: 5555 0000 a8c8 ffff ff7f 0000 801f 0000  UU..............
-000ae660: 0000 0000 004d 6ea9 9e7a 0afc 0240 0000  .....Mn..z...@..
-000ae670: 0000 0000 001e 69b6 7bb9 3adc 0240 0000  ......i.{.:..@..
-000ae680: 0000 0000 0044 d1be 2061 d3bc 0240 0000  .....D.. a...@..
-000ae690: 0000 0000 0091 4e42 d8ca 819d 0240 0000  ......NB.....@..
-000ae6a0: 0000 0000 0012 4ee0 c281 4cfc 0140 0000  ......N...L..@..
-000ae6b0: 0000 0000 0044 f05d a3f0 dfbd 0140 0000  .....D.].....@..
-000ae6c0: 0000 0000 006c 37a3 2931 93fd 0040 0000  .....l7.)1...@..
-000ae6d0: 0000 0000 00b0 197e b193 96fd ff3f 0000  .......~.....?..
+000ae660: 0000 0000 6985 0216 ddf3 258d 1640 0000  ....i.....%..@..
+000ae670: 0000 0000 004d 6ea9 9e7a 0afc 0240 0000  .....Mn..z...@..
+000ae680: 0000 0000 d8b0 c980 5dd2 d2d8 0640 0000  ........]....@..
+000ae690: 0000 0000 6fb3 52ab 83da ed9f 0a40 0000  ....o.R......@..
+000ae6a0: 0000 0000 c770 e749 2de9 cbc4 0d40 0000  .....p.I-....@..
+000ae6b0: 0000 0000 48ba a65d d289 f3c1 1040 0000  ....H..].....@..
+000ae6c0: 0000 0000 6925 d573 3576 da8f 1340 0000  ....i%.s5v...@..
+000ae6d0: 0000 0000 fc90 7fea e49c 7d8e 1540 0000  ..........}..@..
```

Ok, now we have an idea of how this structure is represented. To find it in the provided core dump, we can use the same trick of searching for high-valued image base bytes (`\xf0\x6c\xfa\x55`), or even that `CORE` string we see before the stack. Eventually, we arrive at offset `0xd14`:

```
00000ce0: 0500 0000 0002 0000 0200 0000 434f 5245  ............CORE
00000cf0: 0000 0000 7f03 2000 0000 0000 3676 f06c  ...... .....6v.l
00000d00: fa55 0000 0000 0000 0000 0000 801f 0000  .U..............
00000d10: ffff 0000 004d 011c 58e7 86fa 0240 0000  .....M..X....@..
00000d20: 0000 0000 f5bf 8d80 2bf2 d4d6 0640 0000  ........+....@..
00000d30: 0000 0000 ce05 b0b4 efa3 e39d 0a40 0000  .............@..
00000d40: 0000 0000 639c 8340 af09 5fc1 0d40 0000  ....c..@.._..@..
00000d50: 0000 0000 be52 3872 6f03 70bd 1040 0000  .....R8ro.p..@..
00000d60: 0000 0000 78b5 2c15 b427 208b 1340 0000  ....x.,..' ..@..
00000d70: 0000 0000 8f84 f589 3cc9 0a88 1540 0000  ........<....@..
00000d80: 0000 0000 b3c5 f722 7164 a485 1640 0000  ......."qd...@..
00000d90: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

### Solution

You can find alternative solutions written in C, and for a good reason: unpacking floats is as easy as making some casts out of an unsigned char buffer, so to unpack a float80 (padded to 16 bytes) at index i you just do `*(long double *)&buffer[i * 16]`.

In python, the struct module only supports unpacking floats up to 8 bytes. Then there's the Decimal module, which could be suitable, but I ended up using numpy since it had more direct functions:

```python
#!/usr/bin/env python3

import numpy as np
import struct
import sys

with open(sys.argv[1], "rb") as f:
    v = f.read()

stack_begin = 0xD14
stack = v[stack_begin : stack_begin + 16 * 8]

# Read float128 entries a.k.a. float80 padded to 16 bytes
floats_raw = []
for i in range(8):
    floats_raw += [np.frombuffer(stack[i * 16 : (i + 1) * 16], np.float128)[0]]

# Reverse multiplications
floats1 = []
for i in range(7, 0, -1):
    floats1 += [floats_raw[i] / floats_raw[i - 1]]
floats1 += [floats_raw[0]]

# Reverse sums
floats2 = []
for i in range(7, 0, -1):
    floats2 += [floats1[i] - floats1[i - 1]]
floats2 += [floats1[0]]

for i in range(7, -1, -1):
    sys.stdout.buffer.write(struct.pack("<d", floats2[i])[:-2])  # remove 2 bytes of exponent added in OR operations (0x3fff)
```

Output:

```
PCTF{orange%you&glad$i!didn't^say#banana*again}
```
