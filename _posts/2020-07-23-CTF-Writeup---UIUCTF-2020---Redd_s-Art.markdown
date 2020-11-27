---
layout: post
title: CTF Writeup - UIUCTF 2020 - Redd's Art
date: 2020-07-23 12:18:40 +0100
tags: ctf reversing debugging bruteforce
---

{% include custom.html %}

# Introduction

This solution relies on `pwndbg` to execute relevant functions, while circumventing invalid operations. Although it was possible to solve this task by [adapting the decompiled functions](https://ctftime.org/writeup/22401), I wanted to investigate an approach that relied less on reimplementing the executable's code.

# Description

> Redd has an enticing deal for you. Will you take it?

The [task's executable]({{ site.url }}{{ site.baseurl }}/assets/writeups/UIUCTF2020/ReddsArt) implements a dialog which takes user input, with some branching options. Regardless of our choices, we are always given a fake flag at the end.

# Analysis

The dialog had delays implemented as `usleep()` calls, which I patched to speed up tests:

```diff
- b55:	bf 50 c3 00 00       	mov    $0xc350,%edi
+ b55:	bf 00 00 00 00       	mov    $0x0,%edi
  b5a:	e8 91 fc ff ff       	callq  7f0 <usleep@plt>
```

If obfuscation is applied to executable sections, we might see some invalid instructions. When we dissassemble those sections:

```bash
objdump -d ReddsArt | grep '(bad)'
```

We do find those instructions:

```
 980:	17                   	(bad)
 981:	1e                   	(bad)
[...]
```

With `ghidra`, we find that address `0x973` is the start of this invalid block, right after the end of the previous function (stack frame cleared with `ADD RSP,0x18`, base pointer restored with `POP RBP`, jump to return address with `RET`):

```
0010096c 48 83 c4 18     ADD        RSP,0x18
00100970 5b              POP        RBX
00100971 5d              POP        RBP
00100972 c3              RET
                     DAT_00100973             XREF[5]:     00100a6f(*), 00100a76(*),
                                                           00100a90(R), 00100aa9(W),
                                                           0010168c
00100973 4b              ??         4Bh    K
00100974 56              ??         56h    V
[...]
00100980 17              ??         17h
00100981 1e              ??         1Eh
[...]
00100a58 43              ??         43h    C
00100a59 dd              ??         DDh
                     LAB_00100a5a             XREF[1]:     00101694
00100a5a 55              PUSH       RBP
00100a5b 48 89 e5        MOV        RBP,RSP
00100a5e 48 83 ec 10     SUB        RSP,0x10
```

By following XREF `00100a6f`, we get to a function that starts right after the invalid block (base pointer saved with `PUSH RBP`, stack frame allocated with `SUB RSP,0x10`). Although `ghidra` didn't decompile it, we can select the function block and apply `Context Menu > Create function`. Now it is decompiled to:

```c
void FUN_00100a5a(void) {
  byte bVar1;
  int local_18;

  bVar1 = FUN_0010091a();
  local_18 = 0;
  while (local_18 < 0xe7) {
    (&DAT_00100973)[local_18] = (&DAT_00100973)[local_18] ^ bVar1;
    local_18 = local_18 + 1;
  }
  return;
}
```

So the invalid block is being deobfuscated by this function. With `objdump --section-headers`, we confirm the invalid block is part of section `.text` (starts at `0x810` and ends at `0x810 + 0x742 = 0xf52`, so it contains `0x973..0xa59`):

```
 13 .text         00000742  0000000000000810  0000000000000810  00000810  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
```

With `readelf -a`, we confirm that this section is part of an executable segment (flag = `E`) of type `LOAD`:

```
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000001f8 0x00000000000001f8  R      0x8
  INTERP         0x0000000000000238 0x0000000000000238 0x0000000000000238
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000001998 0x0000000000001998  R E    0x200000
[...]
 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash
          .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt
          .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame
[...]
```

Note that the segment isn't writable, yet the deobfuscation function is writing to it. **A segmentation fault will occur when the memory gets written**. Since the program ends without `SIGSEGV`, we can be sure the function isn't called in the normal execution flow.

Nevertheless, it is possible to call it directly with `gdb`.

## Finding an address to jump from

`readelf -a` informs us that this is a dynamically linked position independent executable, starting at `0x810`:

```
Entry point address:               0x810
[...]
Dynamic section at offset 0x1d98 contains 27 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 [...]
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
```

Therefore, we should run the process until all the shared libraries have been loaded, so no sooner than the start of `main`. That symbol was stripped, so we need to figure out that address. We need to **map section offsets to the process address space**, taking into account that the executable is position independent.

`gdb` [disables ASLR by default](https://visualgdb.com/gdbreference/commands/set_disable-randomization), so addresses are consistent between runs. We retrieve the mappings by first running up to the first instruction (using `starti` or `b *0` + `r`) then `info proc map`:

```
   Start Addr           End Addr       Size     Offset objfile
0x555555554000     0x555555556000     0x2000        0x0 ReddsArt2
0x555555755000     0x555555757000     0x2000     0x1000 ReddsArt2
```

While `starti` puts us in the dynamic linker loading routine (before `CALL _dl_start`), the entrypoint `0x810` puts us in the libc loading routine (before `CALL __libc_start_main`). We can break with `b *(0x555555554000 + 0x810)`, but we still need to advance a bit until `main` is called:

```
0x7ffff7ddd040 <__libc_start_main+240>    call   rax       <0x555555554bea>
```

## Enabling writes in executable segment

At runtime, the libc function `mprotect` can be called to change the access protections of segments, which are divided in pages. Therefore, we call it with the 4k page-aligned address we want to write to, along with bit mask `7` to set `RWX`:

```gdb
p (int)mprotect((0x555555554000 + 0x973) - (0x555555554000 + 0x973)%4096, 4096, 7)
```

On success, it returns `0`.

## Calling deobfuscation function

Let's jump to it by setting the instruction pointer to it's start address, then breaking before it ends, validating if the deobfuscation worked:

```gdb
set $rip = (0x555555554000 + 0xa5a)
b *(0x555555554000 + 0xab8)
c
disassemble /r (0x555555554000 + 0x973),(0x555555554000 + 0x973 + 0xe7)
```

We should see valid instructions:

```
Dump of assembler code from 0x555555554973 to 0x555555554a5a:
   0x0000555555554973:  55      push   rbp
   0x0000555555554974:  48 89 e5        mov    rbp,rsp
   0x0000555555554977:  53      push   rbx
   0x0000555555554978:  48 83 ec 28     sub    rsp,0x28
   0x000055555555497c:  48 c7 45 e8 09 00 00 00 mov    QWORD PTR [rbp-0x18],0x9
   0x0000555555554984:  48 8b 45 e8     mov    rax,QWORD PTR [rbp-0x18]
[...]
```

Using the [Python API](https://sourceware.org/gdb/onlinedocs/gdb/Python-API.html) of `gdb`, we can take these instructions from the process memory and write them to a new executable.

Here's a [script]({{ site.url }}{{ site.baseurl }}/assets/writeups/UIUCTF2020/reddsart_deobfuscate_instructions.py) with all these commands put together, that generates a [new executable]({{ site.url }}{{ site.baseurl }}/assets/writeups/UIUCTF2020/ReddsArt_no_delays_deobfuscated) with the deobfuscated block. Run with `gdb -x $script $executable`:

```python
import gdb
import os
import stat

# start of main
gdb.execute("b *(0x555555554000 + 0xBEA)")
gdb.execute("r")

# enable writes on obfuscated block
aligned_addr = (0x555555554000 + 0x973) - (0x555555554000 + 0x973) % 4096
gdb.execute("p (int)mprotect({}, 4096, 7)".format(aligned_addr))

# goto start of deobfuscator function
gdb.execute("set $rip = (0x555555554000 + 0xA5A)")
gdb.execute("b *(0x555555554000 + 0xAB8)")
gdb.execute("c")

# validate deobfuscated instructions
gdb.execute("disassemble /r (0x555555554000 + 0x973),(0x555555554000 + 0x973 + 0xE7)")

i = gdb.inferiors()[0]
m = i.read_memory(0x555555554000 + 0x973, 0xE7)

process_name = os.path.basename(gdb.current_progspace().filename)
with open(process_name, "rb") as f:
    process_bytes = bytearray(f.read())
process_bytes[0x973 : 0x973 + 0xE7] = m.tobytes()
process_name += "_deobfuscated"
with open(process_name, "wb") as f:
    f.write(process_bytes)
os.chmod(process_name, os.stat(process_name).st_mode | stat.S_IEXEC)

gdb.execute("q")
```

The invalid block was converted to a function, which is decompiled to:

```c
void FUN_00100973(void) {
  char cVar1;
  byte bVar2;
  size_t sVar3;
  int local_2c;
  int local_28;

  cVar1 = *(char *)((long)DAT_00000009 + 9);
  local_2c = 0;
  while( true ) {
    sVar3 = strlen(PTR_s_hthzgubI_00302028);
    if (sVar3 <= (ulong)(long)local_2c) break;
    PTR_s_hthzgubI_00302028[local_2c] = PTR_s_hthzgubI_00302028[local_2c] + cVar1;
    local_2c = local_2c + 1;
  }
  bVar2 = FUN_0010091a();
  local_28 = 0;
  while( true ) {
    sVar3 = strlen(PTR_s_hthzgubI_00302028);
    if (sVar3 <= (ulong)(long)local_28) break;
    PTR_s_hthzgubI_00302028[local_28] = PTR_s_hthzgubI_00302028[local_28] ^ bVar2;
    local_28 = local_28 + 1;
  }
  return;
}
```

It is manipulating a string which could be the real flag. Let's break down this function:

- Takes the value at address `0x9` (which is outside valid offsets) and stores in `cVar1`;
- Iterates through `PTR_s_hthzgubI`, storing at each index the sum of the read char with `cVar1`;
- Takes the value of call `FUN_0010091a()` and stores in `cVar2`;
- Iterates through `PTR_s_hthzgubI`, storing at each index the xor of the read char with `cVar2`.

## Deobfuscating the flag

Our approach here will be similar: we jump to the start, enable writes in the page that contains `PTR_s_hthzgubI`, and inspect the results at the end with a breakpoint. However, we also need to deal with the invalid read for `cVar1`. We have no idea which value should be here, besides that it is a `char`, so between 0 and 255. To handle this case:

- break at the invalid read, assign a candidate value to `cVar1`, then skip the original read and store;
- at the end of the function, if we don't get the flag, jump back to the start and try another candidate.

It is important to **restore the memory state when jumping back**, otherwise we would be reusing the previous values of `PTR_s_hthzgubI` during the candidate loop! This implies making a backup of the real flag bytes.

{::options parse_block_html="true" /}
<div class="c-indirectly-related">
One point that confused me was the call to `FUN_0010091a`, which is decompiled to:

```c
ulong FUN_0010091a(void) {
  size_t sVar1;
  uint local_20;
  int local_1c;

  local_20 = 0;
  local_1c = 0;
  while( true ) {
    sVar1 = strlen(PTR_s_uiuctf{v3Ry_r341_@rTT}_00302010);
    if (sVar1 <= (ulong)(long)local_1c) break;
    local_20 = local_20 + (int)(char)PTR_s_uiuctf{v3Ry_r341_@rTT}_00302010[local_1c];
    local_1c = local_1c + 1;
  }
  return (ulong)local_20;
}
```

The return value is `ulong`, yet on the caller it is used for an xor operation with a `char`. Wouldn't this be an issue? Not at all, let's look at the caller dissassembly:

```
001009f7  CALL  FUN_0010091a
001009fc  MOV   dword ptr [RBP + local_24],EAX
[...]
00100a1a  MOV   EAX,dword ptr [RBP + local_24]
00100a1d  MOV   ESI,EAX
00100a1f  MOV   RDX,qword ptr [PTR_s_hthzgubI>*ww7>z+Ha,m>W,7z
00100a26  MOV   EAX,dword ptr [RBP + local_28]
00100a29  CDQE
00100a2b  ADD   RAX,RDX
00100a2e  XOR   ECX,ESI
00100a30  MOV   EDX,ECX
00100a32  MOV   byte ptr [RAX],DL=>s_hthzgubI>*ww7>z+Ha,m>W,7z
```

While the `ulong` result is stored on `RBP + local_24` and then used in the xor as `ESI`, only the low 8-bits are considered for the target string.
</div>
{::options parse_block_html="false" /}

Wrapping it all up in a `gdb` [script]({{ site.url }}{{ site.baseurl }}/assets/writeups/UIUCTF2020/reddsart_solution.py), which includes the deobfuscation from the previous script:

```python
import gdb
import os
import re

# start of main
gdb.execute("b *(0x555555554000 + 0xBEA)")
gdb.execute("r")

# enable writes on obfuscated block (0x973) and string `PTR_s_hthzgubI` (0xFC0)
aligned_addr = (0x555555554000 + 0x973) - (0x555555554000 + 0x973) % 4096
gdb.execute("p (int)mprotect({}, 4096, 7)".format(aligned_addr))

# run deobfuscator function
gdb.execute("set $rip = (0x555555554000 + 0xA5A)")
gdb.execute("b *(0x555555554000 + 0xAB8)")
gdb.execute("c")

# backup obfuscated string
i = gdb.inferiors()[0]
original_obf_str = i.read_memory(0x555555554000 + 0xFC0, 30)

# invalid address store
gdb.execute("b *(0x555555554000 + 0x97C)")

# end of deobfuscated function (before freeing stack frame)
gdb.execute("b *(0x555555554000 + 0xA52)")

# goto start of deobfuscated function
gdb.execute("set $rip = (0x555555554000 + 0x973)")

for candidate in range(0, 256):
    gdb.execute("c")

    # store our candidate
    gdb.execute("set $rax = {}".format(candidate))

    # skip invalid memory read and stores
    gdb.execute("set $rip = (0x555555554000 + 0x99A)")
    gdb.execute("c")

    # verify if candidate generates flag
    try:
        result = bytearray(i.read_memory(0x555555554000 + 0xFC0, 30))
        print("result = {}".format(result))
        if re.search("uiuctf".encode(), result):
            gdb.execute("q")
            exit()
    except Exception as e:
        print(e)
    finally:
        # undo memory changes, then try next candidate
        i.write_memory(0x555555554000 + 0xFC0, original_obf_str, 30)
        gdb.execute("set $rip = (0x555555554000 + 0x97C)")
```

When we run it, we get the flag:

```
[...]
Breakpoint 3, 0x0000555555554a52 in ?? ()
=> 0x0000555555554a52:  90      nop
result = bytearray(b'uiuctf{R_3dd$_c0Uz1n_D1$c0unT}')
```
