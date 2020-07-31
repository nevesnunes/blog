---
layout: post
title: CTF Writeup - CyBRICS 2020 - Hide and Seek
date: 2020-07-30 22:17:06 +0100
tags: ctf reversing debugging cryptography
---

{% include custom.html %}

# Introduction

An executable with a few interesting twists. I've combined static analysis in `ghidra` with dynamic analysis in `pwndbg` to explore an anti-debugging check and self-modifying code hidden in addresses not assigned to a segment. In the end, there's also a tidbit of AES-CBC crypto to recover the flag.

# Description

> Help me find the valid key!

[Download]({{ site.url }}{{ site.baseurl }}/assets/writeups/cybrics2020/hide_and_seek)

There's a simple password prompt, returning a failure message on mismatch.

# Analysis

In `ghidra` we can select `Search > For strings...`, take the entry for prompt "Hi! enter password:" and follow its cross-reference to arrive at this decompiled function:

```c
undefined8 FUN_0014d0bf(void) {
  char cVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Hi! enter password:");
  fgets(local_118,0x100,stdin);
  cVar1 = FUN_00100751(local_118);
  if (cVar1 != '\0') {
    cVar1 = FUN_00105988(local_118);
    if (cVar1 != '\0') {
      cVar1 = FUN_0010aac0(local_118);
      if (cVar1 != '\0') {
        cVar1 = FUN_0010fcda(local_118);
        if (cVar1 != '\0') {
          cVar1 = FUN_00114eac(local_118);
          if (cVar1 != '\0') {
            cVar1 = FUN_0011a03d(local_118);
            if (cVar1 != '\0') {
              cVar1 = FUN_0011f168(local_118);
              if (cVar1 != '\0') {
                cVar1 = FUN_00124301(local_118);
                if (cVar1 != '\0') {
                  cVar1 = FUN_0012946a(local_118);
                  if (cVar1 != '\0') {
                    cVar1 = FUN_0012e63b(local_118);
                    if (cVar1 != '\0') {
                      cVar1 = FUN_001337af(local_118);
                      if (cVar1 != '\0') {
                        puts("WIN!");
                        uVar2 = 1;
                        goto LAB_0014d209;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  puts("FAIL");
  uVar2 = 0;
LAB_0014d209:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```

There's a sequence of conditional statements with function calls containing input string checks such as:

```c
if ((((((((char)(param_1[0x1c] * '&' +
    param_1[0x1b] * -0x1d +
    (char)((int)*param_1 << 6) + param_1[1] * -0x5f + param_1[2] * -0x7b +
    param_1[3] * -0x31 + param_1[4] * '\x0e' + param_1[5] * -0x6d + param_1[6] * -0x7a
    + param_1[7] * '\x05' + param_1[8] * -0x29 + param_1[9] * -0x50 +
    param_1[10] * '\x1b' + param_1[0xb] * 'T' + param_1[0xc] * -0x39 +
    param_1[0xd] * 'u' + param_1[0xe] * -0x77 + param_1[0xf] * '\x1d' +
    param_1[0x10] * 'G' + param_1[0x11] * '\x1c' + param_1[0x12] * -0x24 +
    param_1[0x13] * -0x79 + param_1[0x14] * -0x5e + param_1[0x15] * -0x56 +
    param_1[0x16] * -0x49 + param_1[0x17] * -0x24 + param_1[0x18] * '_' +
    param_1[0x19] * 'n' + param_1[0x1a] * '\r') == '{') &&
// [...]
```

If your first instinct is to look at this and think "oh, equations, time to crank some symbolic execution in `angr`", you will hit a <span class="c-badge c-badge-nok">dead end</span>. Even if you do find a solution, it is actually a fake flag, because there are more code paths we aren't aware of...

---

Let's analyze it from a higher level, starting with `file`:

```
hide_and_seek: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=14dcf449639c988f0887a283626449d6156208be, stripped
```

Check linked libraries with `ldd`:

```
linux-vdso.so.1 (0x00007ffdf75e3000)
libc.so.6 => /lib64/libc.so.6 (0x00007fdf1af49000)
/lib64/ld-linux-x86-64.so.2 (0x00007fdf1b3b1000)
```

Check system calls with `strace`. To trim out boilerplate, such as dynamic linker initialization, we can compile a simple program in c:

```c
char *p = "A";
int main() {
    return p[0];
}
```

And compare it against our task's executable:

```bash
gcc -O0 simple_alloc.c -o simple_alloc
strace ./simple_alloc > strace-simple_alloc.out
strace ./hide_and_seek > strace-hidenseek.out
```

Filter out all lines from the task's executable that are present in "simple_alloc":

```bash
awk '
BEGIN { FS="" }
(NR==FNR) { ll1[FNR]=$0; nl1=FNR; }
(NR!=FNR) { ss2[$0]++; }
END {
    for (ll=1; ll<=nl1; ll++) if (!(ll1[ll] in ss2)) print ll1[ll]
}
' strace-hidenseek.out strace-simple_alloc.out
```

Which results in these calls:

```strace
execve("./hide_and_seek", ["./hide_and_seek"], 0x7fffffffdd80 /* 71 vars */) = 0
brk(NULL)                               = 0x5555557a7000
mprotect(0x5555557a1000, 4096, PROT_READ) = 0
open("/proc/self/status", O_RDONLY)     = 3
read(3, "Name:\thide_and_seek\nUmask:\t0002\n"..., 1024) = 1024
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 6), ...}) = 0
brk(NULL)                               = 0x5555557a7000
brk(0x5555557c8000)                     = 0x5555557c8000
write(1, "Hi! enter password:\n", 20)   = 20
fstat(0, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 6), ...}) = 0
read(0, "\n", 1024)                     = 1
write(1, "FAIL\n", 5)                   = 5
exit_group(0)                           = ?
+++ exited with 0 +++
```

As we can see, a program doesn't usually open file `/proc/self/status`, so we should inspect where this call was made. With `strace -k`, we also get a stack trace with addresses:

```strace
open("/proc/self/status", O_RDONLY)     = 3
 > hide_and_seek() [0x4d896]
 > hide_and_seek() [0x4d6f6]
 > unexpected_backtracing_error [0xc0]
read(3, "Name:\thide_and_seek\nUmask:\t0002\nState:\tR (running)\nTgid:\t5501\nNgid:\t0\nPid:\t5501\nPPid:\t5499\nTracerPid:\t5499\n[...]", 1024) = 1024
 > hide_and_seek() [0x4d8fc]
 > hide_and_seek() [0x4d6f6]
```

Get the file offset for these addresses with `readelf -a`:

```
[Nr] Name              Type             Address           Offset
     Size              EntSize          Flags  Link  Info  Align
[...]
[18] .eh_frame         PROGBITS         000000000004d380  0004d380
     0000000000000308  0000000000000000   A       0     0     8
[19] .eh_frame         PREINIT_ARRAY    000000000024dd80  0004dd80
     0000000000000008  0000000000000008  WA       0     0     8
```

Hold on... it appears these addresses aren't part of `.text`, or any other section. Address `0x4d6f6` falls between `0x4d380 + 0x308 = 0x4d688` and `0x4dd80`. Disassemblers won't analyze these addresses since they aren't mapped to any section.

But how did they get called in the first place? Let's try to break at any `open()`, with verbose logging enabled for the dynamic linker:

```bash
gdb -ex 'set environment LD_DEBUG=all' -ex 'catch syscall open' -ex 'r' hide_and_seek
```

Before our breakpoint is hit, we get the following log message:

```
calling preinit: hide_and_seek
```

From the [documentation of this section type](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html#special_sections):

> SHT_PREINIT_ARRAY - This section contains an array of pointers to functions that are invoked before all other initialization functions

With the section address from `readelf -a`, we can inspect it under `ghidra` at `0x100000 + 0x24dd80 = 0x34dd80`:

```
//
// .eh_frame 
// SHT_PREINIT_ARRAY  [0x24dd80 - 0x24dd87]
// ram: 0034dd80-0034dd87
//
**************************************************************
* Common Information Entry                                   *
**************************************************************
cie_0034dd80                        XREF[3]:     001000f8(*), 00100210(*), 
                                                 _elfSectionHeaders::000004d0(*)  
0034dd80 90 d6 14 00     ddw        14D690h     (CIE) Length
0034dd84 00 00 00 00     ddw        0h          (CIE) ID
```

We can confirm that pointer `0x4D690` is a reference right to the beginning of the address range without an assigned section.

To disassemble this code, the usual workaround is to open the file in "raw format":

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/cybrics2020/ghidra1.png" alt=""/>
</div>

Another way is to define a new section under window "Memory Map > Add a new block to memory", which overlays the addresses we are interested in:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/cybrics2020/ghidra2.png" alt=""/>
</div>

Which are then manually analyzed:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/cybrics2020/ghidra3.png" alt=""/>
</div>

Here's the decompiled function that calls `open()` and `read()`:

```c
undefined[16] FUN_my_text__0014d7a3(void) {
  undefined8 uVar1;
  undefined8 uVar2;
  uint local_584;
  char *local_580;
  undefined8 auStack1216 [21];
  char local_418 [1040];
  
  syscall();
  uVar2 = 0x400;
  syscall();
  local_580 = local_418;
  while ((*local_580 != '\0' &&
         ((((*local_580 != 'T' || (local_580[1] != 'r')) || (local_580[2] != 'a')) ||
          (local_580[3] != 'c'))))) {
    local_580 = local_580 + 1;
  }
  if (*local_580 != '\0') {
    local_580 = local_580 + 10;
    while ((*local_580 == ' ' || (*local_580 == '\t'))) {
      local_580 = local_580 + 1;
    }
    if ((*local_580 != '0') && (local_580[1] != '\n')) {
      uVar1 = 0;
      goto LAB_my_text__0014daf6;
    }
  }
  local_584 = 0;
  while (local_584 < 0xf) {
    auStack1216[(int)local_584] = 0;
    local_584 = local_584 + 1;
  }
  syscall();
  uVar2 = 0;
  uVar1 = 1;
LAB_my_text__0014daf6:
  return CONCAT88(uVar2,uVar1);
}
```

If we look at the conditional in the while loop, it takes the read content and tries to match with prefix 'Trac'. We only get a single match if we validate the status file of our shell with `cat /proc/self/status | grep Trac`:

```
TracerPid:      0
```

This field contains the [PID of process tracing the current process](https://man7.org/linux/man-pages/man5/proc.5.html), which is the case with debuggers. We can verify this with `gdb -batch -ex 'r /proc/self/status' cat 2>/dev/null | grep Trac`:

```
TracerPid:      434698
```

And also with `strace cat /proc/self/status 2>/dev/null | grep Trac`:

```
TracerPid:      434754
```

The decompilation seems to have some issues at the end, but we can tell from the caller function that it checks the return value of this function, and executes some additional system calls if it's not `0`, which is the case when it didn't detect a debugger:

```c
void UndefinedFunction_0014d698(void) {
  long lVar1;
  long *plVar2;
  long *plVar3;
  long in_stack_00000000;

  plVar2 = (long *)(in_stack_00000000 + -0x10);
  plVar3 = (long *)((long)plVar2 - *(long *)((long)plVar2 + *plVar2));
  lVar1 = *(long *)((long)plVar2 + *plVar2) + 8 + (long)plVar3;
  lVar1 = FUN_my_text__0014d7a3(lVar1 + 0x47c,lVar1 + 0x556);
  if (lVar1 != 0) {
    syscall();
    syscall();
    syscall();
    syscall();
    _DAT_100000008 = plVar3 + 0x49c04;
    _DAT_100000000 = plVar3;
  }
  return;
}
```

The assembly address where the value is set is `0x4d9cc`:

```
0014d9c5 0f b6 00        MOVZX      EAX,byte ptr [RAX]
0014d9c8 3c 0a           CMP        AL,0xa
0014d9ca 74 0a           JZ         LAB_my_text__0014d9d6
0014d9cc b8 00 00        MOV        EAX,0x0
         00 00
0014d9d1 e9 20 01        JMP        LAB_my_text__0014daf6
         00 00
```

To bypass this anti-debugging check, we want to take the jump before it, which can be done in `gdb`:

```gdb
b *(0x555555554000 + 0x4d9ca)
r
set $rip = 0x5555555a19d6
```

It is easier to follow system calls with `pwndbg`, as both name and arguments get resolved, based on [calling conventions](https://man7.org/linux/man-pages/man2/syscall.2.html). After taking the jump, the following system call is executed:

```
0x5555555a1aa2    syscall <SYS_rt_sigaction>
        rdi: 0xb
        rsi: 0x7fffffffcb48 —▸ 0x5555555a1b0c ◂— push   rbp
        rdx: 0x0
        r10: 0x8
```

Which [sets a signal handler](https://man7.org/linux/man-pages/man2/sigaction.2.html), where [`0xb = SIGSEGV`](https://sourceware.org/git/?p=glibc.git;a=blob;f=bits/signum-generic.h;hb=0ad926f34937f7b4843a8b49e5d93199601fe324). But when would it be triggered? Let's look at the caller function's system calls, which will now be executed:

```
syscall <SYS_mprotect>
    addr: 0x555555554000 ◂— jg     0x555555554047
    len: 0x1000
    prot: 0x3
syscall <SYS_mprotect>
    addr: 0x555555555000 ◂— add    al, byte ptr [rcx]
    len: 0x1000
    prot: 0x3
syscall <SYS_mprotect>
    addr: 0x555555556000 ◂— mov    eax, dword ptr [rbp - 8]
    len: 0x1000
    prot: 0x3
syscall <SYS_mmap>
    addr: 0x100000000
    len: 0x1000
    prot: 0x3
    flags: 0x22
    fd: 0xffffffff
    offset: 0x0
```

Note that `prot: 0x3` sets bits [`PROT_READ | PROT_WRITE`](https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/bits/mman-linux.h.html). With `readelf -a`, we know that the entrypoint is at `0x640`, which is contained in range `0x555555554000..0x555555554000 + 0x1000`. So, as soon as this functions returns, and the dynamic linker initialization ends, the entrypoint will be executed and a `SIGSEGV` will be thrown, due to this address not having execution permission. Therefore, the signal handler that was defined earlier will be called.

If we look at the handler's source, identified by taking the address passed as argument to `rt_sigaction`:

```c
void FUN_my_text__0014db0c(undefined8 param_1,long param_2) {
  int local_68;
  byte *local_60;
  byte *local_58;

  local_60 = (byte *)(*(ulong *)(param_2 + 0x10) & 0xfffffffffffff000);
  syscall();
  local_58 = local_60 + (_DAT_100000008 - _DAT_100000000);
  local_68 = 0;
  while (local_68 < 0x1000) {
    *local_60 = *local_60 ^ *local_58;
    local_60 = local_60 + 1;
    local_58 = local_58 + 1;
    local_68 = local_68 + 1;
  }
  return;
}
```

That syscall enables full protections at the virtual base address:

```
0x5555555a1b5d    syscall <SYS_mprotect>
     addr: 0x555555554000 ◂— 0x10102464c457f
     len: 0x1000
     prot: 0x7
```

We see that it's modifying some memory region by xor-ing it with values from another region. With the following `gdb` script, we are able to break at this point and inspect the values of these locals:

```gdb
b *(0x555555554000 + 0x4d9ca)
r
# bypass anti-debugging check
set $rip = 0x5555555a19d6
b *(0x555555554000 + 0x640)
# allow program to handle this signal
handle SIGSEGV nostop noprint pass
# continue inside memory manipulation function
c
b *(0x555555554000 + 0x4dbc4)
# continue until xor instruction
c
```

```
pwndbg> x/2w ($rbp - 0x58)
0x7fffffffcad8: 0x55554000      0x00005555
pwndbg> x/2w ($rbp - 0x50)
0x7fffffffcae0: 0x557a2020      0x00005555
```

To sum it up, the handler modifies a 4k page starting at the virtual base address of the executable, which will contain the entrypoint, using values starting at `0x5555557a2020 - 0x555555554000 = 0x24e020`. Since the executable protection was restored at the virtual base address, when the signal handler returns back to `0x640`, execution can resume without segmentation violations, this time with new code! We just unwrapped a self-modifying code routine.

We can now take the new code and store as a new executable, to decompile it and so on, but it appears that doing it under a debugger makes the routine end prematurely at address `0x1000`. I decided to not look deeper into it and just take the static approach, since we already know all the addresses involved:

```python
#!/usr/bin/env python3

import os
import stat
import sys
import ipdb


process_name = os.path.basename(sys.argv[1])
with open(process_name, "rb") as f:
    process_bytes = bytearray(f.read())

a = 0x640
# Offset taken from `readelf -a`:
# [24] .data             PROGBITS         000000000024e000  0004e000
blob = 0x4E020 + 0x640
with ipdb.launch_ipdb_on_exception():
    for i in range(4096 * 3):
        process_bytes[a + i] = (process_bytes[a + i] & 0xff) ^ (process_bytes[blob + i] & 0xff)

process_name += "_static_deobfuscated"
with open(process_name, "wb") as f:
    f.write(process_bytes)
os.chmod(process_name, os.stat(process_name).st_mode | stat.S_IEXEC)
```

We now stumble upon a very different entrypoint function:

```c
void entry(void) {
  long lVar1;
  undefined8 uVar2;
  
  FUN_00100891();
  _DAT_100000010 = FUN_00100d72();
  lVar1 = FUN_00100973(_DAT_100000010,0x100);
  if (lVar1 != 0) {
    lVar1 = FUN_00100c4c(_DAT_100000010);
    if ((lVar1 != 0) && (lVar1 = FUN_00100a96(), -1 < lVar1)) {
      _DAT_100000018 = lVar1;
      _DAT_100000020 = FUN_00100d72();
      _DAT_100000028 = FUN_00100a02(_DAT_100000018,_DAT_100000020,0x100);
      FUN_00100b25(_DAT_100000018);
      if ((_DAT_100000028 != 0) && (lVar1 = FUN_00100949(_DAT_100000020), lVar1 == 0x20)) {
        _DAT_100000030 = FUN_00100d99();
        _DAT_100000038 = FUN_00100f2f(_DAT_100000030);
        uVar2 = FUN_00100949(_DAT_100000010,_DAT_100000010);
        FUN_00100f41(_DAT_100000038,_DAT_100000010,uVar2);
        lVar1 = FUN_00100f5b(_DAT_100000038,_DAT_100000010,0x200);
        if (lVar1 == 0x14) {
          _DAT_100000040 = FUN_00101109();
          FUN_001012bf(_DAT_100000040,0x117,1);
          _DAT_100000048 = FUN_00100f2f(_DAT_100000040);
          FUN_001012c7(_DAT_100000048,_DAT_100000020,0x10);
          FUN_001012c7(_DAT_100000048,_DAT_100000020 + 0x10,0x10);
          lVar1 = FUN_00101467(_DAT_100000020);
          if ((lVar1 != 0) && (lVar1 = FUN_00101530(_DAT_100000020 + 0x10), lVar1 != 0)) {
            FUN_00100b54();
            goto LAB_0010088a;
          }
        }
      }
    }
    FUN_00100bd0();
  }
LAB_0010088a:
  syscall();
  syscall();
  return;
}
```

Many of these function calls contain boilerplate for syscalls. To set all the breakpoints for them, I took the disassembly and matched all syscall instructions, generating the corresponding commands:

```bash
objdump -d hide_and_seek_static_deobfuscated | awk '
    /syscall/{
        print "b *(0x555555554000 + 0x" substr($1, 0, length($1) - 1) ")"
    }'
```

To follow them with `pwndbg`, we need to remember that there was an `mmap` for region `0x100000000` during the signal handler routine, which isn't applied if we run the new executable, so we also need to include it in our `gdb` script:

```gdb
b *(0x555555554000 + 0x640)
r
p (int)mmap(0x100000000, 0x1000, 0x3, 0x22, (int)open("/dev/mem", 0x2), 0x0)
```

By stepping through these breakpoints, we go through the following validations:

- Input password = `cybrics{HI_this_is_fake_flag}`: This string is hardcoded in the check, so sadly we don't need `z3` or `angr` to retrieve it;
- Open file `.realflag`: We just need to `touch` it;
- Read bytes from file, length must be 32 bytes: we add some placeholder to the file.

Afterwards, we get this sequence of syscalls:

```
0x555555554e3d    syscall <SYS_socket>
     domain: 0x26
     type: 0x5
     protocol: 0x0
0x555555554ed9    syscall <SYS_bind>
     fd: 0x4
     addr: 0x7fffffffd018 ◂— 0x687361680026 /* '&' */
     len: 0x58
0x555555554f3e    syscall <SYS_accept>
     fd: 0x4
     addr: 0x0
     addr_len: 0x0
```

The bind parameter `addr` contains this value:

```
pwndbg> x/32s 0x7fffffffd018
0x7fffffffd018: "&"
0x7fffffffd01a: "hash"
0x7fffffffd01f: ""
[...]
0x7fffffffd030: "sha1"
```

Moving on:

```
0x555555554f58    syscall <SYS_sendto>
     fd: 0x5
     buf: 0x7ffff7ffb000 ◂— 'cybrics{HI_this_is_fake_flag}'
     n: 0x1d
     flags: 0x0
     addr: 0x0
     addr_len: 0x0
0x555555554f72    syscall <SYS_recvfrom>
     fd: 0x5
     buf: 0x7ffff7ffb000 ◂— 'cybrics{HI_this_is_fake_flag}'
     n: 0x200
     flags: 0x0
     addr: 0x0
     addr_len: 0x0

pwndbg> x/s $rsi
0x7ffff7ffb000: "q\226\253\241]P7\004\376.\370\024\255\274J\263=\210\303Sake_flag}"
=> 7196aba15d503704fe2ef814adbc4ab3 3d88c353
pwndbg> x/4xw $rsi
0x7ffff7ffb000: 0xa1ab9671      0x0437505d      0x14f82efe      0xb34abcad
```

It seems it called a kernel API that computes the sha1sum of fake flag string. We can verify the received value with `sha1sum <(printf '%s' 'cybrics{HI_this_is_fake_flag}')`:

```
7196aba15d503704fe2ef814adbc4ab33d88c353  /proc/self/fd/11
```

This value is then used in another socket initialization:

```
0x5555555551cd    syscall <SYS_socket>
     domain: 0x26
     type: 0x5
     protocol: 0x0
0x555555555269    syscall <SYS_bind>
     fd: 0x6
     addr: 0x7fffffffd018 ◂— 0x687069636b730026 /* '&' */
     len: 0x58
0x5555555552c4    syscall <SYS_setsockopt>
     fd: 0x6
     level: 0x117
     optname: 0x1
     optval: 0x7ffff7ffb000 ◂— 0x437505da1ab9671
     optlen: 0x10

pwndbg> x/32s 0x7fffffffd018
0x7fffffffd018: "&"
0x7fffffffd01a: "skcipher"
0x7fffffffd023: ""
[...]
0x7fffffffd030: "cbc(aes)"
```

Which initializes AES encryption in CBC mode, using the 16 bytes (`optlen`) of the sha1 hash (`optval`). The bytes and corresponding encryption come after (I used string `AAAABAAACAAADAAAEAAAFAAAGAAAHAAA` as contents for file `.realflag`):

```
0x5555555553ee    syscall <SYS_sendmsg>
     fd: 0x7
     message: 0x7fffffffd008 ◂— 0x0
     flags: 0x0
0x555555555447    syscall <SYS_read>
     fd: 0x7
     buf: 0x7ffff7fc9000 ◂— 'AAAABAAACAAADAAAEAAAFAAAGAAAHAAA'
     nbytes: 0x10
0x5555555553ee    syscall <SYS_sendmsg>
     fd: 0x7
     message: 0x7fffffffd008 ◂— 0x0
     flags: 0x0
0x555555555447    syscall <SYS_read>
     fd: 0x7
     buf: 0x7ffff7fc9010 ◂— 'EAAAFAAAGAAAHAAA'
     nbytes: 0x10

pwndbg> x/16x 0x7ffff7fc9000
0x7ffff7fc9000: 0x9db1173d      0xac67b14c      0x62217903      0xa73d72c7
0x7ffff7fc9010: 0xff96b846      0x1e8d0038      0xaf8ffba7      0x74f864c2
pwndbg> x/s 0x7ffff7fc9000
0x7ffff7fc9000: "=\027\261\235L\261g\254\003y!b\307r=\247F\270\226\377\070"
```

The last validation takes these encrypted bytes and compares them against hard-coded bytes in 2 distinct functions (`0x1467` and `0x1530`). The following `pwndbg` commands showcase both sets of bytes loaded and compared at specific breakpoints:

```
► 0x555555555449    mov    qword ptr [rbp - 0xb0], rax
RSP  0x7fffffffcf88 —▸ 0x7ffff7fc9010 ◂— 0x1e8d0038ff96b846

pwndbg> x/4w *(char**)$rsp
0x7ffff7fc9010: 0xff96b846      0x1e8d0038      0xaf8ffba7      0x74f864c2
pwndbg> x/16xb *(char**)$rsp
0x7ffff7fc9010: 0x46    0xb8    0x96    0xff    0x38    0x00    0x8d    0x1e
0x7ffff7fc9018: 0xa7    0xfb    0x8f    0xaf    0xc2    0x64    0xf8    0x74

pwndbg> x/4xw (char**)($rbp - 8)
0x7fffffffd070: 0x513ade00      0x60767e2c      0xffffd088      0x00007fff
pwndbg> x/16xb (char**)($rbp - 8)
0x7fffffffd070: 0x00    0xde    0x3a    0x51    0x2c    0x7e    0x76    0x60
0x7fffffffd078: 0x88    0xd0    0xff    0xff    0xff    0x7f    0x00    0x00

► 0x555555554859    call   0x555555555467 <0x555555555467>
RSI  0x100000020 —▸ 0x7ffff7fc9000 ◂— 0xac67b14c9db1173d

pwndbg> x/8wx $rdi
0x7ffff7fc9000: 0x9db1173d      0xac67b14c      0x62217903      0xa73d72c7
0x7ffff7fc9010: 0xff96b846      0x1e8d0038      0xaf8ffba7      0x74f864c2

► 0x5555555554f4    cmp    dl, al
pwndbg> x/4w *(char**)($rbp - 0x30)
0x7fffffffd058: 0x3a1a43be      0xee93c71a      0x3c777f5a      0x200c516e
pwndbg> x/4w *(char**)($rbp - 0x28)
0x7ffff7fc9000: 0x9db1173d      0xac67b14c      0x62217903      0xa73d72c7
```

So the idea is to compute the sha1 of the real flag, so that the first 16 bytes of it is used as a key for AES-CBC, which encrypts the real flag contents, and the result should match some hard-coded bytes.

Knowing that [AES is a symmetrical cipher](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), we can use the same key to decrypt the hard-coded bytes. However, there's still a variable missing: the [initialization vector (IV) for CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation). In theory, a random value is picked for the first block, then the resulting ciphertext block is used for the next block.

For this step, I just took an educated guess for what a predictable IV would be, which was 16 null bytes (minimal length for the Python Crypto API). Then, considering we had two separate blocks of 16 bytes to compare against our 32 bytes of "real flag" contents, I took another guess that there were 2 encryption steps applied. Therefore, we arrive at this decryption script:

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES

# sha1 hash of fake flag
key = b"\x71\x96\xab\xa1\x5d\x50\x37\x04\xfe\x2e\xf8\x14\xad\xbc\x4a\xb3"
# hard-coded encrypted bytes taken from addresses 0x1482 and 0x154b
data = [
    b"\xbe\x43\x1a\x3a\x1a\xc7\x93\xee\x5a\x7f\x77\x3c\x6e\x51\x0c\x20",
    b"\xec\x7b\x87\x2c\xcd\x83\x3d\xaa\x96\xb2\x63\xbc\x21\x62\x94\x42",
]

iv = b"\x00" * 16
aes = AES.new(key, AES.MODE_CBC, iv)
decrypted_data = aes.decrypt(data[0])

iv = data[0]
aes = AES.new(key, AES.MODE_CBC, iv)
decrypted_data += aes.decrypt(data[1])

print(decrypted_data)
```

Running it gives us the flag:

```
b'cybrics{this_1$_ELFven_m@g1c!1!}'
```
