---
layout: post
title: CTF Writeup - TSG CTF 2021 - 2 Reversing Tasks
date: 2021-10-03 11:26:35 +0100
tags:
    - ctf
    - reversing
    - debugging
    - bruteforce
    - dynamic instrumentation
    - symbolic execution
thumbnail: "/assets/writeups/TSGCTF2021/optimized.png"
---

{% include custom.html %}

# Beginner's Rev 2021

> Don't spend too much on reading the code. Once you get an idea of the behavior, I recommend you to try some dynamic analysis with various tools.

[Author's Writeup](https://hackmd.io/@mikit/rkej4TLVK), [Download]({{ site.url }}{{ site.baseurl }}/assets/writeups/TSGCTF2021/beginners_rev)

## Analysis

With `strace` we spot several calls to `fork()` and `wait()`, suggesting some computation being processed from child processes:

```
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3109bfa850) = 1481328
 > /usr/lib64/libc-2.33.so(__libc_fork+0x69) [0xccde9]
 > beginners_rev(check+0x34) [0x31a4]
 > /usr/lib64/libc-2.33.so(__libc_start_main+0xd4) [0x27b74]
 > beginners_rev(_start+0x2d) [0x11bd]
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3109bfa850) = 1481343
 > /usr/lib64/libc-2.33.so(__libc_fork+0x69) [0xccde9]
 > beginners_rev(check+0x34) [0x31a4]
 > /usr/lib64/libc-2.33.so(__libc_start_main+0xd4) [0x27b74]
 > beginners_rev(_start+0x2d) [0x11bd]
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3109bfa850) = 1481344
 > /usr/lib64/libc-2.33.so(__libc_fork+0x69) [0xccde9]
 > beginners_rev(check+0x34) [0x31a4]
 > /usr/lib64/libc-2.33.so(__libc_start_main+0xd4) [0x27b74]
 > beginners_rev(_start+0x2d) [0x11bd]
[...]
wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 1481328
 > /usr/lib64/libc-2.33.so(wait4+0x1a) [0xccaca]
 > beginners_rev(check+0x7a) [0x31ea]
 > /usr/lib64/libc-2.33.so(__libc_start_main+0xd4) [0x27b74]
 > beginners_rev(_start+0x2d) [0x11bd]
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=1481328, si_uid=1000, si_status=1, si_utime=0, si_stime=0} ---
 > /usr/lib64/libc-2.33.so(wait4+0x1a) [0xccaca]
 > beginners_rev(check+0x7a) [0x31ea]
 > /usr/lib64/libc-2.33.so(__libc_start_main+0xd4) [0x27b74]
 > beginners_rev(_start+0x2d) [0x11bd]
wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 1481343
 > /usr/lib64/libc-2.33.so(wait4+0x1a) [0xccaca]
 > beginners_rev(check+0x7a) [0x31ea]
 > /usr/lib64/libc-2.33.so(__libc_start_main+0xd4) [0x27b74]
 > beginners_rev(_start+0x2d) [0x11bd]
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=1481343, si_uid=1000, si_status=1, si_utime=0, si_stime=0} ---
 > /usr/lib64/libc-2.33.so(wait4+0x1a) [0xccaca]
 > beginners_rev(check+0x7a) [0x31ea]
 > /usr/lib64/libc-2.33.so(__libc_start_main+0xd4) [0x27b74]
 > beginners_rev(_start+0x2d) [0x11bd]
```

After providing some input via stdin, we verify from the output messages that it expects an input length of 32 characters.

From the decompilation, we see that `main()` calls `check()`, and each child process runs `is_correct()` over a given character of the passed input (at index `ki_pi`):

```c
do {
  _Var1 = fork();
  iVar2 = iVar2 + 1;
  if (_Var1 == 0) {
    iVar2 = 0;
    ki_pi = ki_pi | 1 << ((byte)i & 0x1f);
    fd = open("/dev/null",1);
    dup2(fd,1);
  }
  i = i + 1;
} while (i != 5);
i = iVar2 + -1;
fd = is_correct((int)*(char *)(input + (int)ki_pi),ki_pi);
flag = fd == 0;
if (iVar2 != 0) {
  do {
    i = i + -1;
    wait(&wstatus);
    flag = flag | local_33;
  } while (i != -1);
}
if (flag == 0) {
  puts("correct");
}
else {
  puts("wrong");
}
```

## Solution

Since each character is being independently processed, it becomes feasible to just bruteforce the expected characters one-by-one. To verify if we got the right character, we need to trace the result of `is_correct()` for all processes. It's possible to follow child processes in gdb. However, there's an anti-debugging check in `is_correct()`:

```c
if (in_stack_00000000 != 0x1031cf) {
  fwrite("This function may not work properly with a debugger.",1,0x34,stderr);
}
```

In assembly:

```
0010128d 48 8b 74        MOV        RSI,qword ptr [RSP + 0x18] ; load return address
         24 18
00101292 48 8d 1d        LEA        RBX,[check] ; load start address of check()
         d7 1e 00 00
00101299 48 89 f0        MOV        RAX,RSI
0010129c 48 29 d8        SUB        RAX,RBX
0010129f 48 83 f8 5f     CMP        RAX,0x5f
001012a3 74 22           JZ         char_check
001012a5 48 8b 0d        MOV        RCX,qword ptr [stderr]
         74 4d 00 00
001012ac be 01 00        MOV        RSI,0x1
         00 00
001012b1 ba 34 00        MOV        EDX,0x34
         00 00
001012b6 48 8d 3d        LEA        input,[s_This_function_may_not_work_prope_0010   = "This function may not work pr
         4b 2d 00 00
001012bd e8 4e fe        CALL       <EXTERNAL>::fwrite                               size_t fwrite(void * __ptr, size
         ff ff
```

This checks that the difference between `0x1031cf` (the return address pushed into the stack, which is the first instruction after the call instruction at `0x1031ca`) and the start of `check()` is `0x5f` (`0x1031cf - 0x103170 = 0x5f`). However, if either the stack or the surrounding instructions are changed, this difference might also change.

The expected return address is also used multiple times during character validation:

```
0010147f 49 01 f0        ADD        R8,RSI
[...]
0010196e 49 01 f0        ADD        R8,RSI
[...]
00102faa 48 89 f0        MOV        RAX,RSI
```

Therefore, running in a debugger could cause the expected characters to not pass validation.

As an alternative to running in a debugger, we can dynamically instrument the process using frida. We'll adapt an existing [full example on instrumenting child processes](https://github.com/frida/frida-python/blob/master/examples/child_gating.py), which is accompanied by an [high-level description](https://frida.re/news/2018/04/28/frida-10-8-released/). Let's focus on the key parts of both our [client script]({{ site.url }}{{ site.baseurl }}/assets/writeups/TSGCTF2021/frida_session.py) and [instrumentation script]({{ site.url }}{{ site.baseurl }}/assets/writeups/TSGCTF2021/frida_trace.js).

A first attempt was to trace at the input check function `is_correct()`:

```javascript
const m = Process.enumerateModules()[0];
console.log('Base address: ' + m.base);

var char = -1
var char_i = -1
var is_correct = -1
Interceptor.attach(ptr(m.base.add(0x1280)), {
    onEnter: function(args) {
        char = args[0].toInt32()
        char_i = args[1].toInt32()
        console.log(`is_correct(${char}, ${char_i})`);
    },
    onLeave: function(retval) {
        const v = retval.toInt32()
        console.log("-> " + v);
        send([char, char_i, v]);
    }
});
```

But this fails the anti-debug. Instead, we have to instrument before and after the function call, parsing the corresponding input and output registers:

```javascript
Interceptor.attach(ptr(m.base.add(0x31c4)),
    function(args) {
        char = Memory.readU8(this.context.r13.add(this.context.rax))
        var rsi = this.context.rsi
        char_i = parseInt(rsi)
    }
);
Interceptor.attach(ptr(m.base.add(0x31cf)),
    function(args) {
        var rax = this.context.rax
        is_correct = parseInt(rax)
        console.log([char, char_i, is_correct])
        send([char, char_i, is_correct]);
    }
);
```

{::options parse_block_html="true" /}
<div class="c-indirectly-related">
This alternative happens to work because the instrumentation patches don't introduce instruction misalignments. To verify this:

1. Run without ASLR (e.g. under a shell started with `setarch "$(uname -m)" -R /bin/bash`);
2. Wait for the debugger at the end of our instrumentation script:
```javascript
while (!Process.isDebuggerAttached()) {
  console.log('Waiting for debugger in PID:', Process.id);
  Thread.sleep(5);
}
```
3. Attach gdb and dump around the call with `disas (0x555555554000+0x31c1),+30`;
4. Attach another gdb to the executable without instrumentation and dump around the call;
5. Compare these two listings, noticing that the call address and one of the following instruction's address (e.g. `lea  rbp,[rsp+0x4]`) happen to have the same offset:
```diff
--- gdb beginners_rev
+++ gdb -p 1689554  # PID taken from script log
@@ -1,8 +1,9 @@
 0x00005555555571c1 <check+81>:       xor    r12d,r12d
-0x00005555555571c4 <check+84>:       movsx  edi,BYTE PTR [r13+rax*1+0x0]
+0x00005555555571c4 <check+84>:       jmp    0x55555557d008
+0x00005555555571c9 <check+89>:       nop
 0x00005555555571ca <check+90>:       call   0x555555555280 <is_correct>
-0x00005555555571cf <check+95>:       test   eax,eax
-0x00005555555571d1 <check+97>:       sete   r12b
+0x00005555555571cf <check+95>:       jmp    0x55555557d108
+0x00005555555571d4 <check+100>:      nop
 0x00005555555571d5 <check+101>:      test   ebp,ebp
 0x00005555555571d7 <check+103>:      je     0x5555555571f8 <check+136>
 0x00005555555571d9 <check+105>:      lea    rbp,[rsp+0x4]
```
</div>
{::options parse_block_html="false" /}

The sent message from our instrumentation script is then parsed:

```python
def _on_message(self, pid, message):
    char_i = message["payload"][1]
    results[char_i] = message["payload"]
    print("* message: pid={}, payload={}".format(pid, message["payload"]))
```

And we track each character that was valid (i.e. `rax = 1`):

```python
flag = ["?"] * 32
for c in string.printable:
    input_data = "".join([c] * 32)
    results = [None] * 32

    app = Application()
    app.run()

    for result in results:
        if result[2] == 1:
            flag[result[1]] = chr(result[0])
```

Joining all the found characters gives us the flag:

```
TSGCTF{y0u_kN0w_m@ny_g0od_t0015}
```

---

# optimized

> Decompilers hate this state-of-the-art math trick...

[Author's Writeup](https://hackmd.io/@ishitatsuyuki/B1MDOgw4Y), [Download]({{ site.url }}{{ site.baseurl }}/assets/writeups/TSGCTF2021/optimized)

## Analysis

Starting with `strace -k`, several operations modifying module maps can be spotted, and later on there's the prompt for input:

```
mmap(0x800000, 2177040, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, 0, 0) = 0x800000
 > optimized() [0x400b3f]
readlink("/proc/self/exe", "opti"..., 4096) = 37
mmap(0x400000, 2117632, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x400000
mmap(0x400000, 13704, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x400000
mprotect(0x400000, 13704, PROT_READ|PROT_EXEC) = 0
mmap(0x603000, 4232, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0x3000) = 0x603000
mprotect(0x603000, 4232, PROT_READ|PROT_WRITE) = 0
open("/lib64/ld-linux-x86-64.so.2", O_RDONLY) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\220\20\0\0\0\0\0\0"..., 1024) = 1024
mmap(NULL, 212992, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fe434b50000
mmap(0x7fe434b50000, 3112, PROT_READ, MAP_PRIVATE|MAP_FIXED, 3, 0) = 0x7fe434b50000
mmap(0x7fe434b51000, 149910, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED, 3, 0x1000) = 0x7fe434b51000
mmap(0x7fe434b76000, 37436, PROT_READ, MAP_PRIVATE|MAP_FIXED, 3, 0x26000) = 0x7fe434b76000
mmap(0x7fe434b80000, 12344, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED, 3, 0x2f000) = 0x7fe434b80000
close(3)                                = 0
munmap(0x800000, 2177040)               = 0
 > optimized() [0x40000e]
[...]
write(1, "Enter password: ", 16)        = 16
 > /usr/lib64/libc-2.33.so(write+0x17) [0xf1387]
 > /usr/lib64/libc-2.33.so(_IO_file_write@@GLIBC_2.2.5+0x2c) [0x8178c]
 > /usr/lib64/libc-2.33.so(new_do_write+0x65) [0x80b05]
 > /usr/lib64/libc-2.33.so(_IO_do_write@@GLIBC_2.2.5+0x18) [0x82828]
 > /usr/lib64/libc-2.33.so(_IO_file_sync@@GLIBC_2.2.5+0xa7) [0x80927]
 > /usr/lib64/libc-2.33.so(_IO_fflush+0x85) [0x758a5]
 > optimized() [0x40093f]
```

However, if we check the executable's disassembly, we see that there's no `write()` call at `0x40093f`, much less any input parsing logic:

```
                     entry
00400928 e8 53 02        CALL       FUN_00400b80
         00 00
0040092d 55              PUSH       RBP
0040092e 53              PUSH       RBX
0040092f 51              PUSH       RCX
00400930 52              PUSH       RDX
00400931 48 01 fe        ADD        RSI,RDI
00400934 56              PUSH       RSI
00400935 48 89 fe        MOV        RSI,RDI
00400938 48 89 d7        MOV        RDI,RDX
0040093b 31 db           XOR        EBX,EBX
0040093d 31 c9           XOR        ECX,ECX
0040093f 48 83 cd ff     OR         RBP,-0x1
00400943 e8 50 00        CALL       FUN_00400998
         00 00
00400948 01 db           ADD        EBX,EBX
0040094a 74 02           JZ         LAB_0040094e
0040094c f3 c3           RET
```

Seems like we have self-modifying code: a new executable map at `0x800000` is created (`mmap(0x800000, 2177040, PROT_READ|PROT_WRITE|PROT_EXEC, ...)`), the original executable map at `0x400000` becomes writable (`mprotect(0x603000, 4232, PROT_READ|PROT_WRITE)`), and we can assume that new code will be written there. This unpacker also cleans up after itself, removing from memory the map that contains its code (`munmap(0x800000, 2177040)`)

To locate the original entry point (i.e. the entry address of the original packed executable), we could `catch syscall munmap`, and follow manually from there. In an attempt to get closer than that, I ran the following gdb script, so that it would stop at the `write()` instruction after unpacking:

```python
import gdb
import struct

# Before jumping to unpacker
gdb.execute("b *0x400b7c")
gdb.execute("r")

# Unpacker has been written at this point, now we can break on it
gdb.execute("b *0x800a3b")

while True:
    gdb.execute("si")
    rip = int(str(gdb.parse_and_eval("$rip")).split()[0], 16)
    if rip == 0x40093f:
        # Stepped up to write() call
        break
```

Besides taking several minutes, it seems that gdb just ends up going from map `0x800000` right into libc addresses, without following addresses in map `0x400000`. Furthermore, the changes in map protections also caused issues with placed breakpoints, which needed to be deleted after being hit. After these fixes, and finding address `0x800c8b` which is closer to the unpacking end, we could reliably stop inside map `0x400000`:

```python
import gdb
import struct

gdb.execute("b *0x400b7c")
gdb.execute("r")
gdb.execute("b *0x800a3b")
gdb.execute("c")
gdb.execute("c")
gdb.execute("c")
gdb.execute("c")
gdb.execute("del 1")
gdb.execute("del 2")
gdb.execute("b *0x800c8b")
gdb.execute("c")
gdb.execute("del 3")
gdb.execute("b *0x40093f")
gdb.execute("c")
```

Alternatively, since we know that the process reads from input, we can just let it run and only attach afterwards to it, which would also work to dump the unpacked executable.

Let's turn the [process memory into an ELF executable]({{ site.url }}{{ site.baseurl }}/assets/writeups/TSGCTF2021/optimized.dump) using [skpd](https://github.com/whatsbcn/skpd):

```
./skpd -p $(pgrep optimized) -o optimized.dump
```

And dissassemble that:

```
Invalid file offset 15888 while reading optimized.dump
java.io.EOFException: Invalid file offset 15888 while reading optimized.dump
	at ghidra.app.util.bin.RandomAccessByteProvider.readBytes(RandomAccessByteProvider.java:140)
	at ghidra.app.util.bin.BinaryReader.readLong(BinaryReader.java:703)
	at ghidra.app.util.bin.BinaryReader.readNextLong(BinaryReader.java:338)
	at ghidra.app.util.bin.format.elf.ElfDynamic.initElfDynamic(ElfDynamic.java:83)
	at ghidra.app.util.bin.format.elf.ElfDynamic.createElfDynamic(ElfDynamic.java:66)
	at ghidra.app.util.bin.format.elf.ElfDynamicTable.initDynamicTable(ElfDynamicTable.java:71)
	at ghidra.app.util.bin.format.elf.ElfDynamicTable.createDynamicTable(ElfDynamicTable.java:48)
	at ghidra.app.util.bin.format.elf.ElfHeader.parseDynamicTable(ElfHeader.java:626)
	at ghidra.app.util.bin.format.elf.ElfHeader.parse(ElfHeader.java:221)
	at ghidra.app.util.opinion.ElfProgramBuilder.load(ElfProgramBuilder.java:110)
	at ghidra.app.util.opinion.ElfProgramBuilder.loadElf(ElfProgramBuilder.java:103)
	at ghidra.app.util.opinion.ElfLoader.load(ElfLoader.java:153)
```

Ok, some headers probably need fixing... Alternatively, we can just dump the executable map:

```
pwndbg> dump memory out.0x400000.mem 0x400000 0x404000
```

And load it as an overlay of the original disassembly (on ghidra: `File > Add To Program...` + `Options... > Check: Overlay, Base Address = 0x400000`), resulting in a new map:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/TSGCTF2021/map.png" alt=""/>
</div>

Now, we manually decompile around address `0x40093f`, revealing the flag checks:

```c
printf("Enter password: ");
FUN_segment_0b__00400820(_DAT_006040a8);
iVar1 = scanf("%u %u %u %u",&v1,&v2,&v3,&v4);
if (iVar1 == 4) {
  uVar4 = SUB164(ZEXT816((ulong)v1 * 0x5f50ddca7b17) * ZEXT816(0x2af91) >> 0x40,0) & 0x3ffff;
  if (false) {
    uVar4 = 0;
  }
  if (false) {
    uVar7 = 0;
  }
  else {
    if (false) {
      uVar7 = 0x9569;
    }
    else {
      uVar7 = 0x9569;
    }
  }
  auVar6 = CONCAT115(0xff,CONCAT114(0xff,CONCAT113(0xff,CONCAT112(0xff,CONCAT111(0xff,CONCAT110(-(
                                                (char)(uVar4 >> 0x10) == '\0'),
                                                CONCAT19(-((char)((ushort)uVar7 >> 8) ==
                                                          (char)(uVar4 >> 8)),
                                                         CONCAT18(-((char)uVar7 == (char)uVar4),
                                                                  0xffffffffffffffff))))))));
  if ((ushort)((ushort)(SUB161(auVar6 >> 7,0) & 1) | (ushort)(SUB161(auVar6 >> 0xf,0) & 1) << 1 |
               (ushort)(SUB161(auVar6 >> 0x17,0) & 1) << 2 |
               (ushort)(SUB161(auVar6 >> 0x1f,0) & 1) << 3 |
               (ushort)(SUB161(auVar6 >> 0x27,0) & 1) << 4 |
               (ushort)(SUB161(auVar6 >> 0x2f,0) & 1) << 5 |
               (ushort)(SUB161(auVar6 >> 0x37,0) & 1) << 6 |
               (ushort)(SUB161(auVar6 >> 0x3f,0) & 1) << 7 |
               (ushort)(SUB161(auVar6 >> 0x47,0) & 1) << 8 |
               (ushort)(SUB161(auVar6 >> 0x4f,0) & 1) << 9 |
               (ushort)(SUB161(auVar6 >> 0x57,0) & 1) << 10 |
               (ushort)(SUB161(auVar6 >> 0x5f,0) & 1) << 0xb |
               (ushort)(SUB161(auVar6 >> 0x67,0) & 1) << 0xc |
               (ushort)(SUB161(auVar6 >> 0x6f,0) & 1) << 0xd |
               (ushort)(SUB161(auVar6 >> 0x77,0) & 1) << 0xe | 0x8000) == 0xffff) {
    uVar4 = SUB164(ZEXT816((ulong)v1 * 0x4dc4591dac8f) * ZEXT816(0x34ab9) >> 0x40,0) & 0x3ffff;

    // [...]
  }
// [...]
}
```

There we go, there's the input parsing of 4 integers, followed by a lot of poorly decompiled checks. Guess we arrive at the "math trick"...

Now, before trying to [understand these checks](https://lemire.me/blog/2019/02/08/faster-remainders-when-the-divisor-is-a-constant-beating-compilers-and-libdivide/), let's go through one of them in assembly:

```
00400969 8b 4c 24 10     MOV        ECX,dword ptr [RSP + v1] ; v1 = one of the parsed integers
0040096d 48 b8 17        MOV        RAX,0x5f50ddca7b17
         7b ca dd
         50 5f 00 00
00400977 48 0f af c1     IMUL       RAX,RCX
0040097b ba 91 af        MOV        EDX,0x2af91
         02 00
00400980 48 f7 e2        MUL        RDX
00400983 81 e2 ff        AND        EDX,0x3ffff
         ff 03 00
00400989 66 48 0f        MOVQ       XMM0,RDX
         6e c2
0040098e 66 0f 73        PSLLDQ     XMM0,0x8
         f8 08
00400993 b8 69 95        MOV        EAX,0x9569
         00 00
00400998 66 48 0f        MOVQ       XMM1,RAX
         6e c8
0040099d 66 0f 73        PSLLDQ     XMM1,0x8
         f9 08
004009a2 66 0f 74 c8     PCMPEQB    XMM1,XMM0
004009a6 66 0f d7 c1     PMOVMSKB   EAX,XMM1
004009aa 3d ff ff        CMP        EAX,0xffff
         00 00
```

Consider what they are accessing:

- For each integer, several SIMD instructions are applied, and the result is compared with 0xffff;
- There are no calls to other functions during these checks;
- After all checks, the input is passed to a function, then to some libc functions.

Assuming no other processing happens in the last function call, these seem simple enough to solve with symbolic execution... Except we don't have a valid executable (running causes it to segfault). Turns out that this isn't a blocker.

## Solution

Conveniently, angr supports executing from straight assembly, so we can skip all the executable setup:

```python
with open(sys.argv[1], "rb") as f:
    # Skip ELF headers and code up to flag check start address
    asm = f.read()[0x960:]

project = angr.load_shellcode(
    asm,
    "x86_64",
    start_offset=0,
    load_address=0x400960,
    support_selfmodifying_code=True,
)
state = project.factory.entry_state()
```

Before executing these instructions, we need to have the actual **program state at this point in execution**, since we are e.g. reading values from registers and stack. Similar to how in software development we make a minimal working test case when we want to isolate logic that causes some bug, here we want to prepare a minimal state so that we can execute the instructions of the flag check like the executable normally would[^1].

[^1]: This would be the same case if we instead wanted to do emulation (e.g. with unicorn). Alternatively, a more interactive approach should be possible with [angrgdb](https://github.com/andreafioraldi/angrgdb).

Also, do we have any state resulting from side-effects (e.g. certain bytes read/written from files)? These wouldn't be captured from a debugger. In this case, we don't depend on such side-effects.

With gdb, it's possible to dump all the state we need. We could adapt an existing [dump script](https://github.com/Battelle/afl-unicorn/blob/master/unicorn_mode/helper_scripts/unicorn_dumper_gdb.py), but let's just go through it manually, starting by accessed module maps:

```
pwndbg> vmmap
0x400000           0x404000 r-xp     4000 0      anon_00400
0x404000           0x603000 ---p   1ff000 0      anon_00404
0x603000           0x604000 r--p     1000 0      anon_00603
0x604000           0x626000 rw-p    22000 0      [heap]
[...]
0x7ffffffdd000     0x7ffffffff000 rw-p    22000 0      [stack]

pwndbg> dump memory out.0x400000.mem 0x400000 0x404000
pwndbg> dump memory out.0x603000.mem 0x603000 0x604000
pwndbg> dump memory out.0x604000.mem 0x604000 0x626000
pwndbg> dump memory out.0x7ffffffdd000.mem 0x7ffffffdd000 0x7ffffffff000
```

Importing them in our script:

```python
memory = open("out.0x400000.mem", "rb").read()
state.memory.store(0x400000, memory, disable_actions=True, inspect=False)
state.memory.permissions(0x400000, 5)  # 0b101 = r-x

memory = open("out.0x603000.mem", "rb").read()
state.memory.store(0x603000, memory, disable_actions=True, inspect=False)
state.memory.permissions(0x603000, 4)  # 0b100 = r--

memory = open("out.0x604000.mem", "rb").read()
state.memory.store(0x604000, memory, disable_actions=True, inspect=False)
state.memory.permissions(0x604000, 6)  # 0b110 = rw-

memory = open("out.0x7ffffffdd000.mem", "rb").read()
state.memory.store(0x7FFFFFFDD000, memory, disable_actions=True, inspect=False)
state.memory.permissions(0x7FFFFFFDD000, 6)  # 0b110 = rw-
```

Followed by registers (taken from gdb via `context`; we don't need state from flags or SIMD registers):

```python
state.regs.rax = 0x4  # used for scanf parsed count check
state.regs.rbx = 0x403350
state.regs.rcx = 0x0
state.regs.rdx = 0x0
state.regs.rdi = 0x7FFFFFFFB930
state.regs.rsi = 0x0
state.regs.r8 = 0x4
state.regs.r9 = 0x0
state.regs.r10 = 0x7FFFF7C48AC0
state.regs.r11 = 0x7FFFF7C493C0
state.regs.r12 = 0x400830
state.regs.r13 = 0x0
state.regs.r14 = 0x0
state.regs.r15 = 0x7FFFFFFFC5D8
state.regs.rbp = 0x0
state.regs.rsp = 0x7FFFFFFFBE70
state.regs.rip = 0x400960
```

Since we will be running without loading libc, we need to explicitly skip any calls to stubs present in the procedure linkage table (a.k.a. `.plt`):

```python
class pass_hook(angr.SimProcedure):
    def run(self):
        print("! pass_hook")
        return

# [...]

# Skip libc handlers
project.hook(0x400790, pass_hook())
project.hook(0x4007A0, pass_hook())
project.hook(0x4007B0, pass_hook())
project.hook(0x4007C0, pass_hook())
project.hook(0x4007D0, pass_hook())
project.hook(0x4007E0, pass_hook())
project.hook(0x4007F0, pass_hook())
project.hook(0x400800, pass_hook())
project.hook(0x400810, pass_hook())
project.hook(0x400C20, pass_hook())
```

While angr has the "explorer" technique, where it tries to reach target addresses while avoiding others, we also want to stop execution at addresses that can't be handled in our setup state, since angr would end up accessing unmapped memory or executing bad instructions. We explicitly mark such addresses as `deadend`. If needed, we could later on manually inspect these states:

```python
# After "CALL scanf"
START = 0x400960
# Flag
FIND = 0x400B5D
# "Bad format!" and "Wrong!"
AVOID = [0x400BF7, 0x400BF0]
# Not fail cases, but don't continue execution
DEADEND = [0x400BFC, 0x400C01, 0x400C03, 0x400C0A, 0x400C0B, 0x400C20]

# [...]

sm = project.factory.simgr(state)
while sm.active:
    print(sm, sm.active)
    for active in sm.active:
        project.factory.block(active.addr, backup_state=active).pp()
        if active.addr in [FIND]:
            ipdb.set_trace()
    sm.step()

    # Don't run fail cases, libc, stack, etc...
    sm.stash(
        from_stash="active",
        to_stash="avoid",
        filter_func=lambda s: s.addr in AVOID or s.addr > 0x7FFFF7AF0000,
    )
    # Don't run code after the flag check end
    sm.stash(
        from_stash="active",
        to_stash="deadend",
        filter_func=lambda s: s.addr in DEADEND or s.addr > 0x400C28,
    )
```

After running this [script]({{ site.url }}{{ site.baseurl }}/assets/writeups/TSGCTF2021/optimized.solver.py) (around 5 minutes), we get a nice trace of angr progressively passing each check:

```
<SimulationManager with 1 active> [<SimState @ 0x400960>]
0x400960:    cmp    eax, 4
0x400963:    jne    0x400bf0
<SimulationManager with 1 active> [<SimState @ 0x400969>]
0x400969:    mov    ecx, dword ptr [rsp + 0x10]
0x40096d:    movabs    rax, 0x5f50ddca7b17
0x400977:    imul    rax, rcx
0x40097b:    mov    edx, 0x2af91
0x400980:    mul    rdx
0x400983:    and    edx, 0x3ffff
0x400989:    movq    xmm0, rdx
0x40098e:    pslldq    xmm0, 8
0x400993:    mov    eax, 0x9569
0x400998:    movq    xmm1, rax
0x40099d:    pslldq    xmm1, 8
0x4009a2:    pcmpeqb    xmm1, xmm0
0x4009a6:    pmovmskb    eax, xmm1
0x4009aa:    cmp    eax, 0xffff
0x4009af:    jne    0x400bf7
<SimulationManager with 1 active, 1 avoid> [<SimState @ 0x4009b5>]
0x4009b5:    movabs    rax, 0x4dc4591dac8f
0x4009bf:    imul    rax, rcx
0x4009c3:    mov    edx, 0x34ab9
0x4009c8:    mul    rdx
0x4009cb:    and    edx, 0x3ffff
0x4009d1:    movq    xmm0, rdx
0x4009d6:    pslldq    xmm0, 8
0x4009db:    mov    eax, 0x26cf2
0x4009e0:    movq    xmm1, rax
0x4009e5:    pslldq    xmm1, 8
0x4009ea:    pcmpeqb    xmm1, xmm0
<SimulationManager with 1 active, 2 avoid> [<SimState @ 0x4009fd>]
0x4009fd:    mov    esi, dword ptr [rsp + 0x14]
0x400a01:    movabs    rax, 0x4ae11552df1a
0x400a0b:    imul    rax, rsi
0x400a0f:    mov    edx, 0x36b39
0x400a14:    mul    rdx
0x400a17:    and    edx, 0x3ffff
0x400a1d:    movq    xmm0, rdx
0x400a22:    pslldq    xmm0, 8
0x400a27:    mov    eax, 0x20468
0x400a2c:    movq    xmm1, rax
0x400a31:    pslldq    xmm1, 8
0x400a36:    pcmpeqb    xmm1, xmm0
0x400a3a:    pmovmskb    eax, xmm1
0x400a3e:    cmp    eax, 0xffff
0x400a43:    jne    0x400bf7
<SimulationManager with 1 active, 3 avoid> [<SimState @ 0x400a49>]
0x400a49:    movabs    rax, 0x46680b140eff
0x400a53:    imul    rax, rsi
0x400a57:    mov    edx, 0x3a2d3
0x400a5c:    mul    rdx
0x400a5f:    and    edx, 0x3ffff
0x400a65:    movq    xmm0, rdx
0x400a6a:    pslldq    xmm0, 8
0x400a6f:    mov    eax, 0x3787a
0x400a74:    movq    xmm1, rax
0x400a79:    pslldq    xmm1, 8
0x400a7e:    pcmpeqb    xmm1, xmm0
0x400a82:    pmovmskb    eax, xmm1
0x400a86:    cmp    eax, 0xffff
0x400a8b:    jne    0x400bf7
<SimulationManager with 1 active, 4 avoid> [<SimState @ 0x400a91>]
0x400a91:    mov    edi, dword ptr [rsp + 0x18]
0x400a95:    movabs    rax, 0x4d935bbd3e0
0x400a9f:    mov    rdx, rdi
0x400aa2:    imul    rdx, rax
0x400aa6:    cmp    rdx, rax
0x400aa9:    jae    0x400bf7
<SimulationManager with 1 active, 5 avoid> [<SimState @ 0x400aaf>]
0x400aaf:    movabs    rax, 0x66b9b431b9ed
0x400ab9:    imul    rax, rdi
0x400abd:    mov    edx, 0x27df9
0x400ac2:    mul    rdx
0x400ac5:    and    edx, 0x3ffff
0x400acb:    movq    xmm0, rdx
0x400ad0:    pslldq    xmm0, 8
0x400ad5:    mov    eax, 0x5563
0x400ada:    movq    xmm1, rax
0x400adf:    pslldq    xmm1, 8
0x400ae4:    pcmpeqb    xmm1, xmm0
0x400ae8:    pmovmskb    eax, xmm1
0x400aec:    cmp    eax, 0xffff
0x400af1:    jne    0x400bf7
<SimulationManager with 1 active, 6 avoid> [<SimState @ 0x400af7>]
0x400af7:    mov    ebx, dword ptr [rsp + 0x1c]
0x400afb:    movabs    rax, 0x1e5d2be81c5
0x400b05:    mov    rdx, rbx
0x400b08:    imul    rdx, rax
0x400b0c:    cmp    rdx, rax
0x400b0f:    jae    0x400bf7
<SimulationManager with 1 active, 7 avoid> [<SimState @ 0x400b15>]
0x400b15:    movabs    rax, 0x448626500938
0x400b1f:    imul    rax, rbx
0x400b23:    mov    edx, 0x3bc65
0x400b28:    mul    rdx
0x400b2b:    and    edx, 0x3ffff
0x400b31:    movq    xmm0, rdx
0x400b36:    pslldq    xmm0, 8
0x400b3b:    mov    eax, 0x133e7
0x400b40:    movq    xmm1, rax
0x400b45:    pslldq    xmm1, 8
0x400b4a:    pcmpeqb    xmm1, xmm0
0x400b4e:    pmovmskb    eax, xmm1
0x400b52:    cmp    eax, 0xffff
0x400b57:    jne    0x400bf7
<SimulationManager with 1 active, 8 avoid> [<SimState @ 0x400b5d>]
0x400b5d:    mov    dword ptr [rsp + 0x20], ecx
0x400b61:    mov    dword ptr [rsp + 0x24], esi
0x400b65:    mov    dword ptr [rsp + 0x28], edi
0x400b69:    mov    dword ptr [rsp + 0x2c], ebx
0x400b6d:    call    0x4007d0
```

Taking the concrete input register values:

```
ipdb> active.solver.eval(active.regs.rbx)
1334930147
ipdb> active.solver.eval(active.regs.rdi)
4273479145
ipdb> active.solver.eval(active.regs.rsi)
2204180909
ipdb> active.solver.eval(active.regs.rcx)
772928896
```

We now get the flag:

```
Enter password: 772928896 2204180909 4273479145 1334930147
TSGCTF{F457_m0dul0!}
```
