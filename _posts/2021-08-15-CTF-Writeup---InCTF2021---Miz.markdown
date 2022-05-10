---
layout: post
title: CTF Writeup - InCTF 2021 - Miz
date: 2021-08-15 16:51:02 +0100
tags:
    - ctf
    - reversing
    - tracing
    - visualization
thumbnail: "/assets/writeups/InCTF2021/zoom2.png"
---

{% include custom.html %}

# Introduction

We are given a stripped rust binary. Functions in rust seem to feature convoluted stack setups that don't play well with Ghidra's decompiler. However, we can mostly avoid them in this binary, since the relevant logic is contained in a single function manipulating few data structures.

# Description

> Senpai plis find me a way.
>
> Author: Freakston, silverf3lix
>
> nc 34.94.181.140 4200

[Download]({{ site.url }}{{ site.baseurl }}/assets/writeups/InCTF2021/miz)

# Analysis

`strace` doesn't report much: input is parsed with a `read()`, and the process exits with `exit_group(256)`.

Let's start with low-hanging fruit: can we get any insights from instruction counting?

```bash
echo 'AAAAAA'| qemu-x86_64 -d in_asm ./miz 2>&1 | wc -l
# 26110
echo 'iAAAAA'| qemu-x86_64 -d in_asm ./miz 2>&1 | wc -l
# 26117
echo 'inctf{'| qemu-x86_64 -d in_asm ./miz 2>&1 | wc -l
# 26117
```

Seems that the flag prefix doesn't go through different code branches. Let's backtrack from the end, address `0x1d386`, reported by `strace -k`:

```
> /usr/lib64/libc-2.33.so(_exit+0x31) [0xcd021]
> /usr/lib64/libc-2.33.so(__run_exit_handlers+0x201) [0x3fc01]
> /usr/lib64/libc-2.33.so(exit+0x1f) [0x3fc9f]
> miz() [0x1d386]
> miz() [0x18bce]
```

Disassembly:

```
                    FUN_0011d380                               XREF[3]: exit256:00118bca(c), 0013c9a0,
                                                                         0013ef30(*)
0011d380  50        PUSH       RAX
0011d381  ff 15 19  CALL       qword ptr [-><EXTERNAL>::exit]  void exit(int __status)
          97 02 00
```

I've named the function that calls it `exit256()`, which in turn has two callers. One was named `flag()`, since it has the only reference to a string that contains the word "flag":

```c
FUN_001154f0(&local_48,"flagYametesrc/bacharu.rshehe \n",4);
```

There's a call to it that we can force in gdb, by breaking at `CMP RAX,0x2` and skipping `JNZ exit`:

```
b *(0x555555554000 + 0x97f5)
r <<< $(printf '%s' llllllllllllllll)
set $rip = (0x555555554000 + 0x97ff)
```

`flag()` will try to open a non-existing file. So once we know the correct input, we need to supply it to the host in the task description, where that file is present.

The other caller of `exit256()` has more logic. There's a switch case for 5 values, all in the ascii range, so I commented them with the corresponding char:

```c
void FUN_00109590(long param_1,long *param_2) {
  // ...

  i = *(ulong *)(param_1 + 8);
  len_in = param_2[2];
  if (i != len_in) {
    lVar1 = *param_2;
    do {
      if (len_in <= i) {
        panic(i,len_in,&PTR_s_src/bacharu.rshehe_00144320);
        do {
          invalidInstructionException();
        } while( true );
      }
      if (false) {
                /* i */
switchD_001095e8_caseD_69:
        *(ulong *)(param_1 + 8) = i + 1;
      }
      else {
        switch(*(undefined *)(lVar1 + i)) {
        case 0x68:
                    /* h */
          *(ulong *)(param_1 + 8) = i + 1;
          if (*(long *)(param_1 + 0x13a0) != 0) {
            uVar4 = *(ulong *)(param_1 + 0x1398);
            if (0x18 < uVar4) {
              panic(uVar4,0x19,&PTR_s_src/bacharu.rshehe_00144350);
              do {
                invalidInstructionException();
              } while( true );
            }
            uVar3 = *(long *)(param_1 + 0x13a0) - 1;
            if (0x18 < uVar3) {
              panic(uVar3,0x19,&PTR_s_src/bacharu.rshehe_00144350);
              do {
                invalidInstructionException();
              } while( true );
            }
            lVar2 = *(long *)(uVar4 * 200 + param_1 + 0x10 + uVar3 * 8);
            if (lVar2 == 0) {
              *(ulong *)(param_1 + 0x13a0) = uVar3;
              goto i++;
            }
            goto if2_flag;
          }
          goto exit;
        default:
          goto switchD_001095e8_caseD_69;
        case 0x6a:
                    /* j */
          *(ulong *)(param_1 + 8) = i + 1;
          if (*(long *)(param_1 + 0x1398) == 0) goto exit;
          uVar4 = *(long *)(param_1 + 0x1398) - 1;
          if (0x18 < uVar4) {
            panic(uVar4,0x19,&PTR_s_src/bacharu.rshehe_00144380);
            do {
              invalidInstructionException();
            } while( true );
          }
          uVar3 = *(ulong *)(param_1 + 0x13a0);
          if (0x18 < uVar3) {
            panic(uVar3,0x19,&PTR_s_src/bacharu.rshehe_00144380);
            do {
              invalidInstructionException();
            } while( true );
          }
          break;
        case 0x6b:
                    /* k */
          *(ulong *)(param_1 + 8) = i + 1;
          if (*(long *)(param_1 + 0x1398) == 0x18) goto exit;
          uVar4 = *(long *)(param_1 + 0x1398) + 1;
          if (0x18 < uVar4) {
            panic(uVar4,0x19,&PTR_s_src/bacharu.rshehe_00144368);
            do {
              invalidInstructionException();
            } while( true );
          }
          uVar3 = *(ulong *)(param_1 + 0x13a0);
          if (0x18 < uVar3) {
            panic(uVar3,0x19,&PTR_s_src/bacharu.rshehe_00144368);
            do {
              invalidInstructionException();
            } while( true );
          }
          break;
        case 0x6c:
                    /* l */
          *(ulong *)(param_1 + 8) = i + 1;
          uVar4 = *(ulong *)(param_1 + 0x13a0);
          if (uVar4 != 0x18) {
            uVar3 = *(ulong *)(param_1 + 0x1398);
            if (0x18 < uVar3) {
              panic(uVar3,0x19,&PTR_s_src/bacharu.rshehe_00144338);
              do {
                invalidInstructionException();
              } while( true );
            }
            if (0x18 < uVar4) {
              panic(uVar4,0x19,&PTR_s_src/bacharu.rshehe_00144338);
              do {
                invalidInstructionException();
              } while( true );
            }
            lVar2 = *(long *)(uVar3 * 200 + param_1 + 0x10 + uVar4 * 8);
            if (lVar2 != 0) goto if2_flag;
            *(ulong *)(param_1 + 0x13a0) = uVar4 + 1;
            goto i++;
          }
          goto exit;
        }
        lVar2 = *(long *)(uVar4 * 200 + param_1 + 0x10 + uVar3 * 8);
        if (lVar2 != 0) {
if2_flag:
          if (lVar2 == 2) {
            flag();
            do {
              invalidInstructionException();
            } while( true );
          }
          break;
        }
        *(ulong *)(param_1 + 0x1398) = uVar4;
      }
i++:
      i = i + 1;
    } while (i != len_in);
  }
exit:
  exit256(0x100);
  do {
    invalidInstructionException();
  } while( true );
}
```

Some points of interest:

- `panic()` is a rust runtime function that terminates the process with an error message. There's 2 checks for `var > 0x18` in each case of the switch. If we `set $rip = (0x555555554000 + 0x973d)` to force one of the calls to `panic()`, we see that those are bound checks:
    > thread 'main' panicked at 'index out of bounds: the len is 25 but the index is 1', src/bacharu.rs:123:20
    > note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
    > [Inferior 1 (process 3673543) exited with code 0145]
- `vi` users will recognize `h j k l` as movement keys. There's also an `i` here, but it seems to only increment a counter stored at `param_1 + 8`, so probably not relevant to the remaining logic.

Ok, so the task's theme is a maze, probably the input we have to supply are the steps to traverse this maze. Let's revisit instruction counting again, this time trying some valid inputs:

```bash
a=(h j k l)
for i in "${a[@]}"; do
  walk="$i"
  inscount=$(echo "$walk" | qemu-x86_64 -d in_asm ./miz 2>&1 | wc -l)
  echo "$inscount $walk"
  for j in "${a[@]}"; do
    walk="$i$j"
    inscount=$(echo "$walk" | qemu-x86_64 -d in_asm ./miz 2>&1 | wc -l)
    echo "$inscount $walk"
    for k in "${a[@]}"; do
      walk="$i$j$k"
      inscount=$(echo "$walk" | qemu-x86_64 -d in_asm ./miz 2>&1 | wc -l)
      echo "$inscount $walk"
    done
  done
done | sort
```

Output:

```
26143 jhh
26143 jhj
26143 jhk
26143 jhl
26143 jjh
...
26186 hj
26186 hk
26186 lj
26186 lk
26188 hhl
26188 hlh
26188 hll
26188 lhh
26188 lhl
26188 llh
26188 llk
26193 hl
26193 lh
26214 hlj
26214 hlk
26214 lhj
26214 lhk
```

Again, it doesn't tell much. Some inputs exit early (e.g. `jhh`), could be because we bumped into a wall after the first `j`. But we see that moving back and forth (e.g. `hl`) naturally runs more instructions, since we never bump into walls. So, looking blindly at these counts won't guide us to the solution.

These walls have a distinct representation in memory, which must be compared against our position. If we look at this conditional:

```c
if (*(long *)(param_1 + 0x13a0) != 0) {
  //...
  goto if2_flag;
}
goto exit;
```

We see that we exit when that variable is zero. Either this variable or `param_1 + 0x1398` are updated on each case, so could they be our position? Would zero be out-of-bounds?

There's also some addressing that falls in range `[0x0..0x13a0]`:

```c
uVar4 = *(ulong *)(param_1 + 0x13a0);
if (uVar4 != 0x18) {
  uVar3 = *(ulong *)(param_1 + 0x1398);
  // ...
  *(long *)(uVar4 * 200 + param_1 + 0x10 + uVar3 * 8);
  // ...
}
```

Probably the maze is stored in this data structure. Let's dump it:

```
dump binary memory /tmp/1 $r8 $r8+0x13a0
```

Output:

<pre><code>
00000000: 0a00 <mark>0000 0000 0000</mark> 0000 <mark>0000 0000 0000</mark>
00000010: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00000020: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00000030: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00000040: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00000050: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00000060: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00000070: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00000080: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00000090: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
000000a0: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
000000b0: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
000000c0: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
000000d0: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
000000e0: 0000 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
000000f0: 0000 <mark>0000 0000 0000</mark> 0000 <mark>0000 0000 0000</mark>
00000100: 0000 <mark>0000 0000 0000</mark> 0000 <mark>0000 0000 0000</mark>
00000110: 0000 <mark>0000 0000 0000</mark> 0000 <mark>0000 0000 0000</mark>
00000120: 0000 <mark>0000 0000 0000</mark> 0000 <mark>0000 0000 0000</mark>
00000130: 0000 <mark>0000 0000 0000</mark> 0000 <mark>0000 0000 0000</mark>
00000140: 0000 <mark>0000 0000 0000</mark> 0000 <mark>0000 0000 0000</mark>
00000150: 0000 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
...
00001340: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00001350: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00001360: 0100 <mark>0000 0000 0000</mark> 0200 <mark>0000 0000 0000</mark>
00001370: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00001380: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
00001390: 0100 <mark>0000 0000 0000</mark> 0100 <mark>0000 0000 0000</mark>
</code></pre>

These are little-endian uint64_t sized values. I've highlighted the part of the uint64_t which is always constant. So, the values are mostly `0` or `1`. One of them is `2`, which seems to be the destination we are trying to reach:

```c
lVar2 = *(long *)(uVar4 * 200 + param_1 + 0x10 + uVar3 * 8);
if (lVar2 != 0) {
    if2_flag:
    if (lVar2 == 2) {
      flag();
      do {
        invalidInstructionException();
      } while( true );
    }
}
```

Recall in the panic message "len is 25"... This must be a 25x25 maze, so a 2D visualization would help. Gimp allows us to import a file as "Raw image data" and then play around with the file offset for alignment:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/InCTF2021/import1.png" alt=""/>
</div>

Each value is stored in 8 * 8-bits, so `25 * 8 = 200` for a 1-bit representation. Sure, if we squint there's a pattern in the preview, but we can avoid the gaps between dots by converting our values from uint64_t to a single byte:

```python
import sys
import struct

with open(sys.argv[1], 'rb') as f:
    data = f.read()
data2 = b""
for i in range(0, len(data), 8):
    v = struct.unpack('<Q', data[i:i+8])[0]
    if v == 1:
        v = b"\xff" # white
    elif v == 2:
        v = b"\x7f" # grey
    else:
        v = b"\x00" # black
    data2 += v
with open(sys.argv[2], 'wb') as f:
    f.write(data2)
```

Now we can use a 8-bit representation, which is clearer:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/InCTF2021/import2.png" alt=""/>
</div>

Zoomed-in:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/InCTF2021/zoom1.png" alt=""/>
</div>

Ok, but what's the player position? We can confirm in the debugger the initial values stored in `r8+0x1398` and `r8+0x13a0`, and check how they are updated when moving around. The following gdb script allows us to supply inputs in a loop, and check if we bumped into a wall at a certain point and stopped moving. By checking the counter that is incremented on each switch case, we know how many steps we took of the original input we supplied (if we bumped into a wall, then `counter < len(input)`):

```python
import gdb
import struct

# start of FUN_00109590
gdb.execute("b *(0x555555554000 + 0x9597)")
# start of switch case (jmp rax)
gdb.execute("b *(0x555555554000 + 0x95e8)")
# exit
gdb.execute("b *(0x555555554000 + 0x95a4)")

walk = ''
while True:
    # Expecting sequence of [hjkl]*
    walk = input("> ")
    gdb.execute(f"r <<< $(printf '%s' {walk})")

    # Break at start of FUN_00109590, $r8 has the pointer to the maze structure
    inferior = gdb.selected_inferior()
    r8 = int(str(gdb.parse_and_eval("$r8")).split()[0], 10)
    gdb.execute("c")

    while True:
        rip = int(str(gdb.parse_and_eval("$rip")).split()[0], 16)
        if rip == 0x555555554000 + 0x95e8:
            # Break at start of switch case
            pos_base = int(str(gdb.parse_and_eval("$r8")).split()[0], 10)
            x = struct.unpack('<Q', bytearray(inferior.read_memory(r8+0x13a0, 8)))[0]
            y = struct.unpack('<Q', bytearray(inferior.read_memory(r8+0x1398, 8)))[0]
            print(f'{hex(x)} {hex(y)}')
            gdb.execute("c")
        else:
            break

    # Break at exit
    walk_counter = struct.unpack('<Q', bytearray(inferior.read_memory(r8+8, 8)))[0]
    print(walk_counter - 1)
```

Output:

```
# no movement, but advances counter
> iii
0xd 0x1
0xd 0x1
0xd 0x1
3

# no movement, bumping into wall after first step
> j 
0xd 0x1
0
> jj
0xd 0x1
0

# moving left
> h
0xd 0x1
1
> hh
0xd 0x1
0xc 0x1
2

# moving right
> l
0xd 0x1
1
> ll
0xd 0x1
0xe 0x1
2
```

There's an off-by-one when reporting the position, but all the information is there to traverse the maze. First, let's mark the player position on our visualization, by computing the offset in the data structure corresponding to that maze cell, using the addressing expression found earlier:

```
0x1 * 200 + 0x10 + 0xd * 8 = 0x140
```

Patched `0x2` in our dump:

```
00000140: 0200 0000 0000 0000 0000 0000 0000 0000
```

Updated visualization:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/InCTF2021/zoom2.png" alt=""/>
</div>

Now we can just traverse manually. Turns out that `j` and `k` have switched directions, so going down uses `k`...

Here's the complete input:

```
llkkhhhhkkkkhhhhjjhhhhhhkkllkkkkkkhhkkllkklljjlllllljjhhjjllllllkklljjllkklljjllkkkkhhhhkkkkllkkkkhhk
```

When submitted to the remote host, we get the flag:

```
hehe inctf{mizes_are_fun_or_get}
```
