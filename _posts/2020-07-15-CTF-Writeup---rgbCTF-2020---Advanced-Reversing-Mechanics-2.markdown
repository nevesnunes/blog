---
layout: post
title: CTF Writeup - rgbCTF 2020 - Advanced Reversing Mechanics 2
date: 2020-07-15 21:31:39 +0100
tags: ctf reversing constraint-solving z3
---

{% include custom.html %}

# Introduction

[CTF challenges](https://ctfd.io/whats-a-ctf/) in the reversing category can contain complex algorithms that can make it hard to figure out the input (i.e. the flag) a user needs to supply to obtain a specific output.

If approached as **combinatorial problems**, the algorithms can be rewritten as constraints, which are satisfied by a theorem prover. A popular choice in CTFs is [Z3](https://ericpony.github.io/z3py-tutorial/guide-examples.htm).

On this writeup, I'll show my [Z3 solution]({{ site.url }}{{ site.baseurl }}/assets/writeups/rgbCTF2020/solver.py), including some **pitfalls to avoid when converting decompiled functions** into expressions for the python API.

# Description

On this reversing challenge, we are given an [object file]({{ site.url }}{{ site.baseurl }}/assets/writeups/rgbCTF2020/arm_hard.o). If we supply it with the flag, it outputs this byte sequence:

> 0A, FB, F4, 88, DD, 9D, 7D, 5F, 9E, A3, C6, BA, F5, 95, 5D, 88, 3B, E1, 31, 50, C7, FA, F5, 81, 99, C9, 7C, 23, A1, 91, 87, B5, B1, 95, E4,

# Analysis

After decompiling the object file with [Ghidra](https://ghidra-sre.org/), we identify the `main` function, which calls the following function, that takes the input string as a parameter and returns the encrypted result:

```c
void encryptFlag(byte *param_1) {
  byte *pbVar1;
  byte *pbVar2;
  uint uVar3;
  byte bVar4;
  uint uVar5;
  uint uVar6;
  
  bVar4 = *param_1;
  pbVar1 = param_1;
  if (bVar4 == 0) {
    return;
  }
  while( true ) {
    uVar5 = (uint)bVar4;
    uVar3 = uVar5 - 10 & 0xff;
    uVar6 = uVar5;
    if ((bVar4 < 0x50) && (uVar6 = uVar3, 0x50 < uVar3)) {
      uVar6 = uVar5 + 0x46 & 0xff;
    }
    uVar6 = (uVar6 - 7 ^ 0x43) & 0xff;
    pbVar2 = pbVar1 + 1;
    *pbVar1 = (byte)(uVar6 << 6) | (byte)(uVar6 >> 2);
    bVar4 = *pbVar2;
    if (bVar4 == 0) break;
    uVar6 = (int)(pbVar2 + -(int)param_1) % 5;
    bVar4 = bVar4 << (-uVar6 & 7) | bVar4 >> (uVar6 & 0xff);
    if (uVar6 == 2) {
      bVar4 = bVar4 - 1;
    }
    *pbVar2 = bVar4;
    bVar4 = *pbVar2;
    pbVar1 = pbVar2;
  }
  return;
}
```

[Other writeups for this task](https://ctftime.org/task/12318) focused on developing a manual bruteforcing algorithm. This was made possible due to the fact that the **encryption value for a given character doesn't take into account the next characters**. Let's follow how the input parameter is being manipulated:

```c
bVar4 = *param_1; // Take current character's value
pbVar1 = param_1; // Pointer to current character
if (bVar4 == 0) { // Current character ends string (i.e. it is a null byte)?
  return;
}
while( true ) {
    // [...] Calculations with current character
    pbVar2 = pbVar1 + 1; // Pointer to next character
    *pbVar1 = (byte)(uVar6 << 6) | (byte)(uVar6 >> 2); // Update current character's value
    bVar4 = *pbVar2; // Take next character's value
    if (bVar4 == 0) break; // Next character ends string?
    // [...] Calculations with next character
    *pbVar2 = bVar4; // Update next character's value
    bVar4 = *pbVar2; // Store next character to use on loop's next iteration
    pbVar1 = pbVar2; // Advance pointer to next character
}
// [...]
```

Note that while calculations are done for the next character, they don't impact the current character. Therefore:

- We only need previous characters to be correct in order to guess the next character
- Although we know the expected input string length (it is the same length as the output byte sequence), we don't need to supply a string with that length, **we only need a string of length n, where n-1 are the previously known characters, plus the character we want to guess**

Due to these properties, a manual bruteforce becomes feasible and solves the problem in no more then a few seconds.

## Deriving the constraints 

Let's start with our known properties: the output bytes and the flag values (usually a known prefix, in this case `rgbCTF{`, with ASCII values in the middle, ending with `}`).

```python
flag_encrypted = list(b'\x0A\xFB\xF4\x88\xDD\x9D\x7D\x5F\x9E\xA3\xC6\xBA\xF5\x95\x5D\x88\x3B\xE1\x31\x50\xC7\xFA\xF5\x81\x99\xC9\x7C\x23\xA1\x91\x87\xB5\xB1\x95\xE4')
flag_len = len(flag_encrypted)

flag = [BitVec('flag_{:04d}'.format(i), 32) for i in range(flag_len)]
for i, c in enumerate('rgbCTF{'):
    s.add(flag[i] == ord(c))
for i in range(7, flag_len):
    # Ensure ASCII values
    s.add(flag[i] >= 32)
    s.add(flag[i] <= 127)
s.add(flag[-1] == ord('}'))
```

Our Z3 variables are bit vectors (`BitVec()`) stored in an array. Each variable is named `flag_` plus a suffix given by the index.

Next, we add the variables from the encryption function and some of the expressions.  The `bVar4` variable was renamed to clarify the role it plays as current character.

```python
bCurrentChar = BitVec("bCurrentChar", 32) # i.e. bVar4
uVar3 = BitVec("uVar3", 32)
uVar5 = BitVec("uVar5", 32)
uVar6 = BitVec("uVar6", 32)
for i in range(flag_len):
    uVar5 = flag[i]
    uVar3 = (uVar5 - 10) & 0xff
    uVar6 = uVar5
    uVar6 = If(flag[i] < 0x50, 
               If(uVar3 > 0x50, 
                  (uVar5 + 0x46) & 0xff, 
                  uVar3), 
               uVar5)
```

In Z3, symbolic expressions cannot be cast to concrete Boolean values, so we need to rewrite conditional expressions using the `If(condition, then_expression, else_expression)` function. Note that the [comma operator](https://en.wikipedia.org/wiki/Comma_operator) in the original snippet:

```c
uVar6 = uVar5;
if ((bVar4 < 0x50) && (uVar6 = uVar3, 0x50 < uVar3)) {
  uVar6 = uVar5 + 0x46 & 0xff;
}
uVar6 = (uVar6 - 7 ^ 0x43) & 0xff;
```

Can be rewritten as:

```c
uVar6 = uVar5;
if (bVar4 < 0x50) {
    uVar6 = uVar3
    if (0x50 < uVar3) {
        uVar6 = uVar5 + 0x46 & 0xff;
    }
}
uVar6 = (uVar6 - 7 ^ 0x43) & 0xff;
```

Note the clamping done by the binary `&` operator with the value `0xff`. This was <span class="c-badge c-badge-info">pitfall n°1: type information was lost</span> when declaring variables in python, and some operations were done on `unsigned int` variables. While some clamping existed in the decompiled function, other operations had it implicit, such as in the next snippet:

```c
uVar6 = (uVar6 - 7 ^ 0x43) & 0xff;
pbVar2 = pbVar1 + 1;
*pbVar1 = (unsigned char)(uVar6 << 6) | (unsigned char)(uVar6 >> 2);
bVar4 = *pbVar2;
```

Rewritten as:

```python
uVar6 = (uVar6 - 7 ^ 0x43) & 0xff;
flag[i] = (uVar6 << 6 | uVar6 >> 2) & 0xff
s.add(flag[i] == flag_encrypted[i])
```

Since we don't have the casts to `unsigned char`, we can add the clamping with `0xff`. If you miss this, the results will be wrong and no model will satisfy the constraints!

At this point, all calculations were done for the current character, so we added the constraint with the known output value: `s.add(flag[i] == flag_encrypted[i])`.

Moving on:

```python
if i+1 < flag_len:
    bCurrentChar = flag[i+1]
    uVar6 = (i+1) % 5
    bCurrentChar = (bCurrentChar << (-uVar6 & 7) | bCurrentChar >> (uVar6 & 0xff)) & 0xff
    if (uVar6 == 2):
        bCurrentChar = bCurrentChar - 1
    flag[i+1] = bCurrentChar
```

The original comparison with the null byte checks if we are on the last loop iteration or not, which can be done by the equivalent check `i+1 < flag_len`. Any pointer arithmetic was ommited or rewritten with the loop index `i`, since it was only done to compute the current index (`(int)(pbVar2 + -(int)param_1)`) or advance to the next character (`pbVar1 = pbVar2`).

Finally, we obtain a model that satisfies the constraints, and output the variables in a readable format:

```python
if s.check() == sat:
    m = s.model()
    vs = [(v,m[v]) for v in m]
    vs = sorted(vs,key=lambda a: str(a))
    print("".join([chr(int(str(v))) for (k, v) in vs]))
else:
    print(s.__repr__())
```

The `__repr__()` is useful for debugging failed models, since it shows all the conditions that were added. Other functions to consider are `assert_and_track()` in place of `add()`, which allows [tracking which constraints failed to be satisfied](https://stackoverflow.com/questions/45225375/is-there-a-way-to-use-solver-unsat-core-without-using-solver-assert-and-track), when inspected with `proof()` and `unsat_core()`. This catched <span class="c-badge c-badge-info">pitfall n°2: missing an assignment to a z3 variable</span>, which results in some expressions not being part of the constraints, therefore useless in regards to computing a proof.

Running this script outputs the flag:

```
rgbCTF{ARM_ar1thm3t1c_r0cks_fad961}
```

As an additional validation, we could cross-compile the object file into an executable, and confirm that this input will produce the same byte sequence as provided in the challenge description.

```bash
arm-linux-gnueabi-gcc arm_hard.o -o arm_hard -static
qemu-arm -L /usr/arm-linux-gnueabi/ ./arm_hard 'rgbCTF{ARM_ar1thm3t1c_r0cks_fad961}'
```
