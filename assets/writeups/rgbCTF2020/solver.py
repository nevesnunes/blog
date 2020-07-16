#!/usr/bin/env python3

from z3 import *
import os

z3.set_param(proof=True)
s = Solver()

# Known input
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

bCurrentChar = BitVec("bCurrentChar", 32)
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
    uVar6 = (uVar6 - 7 ^ 0x43) & 0xff
    flag[i] = (uVar6 << 6 | uVar6 >> 2) & 0xff
    s.add(flag[i] == flag_encrypted[i])
    if i + 1 < flag_len:
        bCurrentChar = flag[i + 1]
        uVar6 = (i + 1) % 5
        bCurrentChar = (bCurrentChar << (-uVar6 & 7) | bCurrentChar >> (uVar6 & 0xff)) & 0xff
        if (uVar6 == 2):
            bCurrentChar = bCurrentChar - 1
        flag[i + 1] = bCurrentChar

print("Solving...")
if s.check() == sat:
    m = s.model()
    vs = [(v, m[v]) for v in m]
    vs = sorted(vs, key=lambda a: str(a))
    print("".join([chr(int(str(v))) for (k, v) in vs]))
else:
    print(s.__repr__())
    # print(s.proof())
    # print(s.unsat_core())
