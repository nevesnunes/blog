#!/usr/bin/env python3

from z3 import *

s = Solver()

i = BitVec("i", 8)
x = BitVec("x", 8)
y = BitVec("y", 8)
z = BitVec("z", 8)
i = i + 1
a = (i) ^ (x ^ z)
b = a + y
c = ((LShR((a + y) & 0xFF, 1)) + z) ^ a

s.add(a == 0x70)
s.add(b == 0x78)
s.add(c == 0xB7)

if s.check() == sat:
    print(s.model())

# [i = 0xff, z = 0x8b, x = 0xfb, y = 0x8]
