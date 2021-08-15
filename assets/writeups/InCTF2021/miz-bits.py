#!/usr/bin/env python3

import sys
import struct

with open(sys.argv[1], 'rb') as f:
    data = f.read()
data2 = b""
for i in range(0, len(data), 8):
    v = struct.unpack('<Q', data[i:i+8])[0]
    if v == 1:
        v = b"\xff"
    elif v == 2:
        v = b"\x7f"
    else:
        v = b"\x00"
    data2 += v
with open(sys.argv[2], 'wb') as f:
    f.write(data2)
