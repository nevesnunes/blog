#!/usr/bin/env python3

import os
import stat
import sys
import ipdb


process_name = os.path.basename(sys.argv[1])
with open(process_name, "rb") as f:
    process_bytes = bytearray(f.read())
print("read {} bytes".format(hex(len(process_bytes))))

a = 0x640
# Offset taken from `readelf -a`:
# [24] .data             PROGBITS         000000000024e000  0004e000
blob = 0x4E020 + 0x640
with ipdb.launch_ipdb_on_exception():
    for i in range(4096 * 3):
        process_bytes[a + i] = (process_bytes[a + i] & 0xff) ^ (process_bytes[blob + i] & 0xff)
print("patched {} bytes".format(hex(4096 * 3)))

process_name += "_static_deobfuscated"
with open(process_name, "wb") as f:
    f.write(process_bytes)
os.chmod(process_name, os.stat(process_name).st_mode | stat.S_IEXEC)
