#!/usr/bin/env python3

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

for candidate in range(0, 255):
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
