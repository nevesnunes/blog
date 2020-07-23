#!/usr/bin/env python3

import gdb
import os
import stat

# start of main
gdb.execute("b *(0x555555554000 + 0xbea)")
gdb.execute("r")

# enable writes on obfuscated block
aligned_addr = (0x555555554000 + 0x973) - (0x555555554000 + 0x973) % 4096
gdb.execute("p (int)mprotect({}, 4096, 7)".format(aligned_addr))

# goto start of deobfuscator function
gdb.execute("set $rip = (0x555555554000 + 0xa5a)")
gdb.execute("b *(0x555555554000 + 0xab8)")
gdb.execute("c")

# validate deobfuscated instructions
gdb.execute("disassemble /r (0x555555554000 + 0x973),(0x555555554000 + 0x973 + 0xe7)")

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
