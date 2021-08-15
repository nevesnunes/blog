#!/usr/bin/env python3

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

    # Break at start of FUN_00109590, $r8 has the pointer to the game structure
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
