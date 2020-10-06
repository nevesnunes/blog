#!/usr/bin/env python3

import os, sys

LOG = 'LOG' in os.environ

def log(message):
    if LOG:
        print(message)

# Parse original archive
with open(sys.argv[1], "rb") as f1:
    c_f1 = f1.read()

    c2_f1 = c_f1[0xC:0xF]
    next_header_offset = int.from_bytes(c2_f1, byteorder="little")
    log(f"next_header_offset: {next_header_offset}")

    # Sizes of SignatureHeader + StartHeader
    start_header_size = 0x20

    next_header_pos = start_header_size + next_header_offset

    nid = c_f1[next_header_pos : next_header_pos + 1]
    # Generic Header
    if nid == b"\x01":
        c2_f1 = c_f1[next_header_pos + 6 : next_header_pos + 8]
        pack_pos = c2_f1[0]
        if c2_f1[0] >= 0x80:
            c2_f1 = bytes([c2_f1[1], c2_f1[0] & 0x0F])
            pack_pos = int.from_bytes(c2_f1, byteorder="little")
        log(f"pack_pos: {pack_pos}")

        # Not applicable to single file archives
        pack_sizes = 0
        log(f"pack_sizes: {pack_sizes}")
    # Encoded Header
    else:
        c2_f1 = c_f1[next_header_pos + 2 : next_header_pos + 4]
        pack_pos_offset = 0
        if c2_f1[0] < 0x80:
            pack_pos_offset = -1
            pack_pos = c2_f1[0]
        else:
            c2_f1 = bytes([c2_f1[1], c2_f1[0] & 0x0F])
            pack_pos = int.from_bytes(c2_f1, byteorder="little")
        log(f"pack_pos: {pack_pos}")

        # Maximum of all pack sizes
        c2_f1 = c_f1[
            next_header_pos + 6 + pack_pos_offset : next_header_pos + 8 + pack_pos_offset
        ]
        pack_sizes = 0
        for i in c2_f1:
            if i > pack_sizes:
                pack_sizes = i
        log(f"pack_sizes: {pack_sizes}")

    begin = start_header_size + pack_pos + pack_sizes
    log(f"PNG begin: {start_header_size} + {pack_pos} + {pack_sizes} = {hex(begin)}")
    end = start_header_size + next_header_offset
    log(f"PNG end: {start_header_size} + {next_header_offset} = {hex(end)}")

    png_part = c_f1[begin:end]
    sys.stdout.buffer.write(png_part)
