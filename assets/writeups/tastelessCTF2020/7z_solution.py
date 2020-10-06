#!/usr/bin/env python3

import os, sys

LOG = 'LOG' in os.environ

def log(message):
    if LOG:
        print(message)

# Parse original archive
with open(sys.argv[1], "rb") as f:
    contents = f.read()

    raw_offset = contents[0xC:0xF]
    next_header_offset = int.from_bytes(raw_offset, byteorder="little")
    log(f"next_header_offset: {next_header_offset}")

    # Sizes of SignatureHeader + StartHeader
    start_header_size = 0x20

    next_header_pos = start_header_size + next_header_offset

    nid = contents[next_header_pos : next_header_pos + 1]
    # Generic Header
    if nid == b"\x01":
        raw_pack_pos = contents[next_header_pos + 6 : next_header_pos + 8]
        pack_pos = raw_pack_pos[0]
        if raw_pack_pos[0] >= 0x80:
            raw_pack_pos = bytes([raw_pack_pos[1], raw_pack_pos[0] & 0x0F])
            pack_pos = int.from_bytes(raw_pack_pos, byteorder="little")
        log(f"pack_pos: {pack_pos}")

        # Not applicable to single file archives
        pack_sizes = 0
        log(f"pack_sizes: {pack_sizes}")
    # Encoded Header
    else:
        pack_pos_offset = 0
        raw_pack_pos = contents[next_header_pos + 2 : next_header_pos + 4]
        if raw_pack_pos[0] < 0x80:
            pack_pos_offset = -1
            pack_pos = raw_pack_pos[0]
        else:
            raw_pack_pos = bytes([raw_pack_pos[1], raw_pack_pos[0] & 0x0F])
            pack_pos = int.from_bytes(raw_pack_pos, byteorder="little")
        log(f"pack_pos: {pack_pos}")

        # Maximum of all pack sizes
        raw_pack_sizes = contents[
            next_header_pos + 6 + pack_pos_offset : next_header_pos + 8 + pack_pos_offset
        ]
        pack_sizes = 0
        for i in raw_pack_sizes:
            if i > pack_sizes:
                pack_sizes = i
        log(f"pack_sizes: {pack_sizes}")

    begin = start_header_size + pack_pos + pack_sizes
    log(f"PNG begin: {start_header_size} + {pack_pos} + {pack_sizes} = {hex(begin)}")
    end = start_header_size + next_header_offset
    log(f"PNG end: {start_header_size} + {next_header_offset} = {hex(end)}")

    png_part = contents[begin:end]
    sys.stdout.buffer.write(png_part)
