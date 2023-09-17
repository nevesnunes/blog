#!/usr/bin/env python3

import ctypes as ct
import os

C_TYPE_MAPPING = {
    'char': ct.c_char,
    'short': ct.c_short,
    'int': ct.c_int,
    'long': ct.c_long,
    'float': ct.c_float,
    'double': ct.c_double,

    'umode_t': ct.c_ushort,
    'unsigned char': ct.c_ubyte,
    'unsigned short': ct.c_ushort,
    'unsigned int': ct.c_uint,
    'unsigned long': ct.c_ulong,
    'unsigned long long': ct.c_ulonglong,
}

libc = ct.CDLL(None)
syscall = libc.syscall
path = ct.c_char_p("/tmp/o.png".encode('latin-1'))
openat = 257
AT_FDCWD = -100
syscall(openat,0xffffff9c, path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o666)
