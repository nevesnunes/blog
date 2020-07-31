#!/usr/bin/env python3

from Crypto.Cipher import AES

key = b"\x71\x96\xab\xa1\x5d\x50\x37\x04\xfe\x2e\xf8\x14\xad\xbc\x4a\xb3"
data = [
    b"\xbe\x43\x1a\x3a\x1a\xc7\x93\xee\x5a\x7f\x77\x3c\x6e\x51\x0c\x20",
    b"\xec\x7b\x87\x2c\xcd\x83\x3d\xaa\x96\xb2\x63\xbc\x21\x62\x94\x42",
]

iv = b"\x00" * 16
aes = AES.new(key, AES.MODE_CBC, iv)
decrypted_data = aes.decrypt(data[0])

iv = data[0]
aes = AES.new(key, AES.MODE_CBC, iv)
decrypted_data += aes.decrypt(data[1])

print(decrypted_data)
