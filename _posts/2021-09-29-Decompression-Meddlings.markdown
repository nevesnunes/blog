---
layout: post
title: Decompression Meddlings
date: '2021-09-29 00:00:00 +0100'
tags:
  - compression
  - file formats
  - bruteforce
  - constraint solving
thumbnail: /assets/img/thumbnails/decompression_meddlings.png
---
{% include custom.html %}

Lack of familiarity with a binary format leads us to handle them with conservative expectations. Today, let's subvert two of these expectations with varying degrees of usefulness, each explored in a dedicated part.

Previously, I dissected a [zip file that had its body AES encrypted](https://nevesnunes.github.io/blog/2019/09/29/Deceitful-Zip.html), despite the compression method being set to the typical DEFLATE. This time, we will dig into the DEFLATE format's implementation details.

{::options parse_block_html="true" /}
<div class="c-aside">
# TOC

<!-- toc -->

- [Part I: Alleviating streams](#part-i-alleviating-streams)
  * [Preparing a stream](#preparing-a-stream)
  * [Peeking at the naughty bits](#peeking-at-the-naughty-bits)
  * [Meet the symbols](#meet-the-symbols)
  * [How bad can a bit flip be?](#how-bad-can-a-bit-flip-be)
    + [BFINAL=0 but no more blocks in stream](#bfinal0-but-no-more-blocks-in-stream)
    + [BTYPE=3 which is reserved](#btype3-which-is-reserved)
    + [HDIST=31 which is more than allowed](#hdist31-which-is-more-than-allowed)
    + [Lengths repeated are greater than HDIST count](#lengths-repeated-are-greater-than-hdist-count)
    + [Trailing bytes that should be ignored](#trailing-bytes-that-should-be-ignored)
    + [Distance too far back](#distance-too-far-back)
    + [Distance valid but bad](#distance-valid-but-bad)
  * [Guidance from structured data](#guidance-from-structured-data)
  * [Isn't this solution just glorified bruteforcing?](#isnt-this-solution-just-glorified-bruteforcing)
- [Part II: Embellishing streams](#part-ii-embellishing-streams)
  * [Playing well with parsers](#playing-well-with-parsers)
  * [Applying the message](#applying-the-message)
- [Further work](#further-work)
- [References](#references)

<!-- tocstop -->

</div>
{::options parse_block_html="false" /}

# Part I: Alleviating streams

**Suppose a zip file gets some bytes corrupted. Can we decompress it?**

Some metadata cases would be simple to deal with:

- Filenames with unexpected characters: if they are reserved characters in the target filesystem, just patch in some valid characters;
- Compressed size larger than file size: can be ignored by decompressors.

Most likely, the corruption falls not in the metadata header, but in the compressed stream: consider that a zip file containing a single compressed file would have header and footer sizes both less than 100 bytes, as the rest of the file size would be taken by the stream:

```bash
zip - -X -FI -r <(printf '%s' '') 2>/dev/null | wc -c
# 146 total, 0 from input

zip - -X -FI -r <(dd if=/dev/urandom of=/dev/stdout bs=1M count=1) 2>/dev/null | wc -c
# 1048880 total, 1024*1024=1048576 from input
```

But could we still recover the original bytes from a corrupted stream?

## Preparing a stream

On the following sections, we'll use as an example a [JSON file](https://raw.githubusercontent.com/aquasecurity/vuln-list/0756b586549026400f91221eb748a0df4251a17b/nvd/2011/CVE-2011-4925.json) that was zipped ([output file](https://github.com/nevesnunes/deflate-frolicking/blob/master/000_samples/CVE-2011-4925.zip)):

```bash
zip -X CVE-2011-4925.zip CVE-2011-4925.json
```

Let's inspect the data structure of this zip file:

```bash
ksv CVE-2011-4925.zip ~/opt/kaitai_struct_formats_HEAD/archive/zip.ksy
```

We can see that the stream starts where the filename entry ends (offset 0x30):

```
[-] [root]                                               00000000: 50 4b 03 04 14 00 00 00 08 00 9b a9 34 53 bb cc | PK..........4S..
  [-] sections (3 = 0x3 entries)                         00000010: 75 39 44 05 00 00 fd 33 00 00 12 00 00 00 43 56 | u9D....3......CV
    [-] 0                                                00000020: 45 2d 32 30 31 31 2d 34 39 32 35 2e 6a 73 6f 6e | E-2011-4925.json
      [.] magic = 50 4b                                  00000030: cd 5b 5d 6f da 48 14 7d cf af 18 79 5f 76 ab 80 | .[]o.H.}...y_v..
      [.] section_type = 1027                            00000040: b1 b1 d3 c4 4f 4b 09 5b 59 1b 20 05 92 4a ad 50 | ....OK.[Y. ..J.P
      [-] body                                           00000050: 34 d8 13 32 5a e3 71 67 c6 a4 51 95 ff be 77 6c | 4..2Z.qg..Q...wl
        [-] header                                       00000060: 70 ec 28 0d b4 ea 2e 57 21 12 9e 7b 7d e7 dc 0f | p.(....W!..{}...
          [.] version = 20                               00000070: 9f 33 91 9c 6f 47 84 58 91 48 6f f9 32 97 54 73 | .3..oG.X.Ho.2.Ts
          [.] flags = 0                                  00000080: 91 2a 2b 20 df 60 15 d6 fb d7 83 9b 98 6a 7a b3 | .*+ .`.......jz.
          [.] compression_method = compression_deflated  00000090: 66 52 81 09 2c 96 d7 ee 58 c7 a5 39 15 31 33 de | fR..,...X..9.13.
          [.] file_mod_time = 43419                      000000a0: 9f 8b 4b b2 b9 ab 30 45 19 bb 59 51 1d dd d5 cc | ..K...0E..YQ....
          [.] file_mod_date = 21300                      000000b0: 4d 97 ad 9b db bd 92 dc 04 86 ef 81 db ee 06 34 | M..............4
          [.] crc32 = 964021435                          000000c0: 88 92 5c 69 26 6f 24 53 22 97 11 53 81 16 f2 4b | ..\i&o$S"..S...K
          [.] compressed_size = 1348                     000000d0: ce aa 05 08 9d d2 25 93 81 d3 ee b4 9d ac 13 bc | ......%.........
          [.] uncompressed_size = 13309                  000000e0: a9 ff 6c e0 55 9b ac f3 24 65 92 2e 12 06 db 68 | ..l.U...$e.....h
          [.] file_name_len = 18                         000000f0: 99 b3 9a f9 f1 f8 bf 06 e7 60 06 e7 62 06 d7 c5 | .........`..b...
          [.] extra_len = 0                              00000100: 0c ce c3 0c ce c7 0c ee 04 2b 38 80 87 97 4a 0c | .........+8...J.
          [.] file_name = "CVE-2011-4925.json"           00000110: 38 b4 54 62 c0 a1 a5 12 03 0e 2d 95 18 70 68 a9 | 8.Tb......-..ph.
          [-] extra                                      00000120: c4 80 43 4b 25 06 1c 5a 2a 71 31 53 89 8b 99 4a | ..CK%..Z*q1S...J
            [-] entries (0 = 0x0 entries)                00000130: 5c cc 54 e2 62 a6 12 17 33 95 b8 98 a9 c4 c5 4b | \.T.b...3......K
        [.] body = cd 5b 5d 6f da 48 14 7d cf af 18 79 5…00000140: 25 00 0d 2f 95 94 e0 90 52 49 09 0e 29 95 94 e0 | %../....RI..)...
    [-] 1                                                00000150: 90 52 49 09 0e 29 95 94 e0 90 52 49 09 ee 10 54 | .RI..)....RI...T
      [.] magic = 50 4b                                  00000160: b2 0f b6 43 fd 7d b3 1f b6 43 d0 c8 7e c8 0e c1 | ...C.}...C..~...
      [.] section_type = 513                             00000170: 21 fb 20 83 69 43 8a ac 8b 18 19 d6 39 eb a2 9d | !. .iC......9...
      [+] body                                           00000180: b3 6e fb 10 42 b5 1f b2 43 a8 d4 7e c8 0e 21 51 | .n..B...C..~..!Q
    [+] 2                                                00000190: fb 21 c3 aa 4f dd f6 5b b4 c8 4e d1 22 3b 43 8b | .!..O..[..N.";C.
```

And ends before the next zip file section, which starts with bytes `PK` (offset 0x574):

```
[-] [root]                        00000360: e9 f8 04 46 17 fa 05 5c a0 74 b0 9d 84 61 d1 e4 | ...F...\.t...a..
  [-] sections (3 = 0x3 entries)  00000370: 5e b3 c9 d3 cd bd e4 dd 43 46 95 6a 4e 20 a0 29 | ^.......CF.jN .)
    [+] 0                         00000380: 87 a7 78 4e 2e c2 e9 ac 69 d7 74 59 bc e6 3c 6f | ..xN....i.tY..<o
    [-] 1                         00000390: ac e6 32 31 fe 77 5a 67 81 6d c3 d3 9f de c3 04 | ..21.wZg.m......
      [.] magic = 50 4b           000003a0: b5 23 b1 b2 13 ae b4 b2 eb 98 6d 03 d9 ee 38 76 | .#........m...8v
      [.] section_type = 513      000003b0: c7 b7 9d da 1c 1c ff 5c de 13 16 fc cf b9 37 d9 | .......\......7.
      [+] body                    000003c0: f1 b2 78 b5 bb 3e 06 bf a6 34 67 fb 97 c6 7b db | ..x..>...4g...{.
    [+] 2                         000003d0: 3d 75 5e c9 65 3a e8 5f 8d c2 de 3e d9 5c b3 34 | =u^.e:._...>.\.4
                                  [...]
                                  00000560: b2 7c 01 54 7b f7 dc cf 69 39 5d e3 e7 78 9f ac | .|.T{...i9]..x..
                                  00000570: a3 c7 7f 01 50 4b 01 02 1e 03 14 00 00 00 08 00 | ....PK..........
```

If you don't wan't to get your hands dirty, the stream can also be [extracted programmatically using kaitai_struct](https://github.com/nevesnunes/zip-frolicking/blob/master/kaitai_struct/dump_first_stream.py).

Comparing the DEFLATE stream with the original zip file, with [summarized distinct bytes](https://github.com/nevesnunes/aggregables/blob/master/aggregables/differences/hexdiff.py):

```diff
hexdiff.py -c -l 40 CVE-2011-4925.zip CVE-2011-4925.deflate.out
--- CVE-2011-4925.zip
+++ CVE-2011-4925.deflate
-        0x0: 504b0304140000000800 [...] 2d343932352e6a736f6e -> b'PK\x03\x04\x14\x00\x00\x00\x08\x00' [...] b'-4925.json' [+ 28 byte(s)]
  0x30,  0x0: cd5b5d6fda48147dcfaf [...] 5de3e7789faca3c77f01 -> b'\xcd[]o\xdaH\x14}\xcf\xaf' [...] b']\xe3\xe7x\x9f\xac\xa3\xc7\x7f\x01' [+ 1328 byte(s)]
-0x574,0x544: 504b01021e0314000000 [...] 40000000740500000000 -> b'PK\x01\x02\x1e\x03\x14\x00\x00\x00' [...] b'@\x00\x00\x00t\x05\x00\x00\x00\x00' [+ 66 byte(s)]
```

## Peeking at the naughty bits

DEFLATE streams are encoded in **bit-aligned values**. Given that a lot of common editing tools only go down to the granularity of bytes (e.g. hex editors can list bits, but you can't directly patch or truncate bits), we will need something more suited for our experiments.

[infgen](https://github.com/madler/infgen) is a DEFLATE disassembler, apparently based on the [puff.c inflater](https://github.com/madler/zlib/blob/master/contrib/puff/puff.c), which applies the same validations as [zlib's inftrees.c](https://github.com/madler/zlib/blob/master/inftrees.c).

Still, it lacked a lot of needed verbosity, in particular which bits parsed at which offset matched a given token, along with traces of dynamic huffman table construction. Therefore, I extended it in my [fork](https://github.com/nevesnunes/infgen) to include such details.

Below is an illustrated breakdown of what is represented in one of the fork's log entries:

```
                               .------> 1st..2nd bits parsed
                               |
                               |       ,--> 6 bits skipped (already parsed)
                               +      +
       DEBUG 00000087 6: 0x2e  01......
                    + +     +  ____0111 (need 6, decode bitbuf (RTL))
                    | |     |  +      +
next byte index <---' |     |  |       `----> 3rd..6th bits parsed
(used in next parsing)|     |  |
                      |     |  '------> 4 bits remaining from byte 0x86
next bit index <------'     |
(used in current parsing)   |
                            |
hex value parsed <----------'
(= 0b101110 from bits read in right-to-left order)
```

Now we should be able to cover many possible errors, since we can lookup which exact bits to replace.

## Meet the symbols

With DEFLATE, we don't need the full payload to start decompression output, since compressed bytes are read as a stream, and can be decompressed on the fly, one byte at a time. Bits are parsed from one or more bytes until a symbol is decoded.

To understand how the wrong symbol can affect output, we can check in the specification the possible values:

- 0..255: **literal bytes**, from the alphabet of byte values (e.g. `symbol 65` = byte 0x41 = "A");
- 256: **end-of-block**;
- 257..285: **lengths for <length, backward distance> pairs** (e.g. `<2, 4>` = copy 2 bytes starting at 4 bytes ago in the output, so if output is "12345678", we would get "56", and any other subsequent distance would be relative to the new output "1234567856").
    - Always followed by: 0..29: **distances for <length, backward distance> pairs**

[YouFLATE](https://github.com/XlogicX/YouFLATE) allows us to interactively craft streams. Combined with infgen, the relations between these symbols become more evident:

```
# ./youflate.pl

Current Tokens: A4,1B
ASCIIHex Data: 7304012700
Uncompressed data: AAAAAB

# echo "7304012700" | xxd -r -p | infgen -dd

                    +---> bits parsed for each token
              .-----'-----.
last        ! 1              +---> BFINAL=1
fixed       ! 01             +---> BTYPE=1: static huffman tables, so no
literal 'A  ! 01110001      -.              table entries included in stream
match 4 1   ! 00000 0000010  +---> symbols
literal 'B  ! 01110010       |
end         ! 0000000       -'
            ! 00 +---> unused bits (byte padding)
```

## How bad can a bit flip be?

Before coming up with a solution, let's investigate how decompressors deal with corrupted streams.

After an attempt at decompression, we can have two types of end result:

- None / partial output, due to **metadata errors** which stop further parsing;
- Full but bad output, due to **length/distance errors** that result in decoding the wrong symbols.

If the compressed stream was parsed until the end, then we got the "full" output. For the parser, bad output is still valid output. The offset that has corrupted bytes could go undetected until a metadata error or the end of the stream is reached. When does that error happen? Maybe close to the corrupted byte, maybe many bytes later. It depends on how the next symbols will be decoded.

How about some examples? As usual when parsing file formats, different tools have different behaviours...

### BFINAL=0 but no more blocks in stream

Comparing [original](https://github.com/nevesnunes/deflate-frolicking/blob/master/000_samples/CVE-2011-4925.deflate) with [modified](https://github.com/nevesnunes/deflate-frolicking/blob/master/100_BFINAL0/CVE-2011-4925.deflate):

```diff
hexdiff.py -c -l 40 ...
--- 000_samples/CVE-2011-4925.deflate
+++ 100_BFINAL0/CVE-2011-4925.deflate
-        0x0: cd -> b'\xcd'
+        0x0: cc -> b'\xcc'
         0x1: 5b5d6fda48147dcfaf18 [...] 5de3e7789faca3c77f01 -> b'[]o\xdaH\x14}\xcf\xaf\x18' [...] b']\xe3\xe7x\x9f\xac\xa3\xc7\x7f\x01' [+ 1327 byte(s)]

infgen -d ...
--- 000_samples/CVE-2011-4925.deflate
+++ 100_BFINAL0/CVE-2011-4925.deflate
@@ -1,12 +1,12 @@
-DEBUG 00000001 0: 0x1   _______1 (need 1, BFINAL)
-INFO  00000001 1: BFINAL 1 (last block)
+DEBUG 00000001 0: 0x0   _______0 (need 1, BFINAL)
+INFO  00000001 1: BFINAL 0 (not last block)
```

Errors:

```
# zlib.decompress(..., -15) | tail
Traceback (most recent call last):
  File "<string>", line 1, in <module>
zlib.error: Error -5 while decompressing data: incomplete or truncated stream

# zlib.decompressobj(-15).decompress(...) | tail
      "obtainAllPrivilege": false,
      "obtainOtherPrivilege": false,
      "obtainUserPrivilege": false,
      "severity": "MEDIUM",
      "userInteractionRequired": false
    }
  },
  "lastModifiedDate": "2012-02-02T04:09Z",
  "publishedDate": "2012-01-13T04:14Z"
}

# infgen -d ... | grep WARN
WARN  00000548 4: incomplete deflate data

# unzip -p -- ...
  error:  invalid compressed data to inflate CVE-2011-4925.json

# jar xf ...
java.util.zip.ZipException: invalid stored block lengths
	at java.base/java.util.zip.InflaterInputStream.read(InflaterInputStream.java:165)
```

Observations:

- unzip just gives a generic error message about the data stream (it always gives this message, so it will be omitted from the other examples);
- zlib.decompressobj() did not report any error, since additional input could still be expected (it will be omitted when it reports the same error as zlib.decompress() and has no output);
- java's decompressor references block lengths, which is misleading: those come after BFINAL and BTYPE, but such fields weren't present in the stream.

### BTYPE=3 which is reserved

Comparing [original](https://github.com/nevesnunes/deflate-frolicking/blob/master/000_samples/CVE-2011-4925.deflate) with [modified](https://github.com/nevesnunes/deflate-frolicking/blob/master/101_BTYPE3/CVE-2011-4925.deflate):

```diff
hexdiff.py -c -l 40 ...
--- 000_samples/CVE-2011-4925.deflate
+++ 101_BTYPE3/CVE-2011-4925.deflate
-        0x0: cd -> b'\xcd'
+        0x0: cf -> b'\xcf'
         0x1: 5b5d6fda48147dcfaf18 [...] 5de3e7789faca3c77f01 -> b'[]o\xdaH\x14}\xcf\xaf\x18' [...] b']\xe3\xe7x\x9f\xac\xa3\xc7\x7f\x01' [+ 1327 byte(s)]

infgen -d ...
--- 000_samples/CVE-2011-4925.deflate
+++ 101_BTYPE3/CVE-2011-4925.deflate
@@ -1,8704 +1,14 @@
-DEBUG 00000001 1: 0x2   _____10. (need 2, BTYPE)
-INFO  00000001 3: BTYPE 10 (compressed, dynamic)
+DEBUG 00000001 1: 0x3   _____11. (need 2, BTYPE)
+INFO  00000001 3: BTYPE 11 (reserved)
```

Errors:

```
# zlib.decompress(..., -15) | tail
Traceback (most recent call last):
  File "<string>", line 1, in <module>
zlib.error: Error -3 while decompressing data: invalid block type

# zlib.decompressobj(-15).decompress(...) | tail
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "<string>", line 1, in <listcomp>
zlib.error: Error -3 while decompressing data: invalid block type

# infgen -d ... | grep WARN
WARN  00000001 3: invalid deflate data -- invalid block type (3)

# jar xf ...
java.util.zip.ZipException: invalid block type
	at java.base/java.util.zip.InflaterInputStream.read(InflaterInputStream.java:165)
```

### HDIST=31 which is more than allowed

Comparing [original](https://github.com/nevesnunes/deflate-frolicking/blob/master/000_samples/CVE-2011-4925.deflate) with [modified](https://github.com/nevesnunes/deflate-frolicking/blob/master/102_HDIST31/CVE-2011-4925.deflate):

```diff
hexdiff.py -c -l 40 ...
--- 000_samples/CVE-2011-4925.deflate
+++ 102_HDIST31/CVE-2011-4925.deflate
         0x0: cd -> b'\xcd'
-        0x1: 5b -> b'['
+        0x1: 5f -> b'_'
         0x2: 5d6fda48147dcfaf1879 [...] 5de3e7789faca3c77f01 -> b']o\xdaH\x14}\xcf\xaf\x18y' [...] b']\xe3\xe7x\x9f\xac\xa3\xc7\x7f\x01' [+ 1326 byte(s)]

infgen -d ...
--- 000_samples/CVE-2011-4925.deflate
+++ 102_HDIST31/CVE-2011-4925.deflate
@@ -1,6 +1,6 @@
-DEBUG 00000001 0: 0x5b  01011011 (parse)
-DEBUG 00000002 0: 0x1b  ___11011 (need 5, dyn HDIST)
+DEBUG 00000001 0: 0x5f  01011111 (parse)
+DEBUG 00000002 0: 0x1f  ___11111 (need 5, dyn HDIST)
 DEBUG 00000002 5: 0x5d  01011101 (parse)
 DEBUG 00000003 5: 0xa   010.....
                         _______1 (need 4, dyn HCLEN)
-INFO  00000003 1: ! dyn count (HLIT 282, HDIST 28, HCLEN 14)
```

Errors:

```
# zlib.decompress(..., -15) | tail
Traceback (most recent call last):
  File "<string>", line 1, in <module>
zlib.error: Error -3 while decompressing data: too many length or distance symbols

# zlib.decompressobj(-15).decompress(...) | tail
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "<string>", line 1, in <listcomp>
zlib.error: Error -3 while decompressing data: too many length or distance symbols

# infgen -d ... | grep WARN
WARN  00000003 1: invalid deflate data -- too many length or distance codes

# jar xf ...
java.util.zip.ZipException: too many length or distance symbols
	at java.base/java.util.zip.InflaterInputStream.read(InflaterInputStream.java:165)
```

### Lengths repeated are greater than HDIST count

Comparing [original](https://github.com/nevesnunes/deflate-frolicking/blob/master/000_samples/CVE-2011-4925.deflate) with [modified](https://github.com/nevesnunes/deflate-frolicking/blob/master/103_HDIST_repeat_more/CVE-2011-4925.deflate):

```diff
hexdiff.py -c -l 40 ...
--- 000_samples/CVE-2011-4925.deflate
+++ 103_HDIST_repeat_more/CVE-2011-4925.deflate
         0x0: cd5b5d6fda48147dcfaf -> b'\xcd[]o\xdaH\x14}\xcf\xaf'
-        0xa: 18 -> b'\x18'
+        0xa: 1f -> b'\x1f'
         0xb: 795f76ab80b1b1d3c44f [...] 5de3e7789faca3c77f01 -> b'y_v\xab\x80\xb1\xb1\xd3\xc4O' [...] b']\xe3\xe7x\x9f\xac\xa3\xc7\x7f\x01' [+ 1317 byte(s)]

infgen -d ...
--- 000_samples/CVE-2011-4925.deflate
+++ 103_HDIST_repeat_more/CVE-2011-4925.deflate
@@ -95,8610 +95,334 @@
-DEBUG 0000000a 4: 0x18  00011000 (parse)
-DEBUG 0000000b 4: 0xa   1010....
-                        _____000 (need 7, repeat=18 (0 x 11..138))
-INFO  0000000b 3: zeros 21
+DEBUG 0000000a 4: 0x1f  00011111 (parse)
+DEBUG 0000000b 4: 0x7a  1010....
+                        _____111 (need 7, repeat=18 (0 x 11..138))
+INFO  0000000b 3: zeros 133
 DEBUG 0000000b 3: 0xc   _0011... (need 4, decode bitbuf (RTL))
-INFO  0000000b 7: ! decoded len 4 bits 0011 sym_i 32 [index + (code - first)] = [5 + (12 - 12)] = [5] = 5
+INFO  0000000b 7: ! decoded len 4 bits 0011 sym_i 144 [index + (code - first)] = [5 + (12 - 12)] = [5] = 5
 INFO  0000000b 7: lens 5 (0x5)
 [...]
 DEBUG 0000002d 5: 0xbe  10111110 (parse)
 DEBUG 0000002e 5: 0x77  111.....
                         ____1110 (need 7, repeat=18 (0 x 11..138))
-INFO  0000002e 4: zeros 130
-DEBUG 0000002e 4: 0xd   1011.... (need 4, decode bitbuf (RTL))
-INFO  0000002e 0: ! decoded len 4 bits 1011 sym_i 256 [index + (code - first)] = [5 + (13 - 12)] = [6] = 10
 [...]
-INFO  00000544 1: ! decoded len 10 bits 1011111111 sym_i 1087 [index + (code - first)] = [88 + (1021 - 1014)] = [95] = 256
-INFO  00000544 1: decode, symbol=256
-INFO  00000544 1: end
```

Errors:

```
# zlib.decompress(..., -15) | tail
Traceback (most recent call last):
  File "<string>", line 1, in <module>
zlib.error: Error -3 while decompressing data: invalid bit length repeat

# infgen -d ... | grep WARN
WARN  0000002e 4: invalid deflate data -- repeat more lengths than available

# jar xf ...
java.util.zip.ZipException: invalid bit length repeat
	at java.base/java.util.zip.InflaterInputStream.read(InflaterInputStream.java:165)
```

### Trailing bytes that should be ignored

Comparing [original](https://github.com/nevesnunes/deflate-frolicking/blob/master/000_samples/CVE-2011-4925.deflate) with [modified](https://github.com/nevesnunes/deflate-frolicking/blob/master/104_trail/CVE-2011-4925.deflate):

```diff
hexdiff.py -c -l 40 ...
--- 000_samples/CVE-2011-4925.deflate
+++ 104_trail/CVE-2011-4925.deflate
         0x0: cd5b5d6fda48147dcfaf [...] 5de3e7789faca3c77f01 -> b'\xcd[]o\xdaH\x14}\xcf\xaf' [...] b']\xe3\xe7x\x9f\xac\xa3\xc7\x7f\x01' [+ 1328 byte(s)]
+      0x544: 41424344 -> b'ABCD'

infgen -d ...
--- 000_samples/CVE-2011-4925.deflate
+++ 104_trail/CVE-2011-4925.deflate
@@ -8700,5 +8700,18 @@
 INFO  00000544 1: ! decoded len 10 bits 1011111111 sym_i 1087 [index + (code - first)] = [88 + (1021 - 1014)] = [95] = 256
 INFO  00000544 1: decode, symbol=256
 INFO  00000544 1: end
-DEBUG 00000544 1: 0xffffffff 11111111 (parse)
-DEBUG 00000545 1: 0xffffffff 11111111 (parse)
+DEBUG 00000544 1: 0x41  01000001 (parse)
+DEBUG 00000545 1: 0x42  01000010 (parse)
+DEBUG 00000546 1: <<<<<<<<<<<<<< (unparse)
+DEBUG 00000545 1: <<<<<<<<<<<<<< (unparse)
+INFO  00000544 1: ! raw
+DEBUG 00000544 1: 0x41  01000001 (parse)
+DEBUG 00000545 1: 0x1   ______1. (need 1, BFINAL)
+INFO  00000545 2: BFINAL 1 (last block)
+DEBUG 00000545 2: 0x0   ____00.. (need 2, BTYPE)
+INFO  00000545 4: BTYPE 00 (no compression) 8
+DEBUG 00000545 4: 0x42  01000010 (parse)
+DEBUG 00000546 4: 0x43  01000011 (parse)
+DEBUG 00000547 4: 0x44  01000100 (parse)
+DEBUG 00000548 4: 0xffffffff 11111111 (parse)
```

Errors:

```
# zlib.decompress(..., -15) | tail
      "obtainAllPrivilege": false,
      "obtainOtherPrivilege": false,
      "obtainUserPrivilege": false,
      "severity": "MEDIUM",
      "userInteractionRequired": false
    }
  },
  "lastModifiedDate": "2012-02-02T04:09Z",
  "publishedDate": "2012-01-13T04:14Z"
}

# zlib.decompressobj(-15).decompress(...) | tail
      "obtainAllPrivilege": false,
      "obtainOtherPrivilege": false,
      "obtainUserPrivilege": false,
      "severity": "MEDIUM",
      "userInteractionRequired": false
    }
  },
  "lastModifiedDate": "2012-02-02T04:09Z",
  "publishedDate": "2012-01-13T04:14Z"
}

# infgen -d ... | grep WARN
WARN  00000549 4: incomplete deflate data
```

Observations:

- infgen tries to read beyond a block with BFINAL=1, perhaps unintentional.

### Distance too far back

Comparing [original](https://github.com/nevesnunes/deflate-frolicking/blob/master/000_samples/CVE-2011-4925.deflate) with [modified](https://github.com/nevesnunes/deflate-frolicking/blob/master/110_dist_too_far_back/CVE-2011-4925.deflate):

```diff
hexdiff.py -c -l 40 ...
--- 000_samples/CVE-2011-4925.deflate
+++ 110_dist_too_far_back/CVE-2011-4925.deflate
         0x0: cd5b5d6fda48147dcfaf [...] f932975473912a2b20df -> b'\xcd[]o\xdaH\x14}\xcf\xaf' [...] b'\xf92\x97Ts\x91*+ \xdf' [+ 65 byte(s)]
-       0x55: 60 -> b'`'
+       0x55: 40 -> b'@'
        0x56: 15d6fbd7839b986a7ab3 [...] 5de3e7789faca3c77f01 -> b'\x15\xd6\xfb\xd7\x83\x9b\x98jz\xb3' [...] b']\xe3\xe7x\x9f\xac\xa3\xc7\x7f\x01' [+ 1242 byte(s)]

infgen -d ...
--- 000_samples/CVE-2011-4925.deflate
+++ 110_dist_too_far_back/CVE-2011-4925.deflate
@@ -919,7 +919,7 @@
 DEBUG 00000054 0: 0xdf  11011111 (parse)
-DEBUG 00000055 0: 0x60  01100000 (parse)
+DEBUG 00000055 0: 0x40  01000000 (parse)
 DEBUG 00000056 0: 0x1f6 11011111
                         _______0 (need 9, decode bitbuf (RTL))
 INFO  00000056 1: ! decoded len 9 bits 011011111 sym_i 23 [index + (code - first)] = [73 + (502 - 492)] = [83] = 123
@@ -929,545 +929,537 @@
 INFO  00000056 5: ! decoded len 4 bits 0000 sym_i 24 [index + (code - first)] = [0 + (0 - 0)] = [0] = 257
 INFO  00000056 5: decode, symbol=257
 DEBUG 00000056 5: 0x0   ___..... (need 0, length code (257..285))
-DEBUG 00000056 5: 0x15  00010101 (parse)
-DEBUG 00000057 5: 0x1a  011.....
-                        ______01 (need 5, decode bitbuf (RTL))
-INFO  00000057 2: ! decoded len 5 bits 01011 sym_i 24 [index + (code - first)] = [10 + (26 - 26)] = [10] = 8
-DEBUG 00000057 2: 0x5   ___101.. (need 3, distance code)
-INFO  00000057 5: match (len 3, dist 22)
-DEBUG 00000057 5: 0xd6  11010110 (parse)
-DEBUG 00000058 5: 0x0   000.....
-                        _______0 (need 4, decode bitbuf (RTL))
-INFO  00000058 1: ! decoded len 4 bits 0000 sym_i 25 [index + (code - first)] = [0 + (0 - 0)] = [0] = 257
-INFO  00000058 1: decode, symbol=257
-DEBUG 00000058 1: 0x0   _______. (need 0, length code (257..285))
-DEBUG 00000058 1: 0x1a  __01011. (need 5, decode bitbuf (RTL))
-INFO  00000058 6: ! decoded len 5 bits 01011 sym_i 25 [index + (code - first)] = [10 + (26 - 26)] = [10] = 8
-DEBUG 00000058 6: 0xfb  11111011 (parse)
-DEBUG 00000059 6: 0x7   11......
-                        _______1 (need 3, distance code)
-INFO  00000059 1: match (len 3, dist 24)
-DEBUG 00000059 1: 0x5f  1111101. (need 7, decode bitbuf (RTL))
-INFO  00000059 0: ! decoded len 7 bits 1111101 sym_i 26 [index + (code - first)] = [30 + (95 - 90)] = [35] = 67
-INFO  00000059 0: decode, symbol=67
-INFO  00000059 0: literal C (0x43)
-DEBUG 00000059 0: 0xd7  11010111 (parse)
 [...]
+DEBUG 00000056 5: 0x2   010..... (need 3, decode bitbuf (RTL))
+INFO  00000056 0: ! decoded len 3 bits 010 sym_i 24 [index + (code - first)] = [0 + (2 - 0)] = [2] = 21
+DEBUG 00000056 0: 0x15  00010101 (parse)
+DEBUG 00000057 0: 0xd6  11010110 (parse)
+DEBUG 00000058 0: 0x15  00010101
+                        _______0 (need 9, distance code)
+INFO  00000058 1: match (len 3, dist 1558)
 [...]
-INFO  00000544 1: ! decoded len 10 bits 1011111111 sym_i 1087 [index + (code - first)] = [88 + (1021 - 1014)] = [95] = 256
+INFO  00000544 1: ! decoded len 10 bits 1011111111 sym_i 1084 [index + (code - first)] = [88 + (1021 - 1014)] = [95] = 256
 INFO  00000544 1: decode, symbol=256
 INFO  00000544 1: end
 DEBUG 00000544 1: 0xffffffff 11111111 (parse)
```

Errors:

```
# zlib.decompress(..., -15) | tail
Traceback (most recent call last):
  File "<string>", line 1, in <module>
zlib.error: Error -3 while decompressing data: invalid distance too far back

# zlib.decompressobj(-15).decompress(...) | tail
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "<string>", line 1, in <listcomp>
zlib.error: Error -3 while decompressing data: invalid distance too far back
{
  "configurations": {

# infgen -d ... | grep WARN
WARN  00000058 1: distance too far back (dist:1558, max:23)

# unzip -p -- ...
{
  "configurations": {
```

Observations:

- Both zlib.decompressobj() and unzip manage to decompress symbols up to the invalid distance, but stop decompression at that point;
- In contrast, infgen continues parsing beyond the invalid distance until the end of the stream, detecting several unexpected symbols.

### Distance valid but bad

Comparing [original](https://github.com/nevesnunes/deflate-frolicking/blob/master/000_samples/CVE-2011-4925.deflate) with [modified](https://github.com/nevesnunes/deflate-frolicking/blob/master/111_full_but_bad/CVE-2011-4925.deflate):

```diff
hexdiff.py -c -l 40 ...
--- 000_samples/CVE-2011-4925.deflate
+++ 111_full_but_bad/CVE-2011-4925.deflate
         0x0: cd5b5d6fda48147dcfaf [...] d5cc4d97ad9bdbbd92dc -> b'\xcd[]o\xdaH\x14}\xcf\xaf' [...] b'\xd5\xccM\x97\xad\x9b\xdb\xbd\x92\xdc' [+ 116 byte(s)]
-       0x88: 04 -> b'\x04'
+       0x88: c4 -> b'\xc4'
        0x89: 86ef81dbee063488925c [...] 5de3e7789faca3c77f01 -> b'\x86\xef\x81\xdb\xee\x064\x88\x92\\' [...] b']\xe3\xe7x\x9f\xac\xa3\xc7\x7f\x01' [+ 1191 byte(s)]

infgen -d ...
--- 000_samples/CVE-2011-4925.deflate
+++ 111_full_but_bad/CVE-2011-4925.deflate
@@ -1264,7 +1264,7 @@
 INFO  00000088 5: ! decoded len 5 bits 11100 sym_i 74 [index + (code - first)] = [2 + (7 - 4)] = [5] = 105
 INFO  00000088 5: decode, symbol=105
 INFO  00000088 5: literal i (0x69)
-DEBUG 00000088 5: 0x4   00000100 (parse)
+DEBUG 00000088 5: 0xc4  11000100 (parse)
 DEBUG 00000089 5: 0xc   110.....
                         ______00 (need 5, decode bitbuf (RTL))
 INFO  00000089 2: ! decoded len 5 bits 00110 sym_i 75 [index + (code - first)] = [2 + (12 - 4)] = [10] = 258
@@ -1273,9 +1273,9 @@
 DEBUG 00000089 2: 0x8   __0001.. (need 4, decode bitbuf (RTL))
 INFO  00000089 6: ! decoded len 4 bits 0001 sym_i 75 [index + (code - first)] = [3 + (8 - 6)] = [5] = 12
 DEBUG 00000089 6: 0x86  10000110 (parse)
-DEBUG 0000008a 6: 0x18  00......
+DEBUG 0000008a 6: 0x1b  11......
                         _____110 (need 5, distance code)
-INFO  0000008a 3: match (len 4, dist 89)
+INFO  0000008a 3: match (len 4, dist 92)
 DEBUG 0000008a 3: 0x0   _0000... (need 4, decode bitbuf (RTL))
 INFO  0000008a 7: ! decoded len 4 bits 0000 sym_i 76 [index + (code - first)] = [0 + (0 - 0)] = [0] = 257
 INFO  0000008a 7: decode, symbol=257
```

Errors:

```
# zlib.decompress(..., -15) | tail
      "obtainAllPrivilegeionfalse,
      "obtainOtherPrivilegeionfalse,
      "obtainUserPrivilegeionfalse,
      "severityion"MEDIUM",
      "userInteractionRequiredionfalse
    }
  },
  "lastModifiedDate": "2012-02-02T04:09Z",
  "publishedDate": "2012-01-13T04:14Z"
}

# unzip -p -- ... | tail
      "obtainAllPrivilegeionfalse,
      "obtainOtherPrivilegeionfalse,
      "obtainUserPrivilegeionfalse,
      "severityion"MEDIUM",
      "userInteractionRequiredionfalse
    }
  },
  "lastModifiedDate": "2012-02-02T04:09Z",
  "publishedDate": "2012-01-13T04:14Z"
}CVE-2011-4925.json      bad CRC 674112a4  (should be 3975ccbb)

# jar xf ...
java.util.zip.ZipException: invalid entry CRC (expected 0x3975ccbb but got 0x674112a4)
	at java.base/java.util.zip.ZipInputStream.readEnd(ZipInputStream.java:410)
```

Observations:

- The output is unexpected (e.g. `"obtainAllPrivilegeionfalse,` instead of a key value pair), but the stream itself is valid, so infgen doesn't report any warning;
- Corruption is only detected when parsed from a zip, since a checksum is also included (assuming the checksum itself wasn't corrupted as well).

## Guidance from structured data

How would we deal with the previous examples?

- With some context, we could correct simple ones manually (e.g. BTYPE or HDIST values);
- Corrupted dynamic huffman tables are the hardest to handle, since the corruption can happen at a certain offset, but only after parsing the whole table will an error be reported. Our solution will not handle these cases, but some hints on how to manipulate these tables are given in the [next part](#part-ii-embellishing-streams);
- This leaves us with errors in literals and distance codes, which seem to be reported close to the offset where the corruption resides. Our solution will cover these cases.

Let's go back to our zip file. The metadata contains a file entry where we can see the extension of the compressed file (i.e. json). We know that json files are structured data. Therefore, if there are decompression errors that lead to bad output, a json parser would pick up some syntax errors. So, if we manage to **parse a given part of the json without errors**, we can assume **it wasn't hit by corruption**. Sure, we can have e.g. `"a":1` instead of `"a":0`, but those would be very specific edge cases.

What can we use as a parser? [Tree-sitter](https://tree-sitter.github.io/tree-sitter/)!

> [...] a parser generator tool and an incremental parsing library. It can build a concrete syntax tree for a source file and efficiently update the syntax tree as the source file is edited.

We can make use of this syntax tree, which includes useful information, such as error nodes for tokens that contain syntax errors. By taking the corresponding text content of each node, we can reconstruct the json up to the first error node, and measure its length.

The idea is to **generate candidate bytes to replace at the error offset** reported by infgen, take the json output, pass it to tree-sitter, then **check if we got a larger valid syntax tree**: if we did, then probably we were able to fix the corruption!

The following [script](https://github.com/nevesnunes/deflate-frolicking/blob/master/fix_deflate_w_sitter.py) automates this process:

```bash
./fix_deflate_w_sitter.py 110_dist_too_far_back/CVE-2011-4925.deflate
```

For each candidate modification, we keep track of the (partially) successfully parsed output:

```python
for k in range(0xFF):  # Try candidate byte at error index
    data[i + wi] = k
    for k2 in range(0xFF):  # Try candidate byte at error index + 1
        data[i + wi + 1] = k2

        # Buffered decompression using zlib.decompressobj(),
        # up to an error or end of stream
        o, i_, has_errors_ = decompress(data)

        # Extract AST using tree-sitter
        tree = PARSER.parse(o)
        count_valid_tokens, error_node = json_sitter.bfs(tree, o)
        error_byte_i = error_node.start_byte if error_node else float("inf")
```

After aggregating these outputs, the user is presented with a writable file, containing entries with candidate byte modifications. This file works similar to that of "git rebase -i", where we can provide commands on further processing. For our example deflate stream, an error was detected by zlib.decompressobj(), and these candidates were generated:

```
# Commands:
# p, pick <line> = use line for patch
# d, drop <line> = ignore line
# w, write <line> = write state for debugging
# x, expand <line> = show full line contents
#
# Lines starting with '#' will be ignored.
# This file will be restored if no line is picked.

d 0 (@0x54_0xfe_0x63, cvt=11, len=inf) b'{\n  "configurations": 5}'
[...]
d 6 (@0x54_0x27_0x8f, cvt=11, len=inf) b'{\n  "configurations": 6}'
d 7 (@0x54_0xbf_0x66, cvt=35, len=988) b'{\n  "configurations": {\n  "configurations": {\n  "configurations": {\n  "configurations": {\n    "CVE_data_version": "4.0",\n    "nodes": [\n      {\n        "cpe_match": [\n          {\n            "cpe23Uri": "cpe:2.3:a:cluster_resources:torque_resource_manager:1.0.1p0:*:*:*:*:*:*:*",\n [...]
d 8 (@0x54_...._0x60, cvt=26, len=922) b'{\n  "configurations": {\n    "CVE_data_version": "4.0",\n    "nodes": [\n      {\n        "cpe_match": [\n          {\n            "cpe23Uri": "cpe:2.3:a:cluster_resources:torque_resource_manager:1.0.1p0:*:*:*:*:*:*:*",\n            "vulnerable": true\n          },\n          {\n            "cpe23Uri": "cpe:2.3:a:cluster_resources:torque_resource_manager:1.0.1p1:*:*:*:*:*:*:*",\n [...]
[...]
```

Entries are sorted by descending length of tree-sitter's successfully parsed output. Index 0 to 6 are edge cases we can ignore. Index 7 has the largest valid length, but we see some fields being repeated... It's possible that this is an artifact of incorrect length/distance codes, so let's move on. Index 8 only has one byte change (`@0x54_...._0x60` = changed byte at offset 0x55 to 0x60), and it seems closer to what we expect. In we pick this entry (replace command `d` with `p`, save and quit), we end up having the full decompressed output, since there were no more errors detected. Of course, if there were more errors in the stream, a new file would be open, and this process would be repeated for the next offset.

Some approaches that I found reduces time spent evaluating entries:

1. If you know a pattern that should be present at a given point in the output, just delete entries that don't contain it (in vim: `:g!/good_pattern/d`);
2. It's preferable to first go through smaller modifications, which are entries that change a single byte (in vim: `/_\.\.\.`), then go through those that change two bytes.

Turns out that we fixed the exact byte that was needed! To ensure the output we got (stored in a [file](https://github.com/nevesnunes/deflate-frolicking/blob/master/110_dist_too_far_back/%400x54_0xdf_0x60.fix) with name pattern "@offset_0x??_0x??.fix") matches the original bytes:

```bash
diff -au \
    000_samples/CVE-2011-4925.deflate \
    @0x54_0xdf_0x60.fix \
    | wc -c
# 0 (no bytes are different)
```

## Isn't this solution just glorified bruteforcing?

True! It's still worth challenging the assumption that this sort of recovery is simply "[not](https://stackoverflow.com/questions/15694270/how-to-force-zlib-to-decompress-more-than-x-bytes) [possible](https://stackoverflow.com/questions/26794514/how-to-extract-data-from-corrupted-gzip-files-in-python)". With some context on the underlying file formats, we can make educated guesses and be closer to the original data.

# Part II: Embellishing streams

**Can we take a compressed stream, modify it, and still get the same decompressed output?**

Let's make the following observations:

- It's possible to guess if the payload is plaintext or not without decompressing: for each dynamic huffman table, check the literal code lengths: if literals in the ascii range have smaller lengths then other literals, then it's likely to be plaintext, since a compressor assigns smaller lengths to literals that appear more frequently.
    - This implies a relationship between the dynamic huffman table entries and the symbols that appear later on in the block.
- **What if we don't have any literals to compress?** What would be the minimal fields that such a block would need to have to be succesfully parsed?
    - **At least symbol 256 is needed** to encode the end of block, so we also need table entries for it.

Great, so unused table entries (i.e. for other symbols besides symbol 256) are still parsed as lengths, but since the corresponding symbols can just not be included in the block, it doesn't matter which lengths end up being defined: those **unused entries can be overwritten by arbitrary bytes**.

However, huffman codes used in DEFLATE are prefix-free (e.g. since `00` is a prefix of `001`, those two bit sequences cannot correspond to two distinct codes), so there must be some validation being applied to these entries, which we still need to somehow pass...

## Playing well with parsers

In theory, a minimal block would contain:

```
- BFINAL = 1 bit
- BTYPE = 2 bits (dynamic huffman tables = 0b10)
- HLIT count = 5 bits (need 1)
- HDIST count = 5 bits (don't need any)
- HCLEN count = 4 bits (need 1)
- HCLEN table (need 1 length for 1 HLIT entry)
- HLIT table (need 1 length for 1 symbol)
- HDIST table (empty)
- symbol 256
```

{::options parse_block_html="true" /}
<div class="c-indirectly-related">
We need to know how those tables are written before we can fix them.

Let's just focus on the part that matters to our solution, which is how a HCLEN code matches a HLIT code, which in turn matches a symbol to decode. Do check the [references](#references) for the full context.

To decode symbol 256 (a literal):

- We need the HLIT code for a certain length. Symbols can match HLIT codes of the same length, as long as the code values themselves are different. Which n-th code is matched depends on the order they were read in the block (defined by the encoder). But which length exactly?
    - We need the HCLEN code for a certain HLIT code. Which n-th HCLEN code depends on the order they were read in the block (pre-defined).

To be clear, we have a **double huffman decoding** going on here. In the below illustration, you can see how all the decodings map to our infgen fork log output, in this case to decode symbol 10:

```
[begin parsing HCLEN codes]
[...]
    static const short order[19] = /* permutation of code length codes */
        {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
                     ^
                     +`--------------------------------------------------.
                      `-----------------------------------------.        |
                                                                V        +
DEBUG 00000004 2: 0x3   ___011.. (need 3, HCLEN code len, order 0, index 3)
                    +                          ,----------------+
                    |                         V
                     `---> symbol with length 0 has 1st HLIT code with length 3
DEBUG 00000004 5: 0x3   011..... (need 3, HCLEN code len, order 8, index 4)   +
                    +                          ,----------------+             |
                    |                         V                               '-.
                     `---> symbol with length 8 has 2nd HLIT code with length 3 |
[...]                                                                         + |
[end parsing HCLEN codes]                                                     | |
[begin parsing HLIT+HDIST codes]                                              | |
[...]                                                                         | |
[on 10th HLIT bit sequence to decode]                                         | |
                     ,--------------------------------------------------------' |
                    V                                                           |
DEBUG 00000009 3: 0x4   __001... (need 3, decode bitbuf (RTL))                  |
                    +---------------------------------------------------------. |
INFO  00000009 6: ! decoded len 3 bits 001 sym_i 10                           | |
                                                  +---> parsing for symbol 10 | |
                                                    ,-------------------------' |
                                                   |    ,-----------------------'
                             (parsed as 0b100 = 4) |   | (parsed as 0b010 = 2)
                                                   V   V
                  [index + (code - first)] = [1 + (4 - 2)] = [3] = 8
                  +                                                +--------.
                   `---> infgen's decode() ordered symbol table lookup      |
                         - int index; /* index of first code of length len  |
                                         in symbol table */                 |
                         - int code;  /* len bits being decoded */          |
                         - int first; /* first code of length len */        |
                        ,---------------------------------------------------'
                       V
INFO  00000009 6: lens 8 (0x8) +---> symbol 10 has 1st code with length 8 +----.
                       +---------------.                                       |
[...]                                  |                                       |
[end parsing HLIT+HDIST codes]         |                                       |
[begin parsing symbols]                |                                       |
[...]                                  |                                       |
[on symbol 10 parsing]                 |                                       |
                                       |                                       |
DEBUG 0000007e 3: 0xe2  00111...       V                                       |
                        _____010 (need 8, decode bitbuf (RTL))                 |
                                 ,-----+                 ,--> 2nd literal that |
                                V                       |     is decoded and   |
INFO  0000007e 3: ! decoded len 8 bits 01000111 sym_i 2 +     sent to output   |
                                              +                                |
                 (parsed as 0b11100010 = 226) |                                |
                                              '------.       ,-----------------'
                                                      V     V
                  [index + (code - first)] = [53 + (226 - 226)] = [53] = 10
                  +                                                       +
                   `---> infgen's decode() ordered symbol table lookup    |
                            ,---------------------------------------------'
                           V
INFO  0000007e 3: literal 10 (0xa)

[...]
[on symbol 256 parsing]
[end parsing symbols]
```
</div>
{::options parse_block_html="false" /}

Back to how these tables are validated. Unfortunately, decompressors (e.g. zlib) may error on incomplete huffman tables. They expect these tables to contain **enough entries to decode any possible bit sequence** used for symbols, even if such symbols don't end up being present in the block!

Let's look closely at the validation done by infgen when building Huffman tables:

```c
int symbol;         /* current symbol when stepping through length[] */
int len;            /* current length when stepping through h->count[] */
int left;           /* number of possible codes left of current length */
short offs[MAXBITS+1];      /* offsets in symbol table for each length */

/* count number of codes of each length */
for (len = 0; len <= MAXBITS; len++)
    h->count[len] = 0;
for (symbol = 0; symbol < n; symbol++)
    (h->count[length[symbol]])++;   /* assumes lengths are within bounds */
if (h->count[0] == n)               /* no codes! */
    return 0;                       /* complete, but decode() will fail */

/* check for an over-subscribed or incomplete set of lengths */
left = 1;                           /* one possible code of zero length */
for (len = 1; len <= MAXBITS; len++) {
    left <<= 1;                     /* one more bit, double codes left */
    left -= h->count[len];          /* deduct count from possible codes */
    if (left < 0)
        return left;                /* over-subscribed--return negative */
}                                   /* left > 0 means incomplete */

/* [...] */

/* return zero for complete set, positive for incomplete set */
return left;
```

Basically, for each code length up to MAXBITS, variable `left` is doubled and then subtracted by the number of occurrences of the corresponding length being iterated. Sure, we can have different counts across lengths, but in the end, `left` needs to be zero, not more, not less.

Luckily, all these constraints can be expressed as linear functions, which can be fed to our favourite model checker (i.e. z3).

## Applying the message

With this knowledge on how to make a "dummy" block, the plan is to take some existing stream, use it to produce a block that contains a human readable message (read with e.g. strings), overriding some code length table entries. More entries will be added to fix the total. We can then concatenate it with a copy of the original stream.

Let's use the [same example file from the last part](https://github.com/nevesnunes/deflate-frolicking/blob/master/000_samples/CVE-2011-4925.deflate).

The following steps can be reproduced with a [script](https://github.com/nevesnunes/deflate-frolicking/blob/master/embellish.py) (some limitations will be <span class="c-badge c-badge-nok">highlighted</span>):

```bash
./embellish.py ~/CVE-2011-4925.deflate 'hello world!'
```

For starters:

- Apply our arbitrary bytes to the DEFLATE stream ([output file](https://github.com/nevesnunes/deflate-frolicking/blob/master/200_hello/CVE-2011-4925.deflate.add_message.out));
    - Check with infgen that the maximum count for a given length wasn't exceeded (a.k.a. over-subscribed), otherwise we need a smaller / different message;

To retrieve the minimum code lengths needed:

- Reduce the HCLIT and HDIST counts, so that parsing of these codes stops near the end of the last injected byte (at least up to the length for symbol 256, everything else that follows will be replaced);
    - Since we don't need distances, we can set their count to zero (will be parsed as `HDIST=1`, the specification's minimal number of distance codes), then adjust later on after we have the final literal/length counts;
- At this point, infgen is able to construct huffman tables, and our expectation is for them to be under-subscribed:
    ```
    DEBUG 00000031 3: ! iterating litlen len  1 (left  1, left<<1  2, count[len]  0, left-count  2)
    DEBUG 00000031 3: ! iterating litlen len  2 (left  2, left<<1  4, count[len]  0, left-count  4)
    DEBUG 00000031 3: ! iterating litlen len  3 (left  4, left<<1  8, count[len]  1, left-count  7)
    [...]
    DEBUG 00000031 3: ! iterating litlen len 13 (left  8, left<<1 16, count[len]  0, left-count 16)
    DEBUG 00000031 3: ! iterating litlen len 14 (left 16, left<<1 32, count[len]  0, left-count 32)
    DEBUG 00000031 3: ! iterating litlen len 15 (left 32, left<<1 64, count[len]  0, left-count 64)
    WARN  00000031 3: ! under-subscribed litlen (left 64)
    INFO  00000031 3: ! construct litlen: err 64, nlen 261, code.count[0] 181
    ```
- Retrieve the reported code lengths that were used so far:
    ```
    INFO  00000031 3: ! construct litlen len 0 count 181 (n 261)
    INFO  00000031 3: ! construct litlen len 1 count 0 (n 261)
    INFO  00000031 3: ! construct litlen len 2 count 0 (n 261)
    INFO  00000031 3: ! construct litlen len 3 count 1 (n 261)
    [...]
    INFO  00000031 3: ! construct litlen len 15 count 0 (n 261)
    ```
- Compute the additional code lengths constrained to the retrieved lengths.

The following [z3 script](https://github.com/nevesnunes/deflate-frolicking/blob/master/huffman_solver.py) computes solutions for additional code counts:

```python
from z3 import *

MAXBITS = 16
MAXHDIST = 29
MAXHLIT = 285


def solve(code_counts, exclusions, max_codes):
    z3.set_param(proof=True)
    s = Optimize()

    # Known input
    f_len = MAXBITS
    f = [Int("{:04d}".format(i)) for i in range(f_len)]
    for k, v in exclusions.items():
        s.add(f[k] == v)
    s.add(f[0] >= 0)
    s.add(f[1] >= 0)

    # Huffman table validation
    left = 2 - f[1]
    for i in range(2, f_len, 1):
        s.add(And(f[i] >= 0, f[i] < (1 << i)))
        left = (left * 2) - f[i]
    s.add(left == 0)

    # Avoid solutions requiring more codes than the maximum allowed
    s.add(Sum(f) <= max_codes)

    # We prefer solutions with the minimum number of additional lengths necessary,
    # so that we can use larger payloads
    s.minimize(Sum(f))

    # Used code lengths so far
    for k, v in code_counts.items():
        s.add(f[k] >= v)

    if s.check() == sat:
        print("Found solution:")
        model = s.model()
        vs = [(v, model[v]) for v in model]
        vs = sorted(vs, key=lambda a: str(a))
        new_code_counts = {}
        for k, v in vs:
            print(k, v)
            ik = int(str(k), 10)
            new_code_counts[ik] = int(str(v), 10)
        return new_code_counts
    else:
        print(s.unsat_core())
        print(s.__repr__())
        raise RuntimeError("No solution.")
```

As an example, with these literal/length codes and distance codes:

```python
lit_counts = {3: 2, 4: 3, 5: 8, 7: 13, 8: 33, 9: 19, 10: 13}
solve(lit_counts, {}, MAXHLIT)

dist_counts = {10: 1}
solve(dist_counts, {}, MAXHDIST)
```

Output:

```
Found solution:
0000 0
0001 0
0002 0
0003 2
0004 3
0005 9
0006 0
0007 13
0008 33
0009 19
0010 14
0011 0
0012 0
0013 0
0014 0
0015 0
Found solution:
0000 0
0001 1
0002 1
0003 1
0004 1
0005 1
0006 1
0007 1
0008 1
0009 1
0010 2
0011 0
0012 0
0013 0
0014 0
0015 0
```

Afterwards, fix the stream:

- Subtract the solution's counts from the existing counts, producing the additional code lengths;
- Add the additional lengths;
    - <span class="c-badge c-badge-nok">No computed huffman tables</span>: can only add known code lengths (e.g. if we never decoded code length 4, our solution cannot contain it, since we don't know which bits to add to the stream);
- Increase the HCLIT and HDIST counts, to cover the previously added lengths ([output file](https://github.com/nevesnunes/deflate-frolicking/blob/master/200_hello/CVE-2011-4925.deflate.add_all_codes.out));
- Add symbol 256 ([output file](https://github.com/nevesnunes/deflate-frolicking/blob/master/200_hello/CVE-2011-4925.deflate.add_sym_256.out));
    - <span class="c-badge c-badge-nok">No computed huffman tables</span>: have to bruteforce the bits corresponding to this symbol's code length.

Finally, concatenate this new block with a copy of the original stream ([output file](https://github.com/nevesnunes/deflate-frolicking/blob/master/200_hello/CVE-2011-4925.deflate.embellished)):

- Set `BFINAL=0` in the new block, since it's followed by one or more blocks.

To ensure the added block doesn't affect decompression output:

```bash
diff -au \
    <(python3 -c 'import sys,zlib;print(zlib.decompress(open(sys.argv[1], "rb").read(), -15))' CVE-2011-4925.deflate) \
    <(python3 -c 'import sys,zlib;print(zlib.decompress(open(sys.argv[1], "rb").read(), -15))' CVE-2011-4925.deflate.engraced) \
    | wc -c
# 0 (no bytes are different)
```

And just to double check that our message is indeed present in the new stream:

```diff
diff -au <(xxd 000_samples/CVE-2011-4925.deflate) <(xxd 200_hello/CVE-2011-4925.deflate.embellished)
--- 000_samples/CVE-2011-4925.deflate
+++ 200_hello/CVE-2011-4925.deflate.embellished
@@ -1,85 +1,88 @@
-00000000: cd5b 5d6f da48 147d cfaf 1879 5f76 ab80  .[]o.H.}...y_v..
-00000010: b1b1 d3c4 4f4b 095b 591b 2005 924a ad50  ....OK.[Y. ..J.P
-00000020: 34d8 1332 5ae3 7167 c6a4 5195 ffbe 776c  4..2Z.qg..Q...wl
-00000030: 70ec 280d b4ea 2e57 2112 9e7b 7de7 dc0f  p.(....W!..{}...
-00000040: 9f33 919c 6f47 8458 9148 6ff9 3297 5473  .3..oG.X.Ho.2.Ts
 [...]
+00000000: 2c4b 5d6f da48 147d cfaf 1879 5f76 ab80  ,K]o.H.}...y_v..
+00000010: b1b1 d3c4 4f4b 095b 591b 2068 656c 6c6f  ....OK.[Y. hello
+00000020: 2077 6f72 6c64 2167 c6a4 5195 ffbe 776c   world!g..Q...wl
+00000030: 7ace 39e7 9c3b 0669 deea 7ad3 46a2 e87b  z.9..;.i..z.F..{
+00000040: 7ec5 c8fb b25b 058c 8d9d 267e 5a4a d8ca  ~....[....&~ZJ..
 [...]
```

# Further work

- Improving the accuracy of reported syntax errors in tree-sitter grammars would lead to better sorting of candidates in bruteforced error repairing. In some cases, the error node can be marked too early in the syntax tree, causing the calculated valid output length to be smaller than expected;
- Including huffman tables generation when preparing arbitrary payloads for a DEFLATE stream, as the presented proof-of-concept relies on parsing the infgen output, and can miss some cases where it would be possible to fit the message in some offset or fix the dynamic huffman table entries with less constrained solutions.

How about other possibilities?

- Ever wanted to have a zip file that is ridiculously larger than the compressed payload? Just concatenate a series of blocks that only contain symbol 256, and replace the zip's stream with that one concatenated to the original stream, but you also need to adjust metadata offsets and sizes;
- Maybe steganography with unused huffman table entries? Well, be aware that even if there isn't a huge size difference between a zip with hidden messages and the corresponding recompressed zip, it's still suspicious to disassemble blocks with just symbol 256...

# References

- Specification and documentation are a must, bonus points if they compare implementations:
    - [rfc1951 \- DEFLATE Compressed Data Format Specification version 1.3](https://datatracker.ietf.org/doc/html/rfc1951)
    - [An Explanation of the \`Deflate' Algorithm](http://zlib.net/feldspar.html)
    - [Understanding zlib](https://www.euccas.me/zlib/)
- Theory needs to be put into practice, which can be more digestible with smaller scoped tools:
    - [GitHub \- madler/infgen: Deflate disassember to convert a deflate, zlib, or gzip stream into a readable form\.](https://github.com/madler/infgen)
    - [GitHub \- XlogicX/YouFLATE: An interactive tool that allows you to DEFLATE \(compress\) data using your own length\-distance pairs, not merely the most efficient ones as is default with DEFLATE\.](https://github.com/XlogicX/YouFLATE)
- Those who rolled their own implementations can have unique insights on design decisions:
    - [Unspecified edge cases in the DEFLATE standard](https://www.nayuki.io/page/unspecified-edge-cases-in-the-deflate-standard)
    - [DEFLATE Compression Algorithm \| INTEG Process Group](https://jnior.com/deflate-compression-algorithm/)

