---
layout: post
title: CTF Writeup - UIUCTF 2020 - RFCland
date: 2020-07-20 13:18:37 +0100
tags:
    - ctf
    - forensics
    - file formats
---

{% include custom.html %}

# Introduction

[CTF challenges](https://ctfd.io/whats-a-ctf/) in the forensics category usually deal with several kinds of data representations, from file formats to memory dumps. On this writeup, the goal was to extract the flag from a network capture in the pcap format.

# Description

> All RFCs are created equal, right?

# Analysis

When opening the [task's pcap]({{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/challenge.pcap) with `wireshark`, we see TCP traffic composed of several conversations. Each conversation is delimited by the [3-way handshake](https://tools.ietf.org/html/rfc793#section-3.4) for establishing a connection:

```
TCP A                                                     TCP B
1.  CLOSED                                                LISTEN
2.  SYN-SENT    --> <SEQ=100><CTL=SYN>                --> SYN-RECEIVED
3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>   <-- SYN-RECEIVED
4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED
5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED
```

Followed by the connection close:

```
TCP A                                                    TCP B
1.  ESTABLISHED                                          ESTABLISHED
2.  (Close)
    FIN-WAIT-1  --> <SEQ=100><ACK=300><CTL=FIN,ACK>  --> CLOSE-WAIT
3.  FIN-WAIT-2  <-- <SEQ=300><ACK=101><CTL=ACK>      <-- CLOSE-WAIT
4.                                                       (Close)
    TIME-WAIT   <-- <SEQ=300><ACK=101><CTL=FIN,ACK>  <-- LAST-ACK
5.  TIME-WAIT   --> <SEQ=101><ACK=301><CTL=ACK>      --> CLOSED
```

A condensed view for these conversations is selecting `Context Menu > Follow > TCP Stream`, where we quickly see the contents at play:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/wireshark1.png" alt="tcp conversation"/>
</div>

1. From "10.136.127.157" to "10.136.108.29": data transmission in json format, containg key "data" and a base64 value;
2. From "10.136.108.29" to "10.136.127.157": response string, containing the length of the received base64 value.

One way to parse these contents is to identify filters for the corresponding packets, which can be obtained by selecting a field in the details pane and selecting `Context Menu > Apply as Filter > Selected`:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/wireshark2.png" alt="apply filter"/>
</div>

Extract the data transmission packets:

```bash
tshark \
  -r challenge.pcap \
  -Y 'data.data && ip.dst_host == 10.136.108.29' \
  -T json \
  > challenge.json
```

Parse contents, decode base64 and dump the decoded data to files:

```python
#!/usr/bin/env python3

from ipdb import launch_ipdb_on_exception
import base64
import binascii
import json
import os
import sys

with open(sys.argv[1], "r") as f:
    contents = f.read()

out_dir = './out'
if not os.path.exists(out_dir):
    os.makedirs(out_dir)

with launch_ipdb_on_exception():
    packets = json.loads(contents)
    for i, packet in enumerate(packets):
        if "data" not in packet["_source"]["layers"]:
            continue

        data = packet['_source']['layers']['data']['data.data'].replace(':', '')
        hex_bytes_clean = ''.join(data.split())
        raw_bytes = binascii.a2b_hex(hex_bytes_clean)
        parsed_data = json.loads(raw_bytes)['data']

        is_decoded = False
        while not is_decoded:
            try:
                decoded_data = base64.b64decode(parsed_data)
                is_decoded = True
            except binascii.Error:
                parsed_data += '0'

        raw_bytes = decoded_data

        with open("{}/{:08d}".format(out_dir, i), 'wb') as f:
            f.write(raw_bytes)
```

Notice how some base64 values seemed to be truncated, so I had to add some padding bytes (`0`) in order to decode them.

I've looked at response messages as well, by counting each distinct type of message:

```bash
tshark \
    -r challenge.pcap \
    -Y 'data.data && ip.dst_host == 10.136.127.157' \
    -T fields \
    -e data.data \
  | sed 's/://g' \
  | xargs -i sh -c 'echo "$1" | xxd -r -p; printf "\n"' _ {} \
  | sed 's/[0-9]\+\( bytes\)/_\1/g' \
  | sort \
  | uniq -c
```

Output:

```
66 cookies? nom nom nom, thanks for sending _ bytes
84 ho brah, you wen sen _ bytes? chee, garans ball-barans i wen use em!
86 Oh, is that all? Well, we'll just.. WAIT, WHAT?! You only sent _ bytes?
78 OwO what's this? _ bytes? wow, thanks, they wewe vewy yummy :)
```

Sure enough, one type complains about the number of received bytes. So maybe our data was being partially sent in some transmissions?

If we check the mime types of our data files:

```bash
file -k * \
    | sed 's/[^:]*:[ \t]*\(.*\)/\1/' \
    | sort \
    | uniq -c \
    | sort -n
```

We see several false positives, a few JPEGs, and unidentified files:

```
    1 MPEG ADTS, layer II, v1,  64 kbps, 44.1 kHz, Stereo\012- data
    1 Non-ISO extended-ASCII text, with CR, NEL line terminators, with escape sequences\012- data
    1 Non-ISO extended-ASCII text, with no line terminators\012- data
    1 PGP Secret Sub-key (v1) [...]
    1 SysEx File -\012- data
    1 TeX font metric data [...]
    1 TTComp archive, binary, 4K dictionary\012- data
    5 COM executable for DOS\012- data
   51 JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, progressive, precision 8, 200x200, frames 3\012- data
  251 data
```

However, when attempting to open one of the images, our image viewer may spit out an unhelpful error:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/viewnior.png" alt="viewer error"/>
</div>

But if we load one of the images in [`Kaitai IDE`](https://ide.kaitai.io/), it seems to be parsed successfully:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/kaitai.png" alt="file format sections"/>
</div>

It appears that the file is truncated, with the last field corresponding to image data. I tried a more fault-tolerant approach by using `imagemagick` to convert these partial JPEGs to PNGs, which allowed me to view them:

```bash
file -k * \
    | grep image \
    | cut -d':' -f1 \
    | xargs -i convert {} {}.png
```

Here are some of them:

<div class="c-container-center c-container-inline">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/1.png" alt=""/>
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/2.png" alt=""/>
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/flag1.png" alt=""/>
</div>

As we can see, they all seem blurry and corrupted, and notably one of them contains the flag! If we check the metadata with `exiftool`, we can see the encoding process is "progressive". If you were fortunate enough to have enjoyed [dial-up speeds in the past](https://youtu.be/ntQ48-d-8x4?t=729), the effect we see in our images corresponds to partially loaded image data, which could be observed with slower download speeds. For images encoded as "baseline", you only got to see a few lines as it was being loaded.

With these insights, I went for a bruteforce approach, simply concatenating the non-image files (filtered by `grep -v image`) with the flag file, and inspecting them one by one to see if the image would get progressively more complete:

```bash
file -k * \
    | grep -v image \
    | cut -d':' -f1 \
    | xargs -i sh -c 'cat 00000095 "$1" > ../out_2/"00000095_$1"' _ {}
```

With this process, we find that files 95 and 106 are a match. Concatenate these two and repeat the process. With the second iteration, we find that files 95, 106 and 223 give us the full flag:

<div class="c-container-center c-container-inline">
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/flag1.png" alt=""/>
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/flag2.png" alt=""/>
    <img src="{{site.url}}{{site.baseurl}}/assets/writeups/UIUCTF2020/flag3.png" alt=""/>
</div>
