---
layout: post
title: TCP By Disk
date: 2021-10-12 18:10:46 +0100
tags: 
    - networking
    - relays
---

{% include custom.html %}

Ever wanted TCP, but instead of directly connecting a client to a server with sockets, you process requests and responses by writing and reading files? What do you mean "no"? Let me give you one contrived use case.

Suppose you are connecting to a Windows host via RDP. Only the RDP port is open to the internet, and the host can only reach other hosts on a private network. Apparently, there's no way to tunnel connections like you would with e.g. SSH port forwarding.

However, it's possible to have a filesystem share under `\\tsclient`, which is reachable from the guest host. A cursed hypothesis comes to mind: **can we reliably redirect TCP connections through files?**

On the following sections, we will put together some implementations of this filesystem based relay.

# Setup

We will start with a simple localhost scenario. Then, we will bring up remote hosts on virtual machines, configured with a bridged network, and a mounted share that both local and remote hosts can write to.

It's possible to relay TCP connections to files using socat. What is missing is some coordination in how to parse requests and responses, which will vary across implementations.

# Scenarios

## One-shot GET, localhost client and server

**Server script** (echo.py):

```python
from flask import Flask

app = Flask(__name__)

@app.route("/<text>", methods=["GET"])
def echo(text):
    return f"You said (len = {len(text)}): {text}"

if __name__ == "__main__":
    app.run()
```

**Server session**:

```bash
# Terminal 1
./echo.py
# Terminal 2
rm -f request response hello bye
while true; do
    socat -v -d -d \
        FILE:request,creat,ignoreeof,trunc \
        TCP:localhost:5000,retry=10,reuseaddr
    : > hello
    echo "bye" > bye
    tail -F hello | grep -qm1 .
done
```

**Client session**:

```bash
# Terminal 1
while true; do 
    tail -F bye | grep -qm1 .
    dd if=request of=response bs=1 skip="$(cat ./request_len)" >/dev/null 2>&1
    cat response
    : > bye
done
# Terminal 2
echo "hello" > hello
sleep 1  # wait for socat to open and truncate ./request
data='GET / HTTP/1.1\r\n\r\n'
wc --bytes <(echo -n "$data") | cut -d' ' -f1 > request_len
echo "$data" > request
```

Files used for coordination:

- ./request: payload of client HTTP request;
- ./request_len: payload length of client HTTP request;
- ./response: payload of server HTTP response;
- ./hello: written when a new request has been written, signaling the server to read the request file;
- ./bye: written when a new response has been written, signaling the client to read the response file.

Conversation flow:

1. Client (Terminal 2) writes to ./hello, stores payload length in ./request_len, writes payload in ./request;
2. Server reads request from ./request, writes response to ./request, writes to ./bye, waits for next write to ./hello;
3. Client (Terminal 1) reads response from ./request, starting at ./request_len bytes offset.

In this scenario, we avoid depending on socat for the client, but due to the server reading and writing to the same request file, we have to identify the response bytes offset in that file to extract just the response. We will see in the next scenarios that also using socat in the client avoids this manual processing.

## Many POSTs, localhost client and server

**Server script** (echo.py):

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/raw", methods=["POST"])
def echo_raw():
    text = request.get_data()
    print(f"You said (len = {len(text)}): {text}")
    return text

if __name__ == "__main__":
    app.run()
```

**Client script** (echo_client.py):

```python
import os
import requests
import sys
import time
import urllib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

if __name__ == "__main__":
    host = sys.argv[1]
    port = sys.argv[2]

    retries = Retry(total=20, backoff_factor=0.5)
    s = requests.Session()
    s.mount("http://", HTTPAdapter(max_retries=retries))
    while True:
        text = os.urandom(32)
        print(f"Gonna say (len = {len(text)}): {text}")
        while True:
            try:
                r = s.post(f"http://{host}:{port}/raw", data=text)
                break
            except Exception as e:
                pass
        print(f"Got (len = {len(r.content)}): {r.content}")
        assert len(r.content) == len(text)
```

**Client session**:

```bash
# Terminal 1
./echo_client.py
# Terminal 2
while true; do
    socat -v -d -d \
        TCP-LISTEN:5001,retry=10,reuseaddr \
        FILE:request,creat,ignoreeof,trunc
    echo "hello" > hello
    tail -F bye | grep -qm1 .
    : > bye
done
```

To ensure we can send and receive arbitrary bytes, we switch to continuously sent POST requests. Doing it in GET requests would imply URL encoding the payload, which [isn't reliable](https://stackoverflow.com/questions/417142/what-is-the-maximum-length-of-a-url-in-different-browsers). By having socat truncating the file both on the server and the client, request and response payloads won't be present at the same time in the file, so we no longer have to manually extract responses by offset, simplifying the client loop.

## Many POSTs, remote Linux server

**Client session**:

```bash
# Terminal 1
./echo_client.py
# Terminal 2
share=$HOME/share
while true; do
    socat -v -d -d \
        TCP-LISTEN:5001,retry=10,reuseaddr \
        FILE:"$share"/request,creat,ignoreeof,trunc
    echo "hello" > "$share"/hello
    tail -F "$share"/bye | grep -qm1 .
    : > "$share"/bye
done
```

Instead of writing to files in a localhost directory, we write to files in a shared directory, which the remote server reads from.

## Many POSTs, remote Windows server

**Server session**:

```powershell
New-Item -ItemType file -ErrorAction SilentlyContinue hello,bye,request,response
do {
    # Workaround for "Invalid function" thrown by: `get-content hello -totalcount 1 -wait`
    while ((gci hello).length -eq 0) {
        Start-Sleep -Milliseconds 100
    }
    & $env:USERPROFILE\Downloads\socat\socat.exe -v -d -d FILE:request,creat,ignoreeof,trunc TCP:localhost:5000,retry=10
    # Workaround for UTF BOM added by: `echo $null > hello`
    New-Item -ItemType file -Force hello
    echo "bye" > bye
} while ($true)
```

Since the remote host is Windows, our shell commands are now written in powershell, but the coordination logic is equivalent.

# Further Work

- Spinning up socat instances for every request is slow, but we can't just have a socat listening with option `fork`, since we require consistent truncation of the same request file. An alternative would probably involve replacing socat with some script that does this relay, but manages files in a more flexible way;
- Add [request multiplexing](https://stackoverflow.com/questions/17480967/using-socat-to-multiplex-incoming-tcp-connection). Currently, only one client at a time is supported, otherwise the request file would end up mixing payloads from distinct clients.
