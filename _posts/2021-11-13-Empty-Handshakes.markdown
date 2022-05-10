---
layout: post
title: Empty Handshakes
date: 2021-11-13 10:07:23 +0100
tags: 
    - bugfix
    - networking
    - protocols
---

{% include custom.html %}

When attempting to make a https request from a Qt app, a terse error was returned:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/img/zeal-error.png" alt=""/>
</div>

Which seemed odd, given that curl had no issue doing the same request, without the user specifying any additional certificates. So, what was different?

# Analysis

With `strace -f -k`, we don't find the message text verbatim, but we can search for the last instance of "handshake", then look up for application specific functions:

```
1984033 write(5, "\1\0\0\0\0\0\0\0", 8) = 8
[...]
 > /usr/lib64/libQt5Widgets.so.5.15.2(QPushButton::QPushButton(QString const&, QWidget*)+0x18) [0x34c448]
[...]
 > /usr/lib64/libQt5Widgets.so.5.15.2(QMessageBox::warning(QWidget*, QString const&, QString const&, int, int, int)+0x5f) [0x3f933f]
 > /home/foo/opt/zeal-dev/build/bin/zeal(Zeal::WidgetUi::DocsetsDialog::downloadCompleted()+0x273) [0x4c7e81]
[...]
1984262 write(163, "\1\0\0\0\0\0\0\0", 8) = 8
[...]
 > /usr/lib64/libQt5Network.so.5.15.2(QAbstractSocket::disconnectFromHost()+0xc8) [0xfe128]
 > /usr/lib64/libQt5Network.so.5.15.2(QSslSocketBackendPrivate::checkSslErrors()+0x11b) [0x13f99b]
 > /usr/lib64/libQt5Network.so.5.15.2(QSslSocketBackendPrivate::startHandshake()+0x3ea) [0x143eaa]
```

On an earlier call stack with the "handshake" function, we see OpenSSL specific functions, from libssl.so:

```
 > /usr/lib64/libssl.so.1.1.1l(state_machine.part.0+0x43a) [0x53f3a]
 > /usr/lib64/libQt5Network.so.5.15.2(QSslSocketBackendPrivate::startHandshake()+0x4e4) [0x143fa4]
```

This shows us what Qt ends up using for the SSL connection. We can use the `openssl s_client` tool to compare validation results, since it will use the same library (checked with ldd).

{::options parse_block_html="true" /}
<div class="c-indirectly-related">
We want to know the full URL to also test with curl. While it's given by another dialog message, we could also figure it out with gdb.

Let's look at the actual download function, which appears earlier in the trace:

```
 > /home/foo/opt/zeal-dev/build/bin/zeal(Zeal::WidgetUi::DocsetsDialog::download(QUrl const&)+0x10d) [0x4cb409]
```

This function is also called as part of the retry logic inside `downloadCompleted()`:

```cpp
if (ret == QMessageBox::Retry) {
    QNetworkReply *newReply = download(reply->request().url());
    // ...
}
```

Debugger setup:

```
set follow-fork-mode parent
b Zeal::WidgetUi::DocsetsDialog::download
r
```

Let's inspect `url`:

```
pwndbg> p url
$8 = (const QUrl &) @0x7fffffffb070: {
  d = 0xd569b0
}
pwndbg> telescope url.d 0x20
00:0000│  0xd569b0 ◂— 0xffffffff00000001
01:0008│  0xd569b8 —▸ 0x7fffdc00d110 ◂— 0x500000001
02:0010│  0xd569c0 —▸ 0x7ffff766f260 (QArrayData::shared_null) ◂— 0xffffffff
03:0018│  0xd569c8 —▸ 0x7ffff766f260 (QArrayData::shared_null) ◂— 0xffffffff
04:0020│  0xd569d0 —▸ 0x10c1b70 ◂— 0x1000000001
05:0028│  0xd569d8 —▸ 0xd79740 ◂— 0xb00000001
06:0030│  0xd569e0 —▸ 0x7ffff766f260 (QArrayData::shared_null) ◂— 0xffffffff
07:0038│  0xd569e8 —▸ 0x7ffff766f260 (QArrayData::shared_null) ◂— 0xffffffff
08:0040│  0xd569f0 ◂— 0x0
09:0048│  0xd569f8 ◂— 0x7400720009 /* '\t' */
0a:0050│  0xd56a00 ◂— 0x2400000065 /* 'e' */
[...]
```

A fine structure... Given that we compiled with debug symbols (`cmake -DCMAKE_BUILD_TYPE=Debug`), we can check these fields:

```
pwndbg> p url.d->host.d
$16 = (QString::Data *) 0x10c1b70
pwndbg> p &url.d->host.d->offset
$17 = (qptrdiff *) 0x10c1b80
pwndbg> p url.d->host.d->offset
$18 = 24
pwndbg> x/20wx 0x10c1b70+24
0x10c1b88:      0x00700061      0x002e0069      0x0065007a      0x006c0061
0x10c1b98:      0x006f0064      0x00730063      0x006f002e      0x00670072
0x10c1ba8:      0x00000000      0x40000000      0x00000050      0x00000000
0x10c1bb8:      0x00000061      0x00000000      0xc426e000      0x00007fff
0x10c1bc8:      0x00065848      0x00000000      0x000070f0      0x00000000
```

Seems like our characters are encoded in UTF-16 little endian. These same values can be iterated with `data()`:

```
pwndbg> p url.d->host.d->data()
$39 = (unsigned short *) 0x10c1b88
pwndbg> p &url.d->host.d->data()[1]
$41 = (unsigned short *) 0x10c1b8a
```

After joining them:

```python
>>> ''.join([chr(x) for x in [0x61,0x70,0x69,0x2e,0x7a,0x65,0x61,0x6c,0x64,0x6f,0x63,0x73,0x2e,0x6f,0x72,0x67]])
'api.zealdocs.org'
```

This only gave us the host, so we would need to repeat this process for subpaths, but keywords `QString::Data gdb` point us to some [helper scripts](https://invent.kde.org/sdk/kde-dev-scripts) that pretty print these Qt types.

Funnily enough, casually invoking telescope on the registers gives us the full URL:

```
pwndbg> telescope
10:0080│         0x7fffffffb060 —▸ 0x7fffffffb110 —▸ 0x7fffffffb140 —▸ 0x7fffffffb190 —▸ 0x7fffffffb270 ◂— ...
11:0088│         0x7fffffffb068 —▸ 0x7fffdc009690 —▸ 0x5fccb8 —▸ 0x4c022e ◂— push   rbp
12:0090│ rdx rsi 0x7fffffffb070 —▸ 0xd569b0 ◂— 0xffffffff00000001
13:0098│         0x7fffffffb078 —▸ 0xd77af0 ◂— 0x2300000001
14:00a0│         0x7fffffffb080 —▸ 0x580090 ◂— 'https://api.zealdocs.org/v1'
15:00a8│         0x7fffffffb088 —▸ 0x7fffffffb090 ◂— 0x7fff00000008
16:00b0│         0x7fffffffb090 ◂— 0x7fff00000008
17:00b8│         0x7fffffffb098 —▸ 0x58042c ◂— '/docsets'
```
</div>
{::options parse_block_html="false" /}

Before testing with `openssl s_client`, we should clarify who is actually reporting a handshake error: the client (our app) or the server (the remote host)?

Let's sniff the traffic from curl, filtering by the ip given by `nslookup api.zealdocs.org`:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/img/zeal-curl.png" alt=""/>
</div>

Compare it with the traffic from our client app:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/img/zeal-before-log.png" alt=""/>
</div>

We get to see that it's the client app that decides to terminate the connection with a TCP FIN packet.

There's some "Encrypted Handshake Message" packets, which can be decrypted by [instrumenting OpenSSL functions](https://github.com/saleemrashid/frida-sslkeylog)[^1], so that the private key is logged in this format:

[^1]: Alternatively, we could compile Qt sources with some [debug macro definitions](https://gist.github.com/jeckhart/b2d4af50e371ed4c20c13cabb11e0f15), maybe [a lot of them](https://www.qt.io/blog/2014/12/04/how-to-help-qt-support-help-you-more-efficiently) to understand where exactly the validation logic fails.

```
RSA Session-ID:f310e2aefbb422b9e7ab02afa2fbc3bdfd00107d6d5dd8653340c98b3ee9db36 Master-Key:1f52347840128456110317cb312a38985b2fd212afa6da2793caaa30b374790eb8043ec665cce0599159b4575a6b0415
```

Which is then loaded in wireshark: `Right click on a TLS packet > Protocol Preferences > Transport Layer Security > Pre-Master-Secret Log`

Output:

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/img/zeal-after-log.png" alt=""/>
</div>

Oh, it was just a "Finished" message...

## Certificate Verification

Now that we suspect that our client is the one originating the error, let's check if we can actually verify the certificate chain successfully with other tools.

Let's start with a minimal Qt app that downloads a file from a user provided URL. Keywords `qt example http` direct us to such an [example](https://doc.qt.io/qt-5/qtnetwork-http-example.html), built with:

```bash
cd $path/qtbase
cmake .
cmake --build . --parallel
cd $path/qtbase/examples/network/http
LD_LIBRARY_PATH=$path/qtbase/lib $path/qtbase/bin/qmake -o Makefile *.pro
```

{::options parse_block_html="true" /}
<div class="c-indirectly-related">
Apparently the `cmake` commands do not compile any examples. No README in the repository had any further instructions. Keywords `gist qt makefile` lead me to [how to compile without something called qmake](https://gist.github.com/mishurov/8134532). Well, that's one of the binaries the initial cmake commands built, so now we knew the magic word to search for and land on the intended [tutorial](https://doc.qt.io/qt-5/qmake-tutorial.html)...
</div>
{::options parse_block_html="false" /}

Running the example app with our URL gives us the same error[^2], but with a clearer description:

[^2]: SSL errors seem to be frequent enough in Qt apps that someone bothered to write [slides on this topic](https://www.kdab.com/wp-content/uploads/stories/slides/DD12/Using-SSL-the-right-way-with-qt.odp). More [generic guides](https://maulwuff.de/research/ssl-debugging.html) can also be found.

```
One or more SSL errors has occurred:
The issuer certificate of a locally looked up certificate could not be found
```

---

Moving on to curl, we trace our request:

```bash
curl --head https://api.zealdocs.org/v1/docsets --trace /dev/stderr >/dev/null
```

Which shows us the system certificates that are loaded:

```
* successfully set certificate verify locations:
*  CAfile: /etc/pki/tls/certs/ca-bundle.crt
```

curl does not send any (client) certificate:

```
== Info: TLSv1.3 (OUT), TLS handshake, Client hello (1):
=> Send SSL data, 512 bytes (0x200)
[...]
<= Recv SSL data, 5 bytes (0x5)
0000: 16 03 03 00 6c                                  ....l
== Info: TLSv1.3 (IN), TLS handshake, Server hello (2):
<= Recv SSL data, 108 bytes (0x6c)
[...]
<= Recv SSL data, 5 bytes (0x5)
0000: 16 03 03 10 da                                  .....
== Info: TLSv1.2 (IN), TLS handshake, Certificate (11):
<= Recv SSL data, 4314 bytes (0x10da)
[...]
<= Recv SSL data, 5 bytes (0x5)
0000: 16 03 03 00 04                                  .....
== Info: TLSv1.2 (IN), TLS handshake, Server finished (14):
<= Recv SSL data, 4 bytes (0x4)
0000: 0e 00 00 00                                     ....
=> Send SSL data, 5 bytes (0x5)
0000: 16 03 03 00 46                                  ....F
== Info: TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
=> Send SSL data, 70 bytes (0x46)
```

The request then proceeds without issues.

---

Now, let's check the server's certificate chain:

```bash
openssl s_client -showcerts -connect api.zealdocs.org:443 </dev/null
```

The root CA certificate should be the last issuer:

```
Certificate chain
 0 s:CN = api.ams2-01.zealdocs.org
   i:C = US, O = Let's Encrypt, CN = R3
[...]
 1 s:C = US, O = Let's Encrypt, CN = R3
   i:C = US, O = Internet Security Research Group, CN = ISRG Root X1
[...]
 2 s:C = US, O = Internet Security Research Group, CN = ISRG Root X1
   i:O = Digital Signature Trust Co., CN = DST Root CA X3
```

And we know they are valid:

```
SSL handshake has read 5071 bytes and written 436 bytes
Verification: OK
```

Let's check if our system certificate bundle contains these CA certificates:

```bash
openssl crl2pkcs7 -nocrl -certfile /etc/pki/tls/certs/ca-bundle.crt \
    | openssl pkcs7 -print_certs -text -noout
```

Seems like they are present:

```
Subject: O=Digital Signature Trust Co., CN=DST Root CA X3
[...]
Subject: C=US, O=Internet Security Research Group, CN=ISRG Root X1
```

Therefore, loading this bundle should be enough to verify these CA certificates.

Is our Qt client doing it?

Filtering with `strace -e file -f -k`, we don't find any read operations of that certificate bundle! Instead, it tries to load some other files that don't exist:

```
1984262 newfstatat(AT_FDCWD, "/etc/openssl/certs//8d33f237.0",  <unfinished ...>
[...]
1984262 <... newfstatat resumed>0x7f0d9bffd080, 0) = -1 ENOENT (No such file or directory)
[...]
1984262 newfstatat(AT_FDCWD, "/etc/ssl/certs//4042bcee.0", 0x7f0d9bffd080, 0) = -1 ENOENT (No such file or directory)
```

Turns out that it's a [known issue](https://github.com/owncloud/client/issues/1540). To summarize, some environments generate `c_rehash` symlinks (which should reference certificate files). When these are present, Qt will parse them, skipping any existing bundles, even if the symlinks don't reference any valid files.

# Solution

Keywords `qnetworkaccessmanager add ssl ca cert` eventually lead to a [snippet](https://qgis.org/api/2.18/qgsnetworkaccessmanager_8cpp_source.html) that hinted at how to set the certificates for requests:

```cpp
QSslConfiguration sslconfig( pReq->sslConfiguration() );
sslconfig.setCaCertificates( QgsAuthManager::instance()->getTrustedCaCertsCache() );
// [...]
pReq->setSslConfiguration( sslconfig );
```

Now, how to get the system certificates? One way to find out is to download the qtbase sources, which contain the QSslConfiguration class (adapt to your favourite distro):

```bash
sudo dnf debuginfo-install qt5-qtbase
```

Then, `grep -rin cacertificate` matches this function definition:

```cpp
/*!
    \since 5.5

    This function provides the CA certificate database
    provided by the operating system. The CA certificate database
    returned by this function is used to initialize the database
    returned by caCertificates() on the default QSslConfiguration.

    \sa caCertificates(), setCaCertificates(), defaultConfiguration(),
    addCaCertificate(), addCaCertificates()
*/
QList<QSslCertificate> QSslConfiguration::systemCaCertificates()
{
    // we are calling ensureInitialized() in the method below
    return QSslSocketPrivate::systemCaCertificates();
}
```

Finally, we have all the parts to go to our client app's request building function and add these system certificates:

```diff
diff --git a/src/libs/core/networkaccessmanager.cpp b/src/libs/core/networkaccessmanager.cpp
index 95200f9..26b88ed 100644
--- a/src/libs/core/networkaccessmanager.cpp
+++ b/src/libs/core/networkaccessmanager.cpp
@@ -71,5 +71,9 @@ QNetworkReply *NetworkAccessManager::createRequest(QNetworkAccessManager::Operat
         op = QNetworkAccessManager::GetOperation;
     }
+
+    QSslConfiguration sslConfig = overrideRequest.sslConfiguration();
+    sslConfig.setCaCertificates(QSslConfiguration::systemCaCertificates());
+    overrideRequest.setSslConfiguration(sslConfig);

     return QNetworkAccessManager::createRequest(op, overrideRequest, outgoingData);
 }
```

With these changes, requests are now successful.
