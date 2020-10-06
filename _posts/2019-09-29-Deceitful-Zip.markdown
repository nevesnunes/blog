---
layout: post
title: Deceitful Zip
date: 2019-09-29 00:00:00 +0100
tags: compression cryptography
---

What appeared to be a regular zip file could not be successfully extracted. Each extracted file would be empty or contain junk bytes. The file hierarchy could be read, and none of those files were password protected. Could there be some actual corruption in the zip, or was something else going on?

## Analysis

Various extractors complained about corrupted data, or crashed in mysterious ways, such as `jar xvf` with `java.io.IOException: Push back buffer is full`.

Our zip was an instance of a `xod`, which is a [web optimized xps used by the web viewer PDFTron](https://www.pdftron.com/samples/web/samples/viewing/viewing-with-custom-server/). A xps is functionally similar to a pdf: it is organized as a hierarchy of pages (xml) and detached resources contained in those pages (fonts and images). The `xod` has some changes in the hierarchy, but the underlying implementation uses the same xml elements as a xps.

We can grab a [`xod` example](https://www.pdftron.com/samples/web/samples/files/demo-annotated.xod) and list files with `unzip -l` (to improve readability, the following was formatted with `tree`):

```
.
├── Annots.xfdf
├── [Content_Types].xml
├── Document
│   ├── DocProps
│   │   └── core.xml
│   └── FixedDocument.fdoc
├── FixedDocumentSequence.fdseq
├── Fonts
│   ├── 0a362aa2-30ce-bf6f-e547-af1200000000.odttf
...
│   └── 0a362aa2-30ce-bf6f-e547-af1200000009.odttf
├── Images
│   ├── 1.jpg
│   └── 3.jpg
├── Pages
│   ├── 1.xaml
│   ├── 2.xaml
│   └── _rels
│       ├── 1.xaml.rels
│       └── 2.xaml.rels
├── _rels
├── Struct
│   ├── 1.xml
│   ├── 2.xml
│   └── font.xml
└── Thumbs
    ├── 1.jpg
    └── 2.jpg
```

This hierarchy matches the one present in the invalid zip.

<span class="c-badge c-badge-info">Hypothesis:</span> It seems all files are present, so maybe our issue is in the metadata.

Attempting to fix it with `zip -F` or `zip -FF` didn't work (the latter recreates the central directory listing, so that can be ruled out of the issue). Therefore, a manual approach was needed.

To explore this metadata and check if all its values were valid, we used [`kaitai_struct`](https://github.com/kaitai-io/kaitai_struct), in particular the [Web IDE](https://ide.kaitai.io/):

<div class="c-container-center">
    <img src="{{site.url}}{{site.baseurl}}/assets/img/kaitai_ide.png" alt="Kaitai Web IDE with a zip loaded"/>
</div>

In addition to the IDE, a parser can be generated, so that general purpose scripting can be done on a zip file:

```bash
git clone --recursive https://github.com/kaitai-io/kaitai_struct.git
./kaitai-struct-compiler-0.8/bin/kaitai-struct-compiler \
    --target python \
    ./kaitai_struct/formats/archive/zip.ksy
```

Each compressed file is represented by a `PkSection` field, with its corresponding metadata contained in `PkSection/LocalFile/LocalFileHeader` and its compressed data contained in `PkSection/LocalFile/body`.

To iterate through all `PkSection` fields in our scripts, the generated parser was modified to keep track of each starting address:

```diff
@@ -253,6 +253,7 @@
             self._read()

         def _read(self):
+            self.global_pos = self._io.pos()
             self.magic = self._io.ensure_fixed_contents(b"\x50\x4B")
             self.section_type = self._io.read_u2le()
             _on = self.section_type
```

We can aggregate the files under observation by file type.

Text files (e.g. xml) are always compressed (`compressionMethod = DEFLATED`), while image files (e.g. jpg) are left uncompressed (`compressionMethod = NONE`). A jpg can be identified by the string `JFIF` in the byte sequence `FF D8 FF E0 ?? ?? 4A 46 49 46`. Since image data is encoded with a lossy compression, these files aren't compressed again in a zip. That would be a waste of CPU resources due to diminishing returns.

As a result, the **magic bytes of a jpg file are preserved inside the body field**. Even if this file format didn't have magic bytes, we could still observe other artifacts, such as sequences of bytes with the same value.

When comparing fields of this example zip with the invalid zip, some differences become explicit:

- **Image files don't have magic bytes.** Instead, the body seems to have a random distribution of byte values, similar to compressed text files.
- **CRC values are zero for all files.** This checksum is used to ensure the integrity of decompressed data is preserved after extracting these files from the zip. While this is an optional check done by decompressors, by default a compressor will calculate these values. We can confirm it isn't needed by taking a valid zip, patching the CRC value to `0`, then running `jar xvf`, which will successfully extract the file with the following warning: `java.util.zip.ZipException: invalid entry CRC (expected 0x0 but got 0xd0d30aae)`.
- **The compressed data doesn't match the specification** of  the `DEFLATE` algorithm. The [header format](https://en.wikipedia.org/wiki/DEFLATE#Stream_format) describes the first 3 bits of a compressed stream as:

```
First bit: Last-block-in-stream marker:
    1: this is the last block in the stream.
    0: there are more blocks to process after this one.

Second and third bits: Encoding method used for this block type:
    00: a stored/raw/literal section, between 0 and 65,535 bytes in length.
    01: a static Huffman compressed block, using a pre-agreed Huffman tree.
    10: a compressed block complete with the Huffman table supplied.
    11: reserved, don't use.
```

Therefore, it would be unexpected if bit sequences `110` or `111` were present. We grabbed a valid `xod` with a larger file count, similar to the one in the invalid zip file, to count and compare the first 3 bits of each `PkSection/LocalFile/body` inside each zip:

<div class="c-container-center c-container-inline">
    First 3 bits for <code>DEFLATE</code> compressed files in a valid vs an invalid zip:
    <img src="{{site.url}}{{site.baseurl}}/assets/img/zip_deflate_ok.svg" alt=""/>
    <img src="{{site.url}}{{site.baseurl}}/assets/img/zip_deflate_nok.svg" alt=""/>
</div>

<div class="c-container-center c-container-inline">
    First 3 bits for uncompressed files in a valid vs an invalid zip:
    <img src="{{site.url}}{{site.baseurl}}/assets/img/zip_none_ok.svg" alt=""/>
    <img src="{{site.url}}{{site.baseurl}}/assets/img/zip_none_nok.svg" alt=""/>
</div>

For the valid zip, compressed bits follow the protocol by not matching the reserved method `11`; uncompressed bits `111` match the first magic byte of jpg files, while `001` match the first magic byte of png files.

For the invalid zip, we do get unexpected sequences, proving that the compressed data isn't just a `DEFLATE` stream.

## Reversing the body encoding

<span class="c-badge c-badge-info">Hypothesis:</span> The value reported in `PkSection/LocalFile/LocalFileHeader/compressedSize` doesn't match the actual body length.

If this was the case, `kaitai_struct` would error out while parsing the file. In addition, this can be easily checked by subtracting the addresses of the next `PkSection` magic bytes with the start of the body.

<span class="c-badge c-badge-info">Hypothesis:</span> Another compression method is actually being used, but it was overwritten with `DEFLATE` and `NONE`.

These methods can be ruled out by [bruteforcing through all possible values](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html#localheader), with the following steps:

1. copy bytes of a `PkSection` to a new file (skip the central directory, since it's optional for decompressing);
2. set field `PkSection/LocalFile/LocalFileHeader/compressionMethod` to a value in range `0-19` or `95-98`;
3. extract the new file.

<span class="c-badge c-badge-info">Hypothesis:</span> There is password protection, but the metadata that specifies this feature was cleared.

Marking a file in a zip as password protected is as simple as setting fields `PkSection/LocalFile/LocalFileHeader/flags` and `PkSection/CentralDirEntry/flags` with value `1`.

We still need a password. The invalid zip is used by a closed-source application. After decompiling it, finding the hardcoded password was just a matter of running a proximity search for keywords `xod` and `password`:

```bash
grep -A 10 -B 10 --color=always -rin 'xod' . | \
    tee >(grep -i 'password')
```

However, simply using the password didn't result in a successful extraction.

<span class="c-badge c-badge-info">Hypothesis:</span> Compressed data is an encrypted stream.

[According to the PDFTron docs](https://www.pdftron.com/documentation/web/guides/xod-and-encryption/), AES encryption can be applied to a `xod`. In our application, we can find the call to the mentioned web worker constructor (which is how we found out that PDFTron was being used, in addition to keywords `DecryptWorker.js` `window.forge` `aes`).

The SDK is available for download with `npx @pdftron/webviewer-downloader`.

The decryption web worker lies within the suggestive file `webviewer/public/lib/core/DecryptWorker.js`.

We now have all the pieces to decrypt our files: encryption method (AES), password and filenames (both are used to build the AES key), and the source code for decryption. It's just a matter of getting it to run.

{::options parse_block_html="true" /}
<div class="c-indirectly-related">

Web workers have an elaborate message passing protocol that wasn't worth it to setup and getting to work under `node`. A more simple alternative was to include the web worker as a module:

```javascript
const worker = require('./DecryptWorker.js');
```

There was an issue with parts of the code that referenced missing definitions:

- `require("./util")` in the constructor: Given the API methods called inside the worker, with keywords `node` `forge` `startDecrypting` we found the module `node-forge`, installed it, and replaced `"./util"` with `"node-forge"`;

- `self` inside the `postMessage()` handler: seemed to be set somewhere else. We moved the call that referenced it into our script, changed the reference to use the module instance, and wrote the result of that function to a file:

```diff
(function(a) {
    a.a = function(a, e, d) {
         // ...
         c = forge.aes.startDecrypting(c, e);
         c.update(forge.util.createBuffer(a));
-        return c.finish() ? c.output.data : {
-            error: "Bad password or file corrupt"
+        if (c.finish()) {
+            fs.writeFileSync(process.argv[4], c.output.data, 'binary', function(err){
+                console.log(err);
+            });
+            console.log("c.finish():", c.output.data.length);
+        } else {
+            console.log("Bad password or file corrupt");
         }
     }
-})(self);
+})(worker);
```

Now we could directly call the function that would be called in the `postMessage()` handler:

```javascript
worker.a(encryptedStream,
    "verySecurePassword",
    filenameInZip);
```

</div>
{::options parse_block_html="false" /}

After decrypting the files, those that were compressed with `DEFLATE` still needed to be "inflated".

{::options parse_block_html="true" /}
<div class="c-indirectly-related">

This part was heavily minified ([`unminify`](https://github.com/shapesecurity/unminify) accomplished some constant folding, but the logic was still pretty obfuscated), so the methodology was a bit more involved:

- Adding a `debugger;` statement before the `postMessage()` call;
- Stepping into further methods while spraying `console.log()` calls, to get a rough trace of which conditional branches were taken;
- Comparing the returned values of those calls with the inputs, to figure out when we had encrypted data (a large string of bytes), decrypted but compressed data (the string's value changed), and finally decompressed data (readable text). Adding a test for a specific filename allowed us to have reference bytes to check in the decryption phase. In the case of a image file, we could inspect the result and find the magic bytes;
- Given that images wouldn't be decompressed, we also did a proximity search for `jpg` and `inflate`, in order to find a test for that file extension, which would skip the inflate method call. This resulted in drilling down closer to the decompression API call;
- Extracting API function names, static arrays, and constants.

Some points of interest started to emerge:

- A call to a function named `inflate`, with a conditional argument of value `-15`, a valid boundary value for [window size in the `DEFLATE` algorithm](https://zlib.net/manual.html#Advanced);
- Error messages with string `HufBuild`;
- Constant table of copy offsets for distance codes.

Putting all this together, with keywords `js` `Hufbuild` `1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577` (that's the constant table), we found the [original zip library](https://www.onicos.com/staff/iz/amuse/javascript/expert/inflate.txt).

It can be transformed into a module by exporting the actual API function:

```diff
@@ -718,7 +718,7 @@
     return n;
 }
 
-exports.inflate = function zip_inflate(str) {
+function zip_inflate(str) {
     var out, buff;
     var i, j;
```

Then it's used in our script, with the result written to a file:

```javascript
var zip = require('./zip');
// ...
output = zip.inflate(input);
fs.writeFileSync(outputFilename, output, 'binary', function(err){
    console.log(err);
});
```

</div>
{::options parse_block_html="false" /}

With the files decrypted and decompressed, we can put them under the same filesystem hierarchy as described in the original zip, then create a new zip with that directory's contents. The result will be a valid unencrypted `xod`.

## Source code

Available in a [git repository](https://github.com/nevesnunes/zip-frolicking).
