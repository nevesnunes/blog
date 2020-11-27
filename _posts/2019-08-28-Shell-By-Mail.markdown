---
layout: post
title: Shell By Mail
date: 2019-08-28 00:00:00 +0100
tags:
    - mail
    - virtualization
---

What if the only way to interact with a remote server would be via SMTP?

Here's an attempt at implementing such a system. Keep in mind this is intended as a proof of concept, not for serious usage.

## Setting up a mail server

The main functionality of this server is routing and delivering mails, which is provided by a Mail Transfer Agent (MTA), e.g. `postfix`. To simplify its configuration, I picked a [docker container](https://hub.docker.com/r/catatnight/postfix/). While there are far more comprehensive solutions[^1], I preferred to build upon a simpler base, to avoid dealing with unneeded interacting components.

[^1]:
    All-in-one containers for mail servers:
    - [mailcow-dockerized](https://github.com/mailcow/mailcow-dockerized)
    - [tomav/docker-mailserver](https://github.com/tomav/docker-mailserver)
    - [hardware/mailserver](https://github.com/hardware/mailserver)
    - [Mailu](https://github.com/Mailu/Mailu)

{::options parse_block_html="true" /}
<div class="c-indirectly-related">
While iterating on my own `Dockerfile`, I had to do some yak shaving:
- `apt` seemed to just freeze when run in the container. Neither `/var/log/dpkg.log` or `/var/log/apt/` contained errors.
- I wanted to see what was going on with `strace`, but the container didn't have it installed. Without `apt` to install it, I decided to make a static build. The project I used only had scripts for ARM, so [I made one for AMD64](https://github.com/andrew-d/static-binaries/pull/28). After copying the binary over to the container and running it:
```sh
/opt/strace ls
# /opt/strace: ptrace(PTRACE_TRACEME, ...): Operation not permitted
```
- It turns out the container needed to run with the corresponding [capability](http://man7.org/linux/man-pages/man7/capabilities.7.html). At first, a reference suggested to [make a seccomp profile with that capability enabled](https://blog.afoolishmanifesto.com/posts/how-to-enable-ptrace-in-docker-1.10/). There was a perl script provided, but my perl installation seemed to be misconfigured, as it couldn't find my installed dependencies:
```
Can't locate JSON.pm in @INC (you may need to install the JSON module) (@INC contains: /home/fn/opt/perl5/lib/perl5  /usr/local/lib64/perl5 /usr/local/share/perl5 /usr/lib64/perl5/vendor_perl /usr/share/perl5/vendor_perl /usr/lib64/perl5 /usr/share/perl5)
```
The library path exists, since `test -f ~/opt/perl5/lib/perl5/JSON.pm` passes. Can you spot the issue above? How about with `strace`:
```
stat("/home/fn/opt/perl5/lib/perl5 /JSON.pm", 0x7ffc2c064c30) = -1 ENOENT (No such file or directory)
```
The extra space was coming from an exported variable:
```bash
PERL5LIB="$HOME/opt/perl5/lib/perl5 $PERL5LIB"
```
Which can be corrected to:
```bash
PERL5LIB="$HOME/opt/perl5/lib/perl5${PERL5LIB:+:${PERL5LIB}}"
```
But none of this was necessary, as `docker run` supports passing capabilities as a parameter, so all I needed was to pass `--cap-add=SYS_PTRACE`.
- To confirm `strace` didn't have any other issue, I made a "contextual diff" of outputs against `ls`, between the container's binary and my host's binary:
```bash
diff -Naurw \
    <(sed 's/0x[0-9a-f]*/0x0/gi; s/[0-9]\+/0/g' ~/1) \
    <(sed 's/0x[0-9a-f]*/0x0/gi; s/[0-9]\+/0/g' ~/2) | \
    vim -
```
Basically this replaces all addresses and numerical values with the same value, filtering out irrelevant differences. Indeed, practically all syscalls were present in both outputs.
- Now with `/opt/strace -f -s 9999 apt update`, there was a noticeable repetition of the same syscalls:
```strace
[pid 150] getrlimit(RLIMIT_NOFILE, {rlim_cur=1073741816, rlim_max=1073741816}) = 0
[pid 150] fcntl(4, F_SETFD, FD_CLOEXEC) = 0
[pid 150] getrlimit(RLIMIT_NOFILE, {rlim_cur=1073741816, rlim_max=1073741816}) = 0
[pid 150] fcntl(5, F_SETFD, FD_CLOEXEC) = 0
[pid 150] getrlimit(RLIMIT_NOFILE, {rlim_cur=1073741816, rlim_max=1073741816}) = 0
[pid 150] fcntl(6, F_SETFD, FD_CLOEXEC) = 0
[pid 150] getrlimit(RLIMIT_NOFILE, {rlim_cur=1073741816, rlim_max=1073741816}) = 0
[pid 150] fcntl(7, F_SETFD, FD_CLOEXEC) = -1 EBADF (Bad file descriptor)
[pid 150] getrlimit(RLIMIT_NOFILE, {rlim_cur=1073741816, rlim_max=1073741816}) = 0
[pid 150] fcntl(8, F_SETFD, FD_CLOEXEC) = -1 EBADF (Bad file descriptor)
...
[pid 150] getrlimit(RLIMIT_NOFILE, {rlim_cur=1073741816, rlim_max=1073741816}) = 0
[pid 150] fcntl(38326, F_SETFD, FD_CLOEXECProcess 149 detached
...
```
- For some reason it was iterating through all available file descriptors. `rlim_max` matches the value returned by `ulimit -n`. This image is based on Ubuntu, which has a [known issue regarding a large limit](https://bugs.launchpad.net/ubuntu/+source/apt/+bug/1332440). The workaround was to `docker run` with `--ulimit nofile=8192:8192`.
</div>
{::options parse_block_html="false" /}

## Sending and evaluating shell commands

Initially I thought of having the body of the message be the command, while attachments could be files passed as input. To simplify, I figured that commands taking files could just as well take a `<(printf 'foo')`. In the end, the request was entirely contained in the body.

To which address is it sent? This container is running as `root`, and the hostname is `mailsh.localdomain`, so the sender needs to associate that name with the docker container's IP:
{% raw %}
```bash
mailsh_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mailsh)
echo "$mailsh_ip mailsh.localdomain" >> /etc/hosts
```
{% endraw %}

Now we can send a mail with `mailx`:

```bash
echo 'To: root <root@mailsh.localdomain>
From: foo <foo@localhost>
Subject: Test '"$(date +%s)"'

This is a test email message' | \
    mailx \
        -v \
        -S 'smtp=smtp://mailsh.localdomain' \
        -S 'smtp-auth-user=test' \
        -S 'smtp-auth-password=test' \
        -S 'from=foo@localhost' \
        -t
```

We can confirm it hits `postfix` with `docker exec -it mailsh tail -f /var/log/syslog`:
```
mailsh postfix/qmgr[151]: EAA3D207C96: from=<foo@localhost>, size=563, nrcpt=1 (queue active)
```

To deal with binary contents, we can encode the command with `uuencode`, which takes a file and outputs ASCII text:

```bash
(
echo 'To: root <root@mailsh.localdomain>
From: foo <foo@localhost>
Subject: Test '"$(date +%s)"'

Please run me :)'

uuencode "$request_command_file" "$request_attachment_name"
) | \
    mailx \
    # ...
```

On the server side, we want to:
- Be notified of new mails in `root`'s mailbox;
- Decode the command;
- Evaluate the command.

Since `postfix` stores this user's mailbox as a file at `/var/mail/root`, we simply need to keep track of filesystem events, in this case file writes.

A common solution is `inotifywatch`, but I prefer to use `entr`. It has a [more robust handling of events when compared to the former](http://eradman.com/entrproject/), such as interpreting a file delete followed by a new file as a file save.

{::options parse_block_html="true" /}
<div class="c-indirectly-related">
`entr` is also affected by a large file descriptor limit issue, although expressed with a cryptic segmentation fault. Here are the `strace` dumps of `echo 1 | /opt/strace entr ls`, between large and small limits:

With 1073741816:
```strace
setrlimit(RLIMIT_NOFILE, {rlim_cur=1073741816, rlim_max=1073741816}) = 0
brk(0)                                  = 0x56402e5b7000
brk(0x56402e5d8000)                     = 0x56402e5d8000
mmap(NULL, 8589934592, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1 ENOMEM (Out of memory)
brk(0x56422e5d8000)                     = 0x56402e5d8000
mmap(NULL, 8590069760, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1 ENOMEM (Out of memory)
mmap(NULL, 134217728, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0) = 0x7fb54357c000
munmap(0x7fb54357c000, 11026432)        = 0
munmap(0x7fb548000000, 56082432)        = 0
mprotect(0x7fb544000000, 135168, PROT_READ|PROT_WRITE) = 0
mmap(NULL, 8589934592, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1 ENOMEM (Out of memory)
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0} ---
+++ killed by SIGSEGV (core dumped) +++
Segmentation fault (core dumped)
```

With 1024:
```strace
setrlimit(RLIMIT_NOFILE, {rlim_cur=1024, rlim_max=1024}) = 0
brk(0)                                  = 0x5641e1d2e000
brk(0x5641e1d4f000)                     = 0x5641e1d4f000
inotify_init()                          = 3
fstat(0, {st_mode=S_IFIFO|0600, st_size=0, ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f482ad5d000
read(0, "1\n", 4096)                    = 2
stat("1", {st_mode=S_IFREG|0644, st_size=0, ...}) = 0
read(0, "", 4096)                       = 0
open("1", O_RDONLY)                     = 4
inotify_add_watch(3, "1", IN_MODIFY|IN_CLOSE_WRITE|IN_DELETE_SELF) = 1
```
</div>
{::options parse_block_html="false" /}

Decoding and evaluating will be done by our script `watch.sh`:

```bash
# Temporary storage for decoded commands
tmp_mail_dir=$(mktemp -d)
tmp_mail_name=$(mktemp --tmpdir="$tmp_mail_dir")
cleanup() {
  err=$?
  sudo rm -rf "$tmp_mail_dir"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

(
  cd "$tmp_mail_dir"

  # Retrieve request (i.e. most recent mail)
  echo "w $ $tmp_mail_name" | mailx
  uudecode "$tmp_mail_name"

  # Evaluate request
  bash request.txt > response-stdout.txt

  # Send response
  printf '%s\n' \
    'replysender $' \
    "$(cat response-stdout.txt)" | mailx
)
```

Which will be activated like this:

```bash
# `entr` exits if file doesn't exist
touch /var/mail/root

echo /var/mail/root | entr /opt/mailsh-watch.sh
```

Given that our base image already uses [`supervisord`](http://supervisord.org/index.html) to launch and monitor processes, we might as well make use of it:

```bash
supervisor_program=watch
cat > "/etc/supervisor/conf.d/$supervisor_program.conf" <<EOF
[program:$supervisor_program]
command=/bin/bash -c 'echo /var/mail/root | entr /opt/watch.sh'
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
EOF
```

## Validating the user making a request

Right now anyone can send a command and have it be evaluated by the superuser. We need some way of making sure that the user making the request is trusted.

I settled on using `gpg`: The user cryptographically signs their request with their own private key, and the server checks the signature against one of it's stored public keys. If:
- command isn't signed, then request is <span class="c-badge c-badge-nok">rejected</span>;
- command is signed by an unrecognized key, then request is <span class="c-badge c-badge-nok">rejected</span>;
- command is signed by a recognized key, then request is <span class="c-badge c-badge-ok">accepted</span>.

The sender can generate their `gpg` key pair with the following script:
```bash
. ./request.env

tmp_parameters_file=$(mktemp)
cleanup() {
  err=$?
  sudo rm -f "$tmp_parameters_file"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

cat >"$tmp_parameters_file" <<EOF
Key-Type: RSA
Key-Length: 4096
Subkey-Type: ELG-E
Subkey-Length: 4096
Name-Real: $REQUEST_USER
Name-Comment: Test
Name-Email: $REQUEST_MAIL
Expire-Date: 0
Passphrase: test
EOF

gpg --batch --yes --gen-key "$tmp_parameters_file"
gpg --output test.gpg --armor --export "$REQUEST_MAIL"
```

The public key is copied over to the container during build and added with `gpg --import` during execution.

In the request script, the command is signed:
```bash
request_name=$(basename "$request_command_file")
request_attachment_name="$request_name.asc"

rm -f "$request_attachment_name"
gpg \
  --output "$request_attachment_name" \
  --local-user "$REQUEST_USER" \
  --armor \
  --sign "$request_name"

# ...

uuencode "$request_attachment_name" "$request_attachment_name"
```

Finally, on `watch.sh`, the signature is verified:
```bash
# Validate and evaluate request
if gpg --output script.sh --decrypt request.txt.asc; then
    bash script.sh > response-stdout.txt
else
    echo "[ERROR] Invalid signature in request." > response-stdout.txt
fi
```

## Enforcing email authentication to pass spam filtering

This is a cross-cutting concern that has to be accounted for in mail servers, otherwise our sent mails will be blocked or disposed in the spam folder.

Usually this means configuring the following: SMTP over TLS, SPF, DKIM, DMARC...

Unfortunately, this is impractical to accomplish in a "free as in free beer" manner on your local system:
- A DNS name is required for DNS records. There are dynamic DNS solutions that allow you to associate a name to a dynamic IP. Most free offers don't allow you to configure TXT records[^2]. Two of them allow it: [DuckDNS](https://www.duckdns.org) and [FreeDNS](https://freedns.afraid.org/). However, the former only allows you to set one, which is shared among all subdomains, while the latter has SPF restricted;
- Furthermore, dynamic DNS will fail on reverse DNS checks, since they resolve to your ISP's hostname. A PTR record can be published, but again, can be restricted by most free offers;
- Even if you manage to find one service that allows multiple values for any records you need, you are at the mercy of the IP provided by your ISP. Most likely, it is present in some spam blacklist, because it was part of some botnet or whatever. You will be greeted by nice messages in your `postfix` log, such as:
```
550 5.7.1 Service unavailable, Client host [148.69.37.212] blocked using Spamhaus. To request removal from this list see https://www.spamhaus.org/query/ip/148.69.37.212 (AS3130). [BN3NAM01FT023.eop-nam01.prod.protection.outlook.com] (in reply to MAIL FROM command))
```

[^2]: Some are even deliberately ambiguous in their support, forcing you to register an account only to then inform you that you need a paid account to create those records.

These challenges require you to have your own Virtual Private Server (VPS). Nevertheless, our docker image has everything set up so that most remaining configuration will be confined to DNS records.

### TLS

Covered by Let's Encrypt. To generate certificates we used [`dehydrated`](https://github.com/lukas2511/dehydrated). The DNS challenge is preferred because it can be done in your local system, since all you need is a dynamic DNS service that allows setting a TXT record.

Generating the SSL certificates (and renaming them with suffixes expected by `postfix`) was automated as part of a `Makefile`:
```make
ssl-generated-dir := dehydrated/certs/$(MAILSH_DOMAIN)
ssl-dir := $(shell readlink -f assets/ssl)
ssl-obj := \
	$(ssl-dir)/$(MAILSH_DOMAIN).key \
	$(ssl-dir)/$(MAILSH_DOMAIN).fullchain.crt
$(ssl-obj):
	rm -rf dehydrated
	git clone --depth=1 https://github.com/lukas2511/dehydrated
	echo "$(MAILSH_DOMAIN)" > assets/dehydrated/domains.txt
	cp assets/dehydrated/* dehydrated/
	# `|| true`: Ignoring unknown hook errors
	cd dehydrated && \
		chmod 755 hook.sh && \
		chmod +x dehydrated && \
		./dehydrated --register  --accept-terms && \
		./dehydrated -c || true
	mkdir -p $(ssl-dir)
	cp $(ssl-generated-dir)/privkey.pem $(ssl-dir)/$(MAILSH_DOMAIN).key
	cp $(ssl-generated-dir)/fullchain.pem $(ssl-dir)/$(MAILSH_DOMAIN).fullchain.crt
```

For SSL verification, we need to serve HTTPS with a web server at port 443. We used `caddy`, configuring it to serve TLS with our previously generated certificates:
```
tls /etc/postfix/certs/mailsh.duckdns.org.fullchain.crt /etc/postfix/certs/mailsh.duckdns.org.key
```

`caddy` is also managed by `supervisord`:
```bash
supervisor_program=caddy
cat > "/etc/supervisor/conf.d/$supervisor_program.conf" <<EOF
[program:$supervisor_program]
command=/opt/caddy -agree=true -conf /opt/Caddyfile -log stdout -port 443
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
EOF
```

We can test if our certificates have been successfully applied with `openssl s_client -connect mailsh.duckdns.org:443 -servername mailsh.duckdns.org`:
```
CONNECTED(00000003)
depth=2 O = Digital Signature Trust Co., CN = DST Root CA X3
verify return:1
depth=1 C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
verify return:1
depth=0 CN = mailsh.duckdns.org
verify return:1
---
Certificate chain
 0 s:CN = mailsh.duckdns.org
   i:C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
 1 s:C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
   i:O = Digital Signature Trust Co., CN = DST Root CA X3
```

### SPF

Applied with the following TXT record:
```
v=spf1 a include:_spf.google.com ~all
```

Verified in the following reply mail header field:
```
Authentication-Results: mx.google.com;
   spf=pass (google.com: domain of root@mailsh.duckdns.org designates 148.69.37.212 as permitted sender) smtp.mailfrom=root@mailsh.duckdns.org
```

### DKIM

Handled by `opendkim`, which [was accounted for in our base image](https://github.com/catatnight/docker-postfix/blob/b1a2dad2d3e49be52b73f74b9f96d0a4263db024/assets/install.sh). The only difference is that generating and copying the domain key is done as part of the container execution:
```bash
# Instead of passing a DKIM private key,
# generate it in the container and copy it
# to the target directory checked by
# `install.sh` from `catatnight/postfix`
opendkim-genkey -s mail -d "$MAILSH_DOMAIN"
mkdir -p /etc/opendkim/domainkeys
mv mail.private /etc/opendkim/domainkeys
mv mail.txt /opt/
```

We can retrieve the value of the DKIM DNS record from the container (in this example, it is set in DuckDNS):
```bash
txt=$(docker exec -it mailsh cat /opt/mail.txt | \
    sed 's/.*"\([a-z]=\)/\1/; s/".*//' | \
    tr -d '\r\n' | \
    node -p 'encodeURIComponent(require("fs").readFileSync(0))') && \
    curl "https://www.duckdns.org/update?domains=mail._domainkey.mailsh&token=$TOKEN&txt=$txt&verbose=true"
```

When the message is signed successfully, `postfix` logs:
```
Aug 28 19:23:39 mailsh opendkim[141]: 1ACD52069AA: DKIM-Signature field added (s=mail, d=mailsh.duckdns.org)
```

Verified in the following reply mail header field:
```
Authentication-Results: mx.google.com;
   dkim=pass header.i=@mailsh.duckdns.org header.s=mail header.b="J/N1GMIX";
```

## Source code

Available in a [git repository](https://github.com/nevesnunes/mailsh).

## Further work

- To enable more complex parsing of new mail, we could consider [`procmail`](http://porkmail.org/era/procmail/mini-faq.html). Right now, it is assumed no other changes are done to the mailbox file besides adding new mails (e.g. we could delete previous ones), and that each file write maps to a single new mail (otherwise, requests that arrived before the most recent one would be skipped);
- DMARC and some TLS configuration were skipped since DNS records couldn't be reliably applied, it would be nice to include them when everything is tested in a VPS.

## References

- [Newsletters spam test by mail\-tester\.com](https://www.mail-tester.com)
- [How to set up a mail server on a GNU / Linux system](https://flurdy.com/docs/postfix/)
- [How To Install and Configure DKIM with Postfix on Debian Wheezy \| DigitalOcean](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [Sender Guidelines \- Gmail Help](https://support.google.com/mail/answer/81126?hl=en)
- [My emails are going to spam SPF, DKIM are set PASS \- Gmail Help](https://support.google.com/mail/thread/6350893?hl=en)
