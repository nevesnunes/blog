---
layout: page
title: About
permalink: /about/
---

A showcase of interesting debugging sessions and other technical writeups related to software development or security challenges.

From these case studies, we can extract:

- Reusable [methodologies]({{ site.baseurl }}/tags/#methodologies) to apply in similar scenarios;
- Disclosed information that can spark new bug reports or patches. Consider how oftentimes interface errors are aggravated by insufficient, misleading, or unintended messages.

## Inspiration

#### Computer Security

- [GoogleCTF 2022 \- eldar \(333 pt / 14 solves\)](https://ctf.harrisongreen.me/2022/googlectf/eldar/)
- [34c3 CTF minbashmaxfun writeup](https://medium.com/@orik_/34c3-ctf-minbashmaxfun-writeup-4470b596df60)
- [Solving warsaw&\#8217;s Java Crackme 3 &\#8211; ReWolf&\#039;s blog](http://blog.rewolf.pl/blog/?p=856)
- [Reddish \- HackTheBox Writeup \- IppSec](https://www.youtube.com/watch?v=Yp4oxoQIBAM)
- [Fuzzing Browsers for weird XSS Vectors \- LiveOverflow](https://www.youtube.com/watch?v=yq_P3dzGiK4)
- [Hacking with Environment Variables](https://www.elttam.com/blog/env/)
- [x86matthew \- Exploiting a Seagate service to create a SYSTEM shell \(CVE\-2022\-40286\)](https://www.x86matthew.com/view_post?id=windows_seagate_lpe)
- [Kernel Pwning with eBPF: a Love Story](https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story)
- [Project Zero: Down the Rabbit\-Hole\.\.\.](https://googleprojectzero.blogspot.com/2019/08/down-rabbit-hole.html)

#### Data Analysis

- [24\-core CPU and I can't move my mouse](https://randomascii.wordpress.com/2017/07/09/24-core-cpu-and-i-cant-move-my-mouse/)
- [Active Benchmarking: bonnie\+\+](https://www.brendangregg.com/ActiveBenchmarking/bonnie++.html)
- [Analysing Petabytes of Websites](https://tech.marksblogg.com/petabytes-of-website-data-spark-emr.html)
- [Using FOIA Data and Unix to halve major source of parking tickets](https://mchap.io/using-foia-data-and-unix-to-halve-major-source-of-parking-tickets.html)
- [Battelle Publishes Open Source Binary Visualization Tool](https://inside.battelle.org/blog-details/battelle-publishes-open-source-binary-visualization-tool)
- [How to Implement a Simple USB Driver for FreeBSD](https://freebsdfoundation.org/wp-content/uploads/2021/11/Simple_USB_Driver_for_FreeBSD.pdf)
- [Wireshark visualization TIPS & tricks by Megumi Takeshita \- SharkFest'19](https://sharkfestus.wireshark.org/assets/presentations19/28-37.pdf)
- [Visualizing Commodore 1541 Disk Contents – Part 2: Errors - pagetable\.com](https://www.pagetable.com/?p=1356)
- [Unraveling The JPEG](https://parametric.press/issue-01/unraveling-the-jpeg/)

#### Systems Programming

- [Debugging memory corruption: who the hell writes “2” into my stack?! \- Unity Technologies Blog](https://blogs.unity3d.com/2016/04/25/debugging-memory-corruption-who-the-hell-writes-2-into-my-stack-2/)
- [Tracking down a segfault in grep](https://blog.loadzero.com/blog/tracking-down-a-segfault-in-grep/)
- [Debugging an evil Go runtime bug \- marcan\.st](https://marcan.st/2017/12/debugging-an-evil-go-runtime-bug/)
    - [runtime: memory corruption crashes with os/exec on Linux kernel 4\.4 · Issue \#20427 · golang/go · GitHub](https://github.com/golang/go/issues/20427)
- [Hunting down a non\-determinism\-bug in our Rust Wasm build](https://dev.to/gnunicorn/hunting-down-a-non-determinism-bug-in-our-rust-wasm-build-4fk1)
- [USB Debugging and Profiling Techniques](https://elinux.org/images/1/17/USB_Debugging_and_Profiling_Techniques.pdf)
- [The select story \- removal of a compiler optimization](https://aqjune.github.io/posts/2021-10-4.the-select-story.html)
- [The hunt for the cluster\-killer Erlang bug \| by Dániel Szoboszlay \| Klarna Engineering](https://engineering.klarna.com/the-hunt-for-the-cluster-killer-erlang-bug-81dd0640aa81?gi=6ba3d3b0c54f)

#### Contraptions Programming

- [GIF MD5 hashquine \- Rogdham](https://www.rogdham.net/2017/03/12/gif-md5-hashquine.en)
- [Polyglot Assembly \- vojtechkral\.github\.io](https://vojtechkral.github.io/blag/polyglot-assembly/)
- [Palindromic 64 bit ELF binaries](https://n0.lol/bggp/writeup.html)
- [mov is Turing-complete](https://drwho.virtadpt.net/files/mov.pdf)
- [codemix/ts\-sql: A SQL database implemented purely in TypeScript type annotations \- GitHub](https://github.com/codemix/ts-sql)
- [sed maze solver \- GitHub](https://gist.github.com/xsot/99a8a4304660916455ba2c2c774e623a)
- [AES in Scratch](https://scratch.mit.edu/projects/555156198/)

#### Yak Shaving

- [Rabbit Holes: The Secret to Technical Expertise](http://blog.bityard.net/articles/2019/August/rabbit-holes-the-secret-to-technical-expertise.html)
- [blog_deploy_yak_shave.md](https://gist.github.com/trptcolin/3353806872d367819f0709c4607acbb8)
- [Everything I googled in a week as a professional software engineer](https://localghost.dev/2019/09/everything-i-googled-in-a-week-as-a-professional-software-engineer/)

#### Development Challenges

- **Sorting paginated search results** for a web interface. These results were retrieved from multiple databases, running distinct database engines. It would be highly inefficient to retrieve the full result sets in a single request.
    - The solution I developed was to **asynchronously perform, for each database, a ranged sql query**. At the application level, we **merged and sorted the result sets** of these queries. If we returned back to the web interface some results of a given database, we would increment and cache the corresponding range offset, so that **requesting the next page would fetch the next ranged result set**.
    - I found this challenge interesting due to implementing an algorithm from scratch for a complex use case which was not contemplated by the frameworks we were using.
- **Managing an application's lifecycle** with the service manager `systemd`. When the process was stopped with our service, some **subprocesses did not perform a clean shutdown**, and a manual subprocess start was required. However, stopping the application manually resulted in all subprocesses successfully shutting down.
    - The root cause was found while comparing the system calls between the two shutdown procedures. The service sent a kill signal to the parent process and each child, while the manual stop only sent a kill to the parent process, which in turn sent network requests to each subprocess containing a command to gracefully shutdown. After reconfiguring the service to **only send a kill signal to the parent process**, the issue was solved.
    - I found this challenge interesting due to requiring low-level analysis, since there were no evidences for this behaviour in typical indicators such as application logs.
- **Running applications in distinct hosts**, although they did not have support for this scenario. An endpoint of an `application (host A)` returned an address for `another application in the sub-network (host B)`. This address was consumed by both `A` and an `external application in a VPN network (host C)`. A sub-network address couldn't be resolved by `C`, while a VPN network address couldn't be resolved by host `A`.
    - The solution I applied was to add a **NAT OUTPUT rule in the firewall of the endpoint host**, causing locally-generated packets to a given IP and port in the VPN network range to be sent to a sub-network IP and port instead. This allowed `A` to communicate with `B`, while setting an address reachable by `C`.
    - I found this challenge interesting due to requiring cross-cutting knowledge in networking, allowing us to continue using our applications in the scenario we needed.

#### More...

- Debugging: [Methodologies](https://github.com/nevesnunes/env/blob/master/common/code/cheats/debug.md#methodologies), [Case Studies](https://github.com/nevesnunes/env/blob/master/common/code/cheats/debug.md#case-studies)
- Reverse Engineering: [Methodologies](https://github.com/nevesnunes/env/blob/master/common/code/cheats/reversing.md#methodologies), [Case Studies](https://github.com/nevesnunes/env/blob/master/common/code/cheats/reversing.md#case-studies)

## Source code

Available in a [git repository](https://github.com/nevesnunes/blog/tree/gh-pages). Feel free to [share any suggestions](https://github.com/nevesnunes/blog/issues).
