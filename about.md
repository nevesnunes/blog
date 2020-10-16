---
layout: page
title: About
permalink: /about/
---

A showcase of interesting debugging sessions and other technical writeups related to software development or security challenges.

Oftentimes, errors are aggravated by unhelpful or misleading messages. We can take these cases as opportunities to reflect on disclosed information and possible improvements to the interfaces under study, which could lead to opening issues on a bug tracker or submitting patches.

## Inspiration

Computer Security
- [CTFtime.org \| Writeups](https://ctftime.org/writeups)
- [IppSec \| HackTheBox Writeups](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)
- [34c3 CTF minbashmaxfun writeup](https://medium.com/@orik_/34c3-ctf-minbashmaxfun-writeup-4470b596df60)
- [Solving warsaw&\#8217;s Java Crackme 3 &\#8211; ReWolf&\#039;s blog](http://blog.rewolf.pl/blog/?p=856)
- [nullsecurity\.org/articles \- "crackmes\.one : noverify's GraxCode's Java CrackMe 1"](http://www.nullsecurity.org/article/crackmes_one_noverify_graxcode_java_crackme_1)
- [Fuzzing Browsers for weird XSS Vectors \- LiveOverflow](https://www.youtube.com/watch?v=yq_P3dzGiK4)

Data Analysis
- [24\-core CPU and I can't move my mouse](https://randomascii.wordpress.com/2017/07/09/24-core-cpu-and-i-cant-move-my-mouse/)
- [Analysing Petabytes of Websites](https://tech.marksblogg.com/petabytes-of-website-data-spark-emr.html)
- [Using FOIA Data and Unix to halve major source of parking tickets](https://mchap.io/using-foia-data-and-unix-to-halve-major-source-of-parking-tickets.html)
- [Battelle Publishes Open Source Binary Visualization Tool](https://inside.battelle.org/blog-details/battelle-publishes-open-source-binary-visualization-tool)
- [Wireshark visualization TIPS & tricks by Megumi Takeshita \- SharkFest'19](https://sharkfestus.wireshark.org/assets/presentations19/28-37.pdf)
- [Visualizing Commodore 1541 Disk Contents – Part 2: Errors - pagetable\.com](https://www.pagetable.com/?p=1356)

Systems Programming
- [Debugging memory corruption: who the hell writes “2” into my stack?! \- Unity Technologies Blog](https://blogs.unity3d.com/2016/04/25/debugging-memory-corruption-who-the-hell-writes-2-into-my-stack-2/)
- [Tracking down a segfault in grep](https://blog.loadzero.com/blog/tracking-down-a-segfault-in-grep/)
- [Debugging an evil Go runtime bug \- marcan\.st](https://marcan.st/2017/12/debugging-an-evil-go-runtime-bug/)
    - [runtime: memory corruption crashes with os/exec on Linux kernel 4\.4 · Issue \#20427 · golang/go · GitHub](https://github.com/golang/go/issues/20427)

Yak Shaving
- [blog_deploy_yak_shave.md](https://gist.github.com/trptcolin/3353806872d367819f0709c4607acbb8)
- [Lobsters \| What's your current yak-shaving depth?](https://lobste.rs/s/ngswph/what_s_your_current_yak_shaving_depth)
- [Rabbit Holes: The Secret to Technical Expertise](http://blog.bityard.net/articles/2019/August/rabbit-holes-the-secret-to-technical-expertise.html)
- [Everything I googled in a week as a professional software engineer](https://localghost.dev/2019/09/everything-i-googled-in-a-week-as-a-professional-software-engineer/)

Development Challenges
- We wanted to implement **sorted and paginated search results** for a web interface. These results were retrieved from multiple databases, running distinct database engines. It would be highly inefficient to retrieve the full result sets in a single request.
    - The solution I developed was to **asynchronously perform, for each database, a ranged sql query**. At the application level, we **merged and sorted the result sets** of these queries. If we returned back to the web interface some results of a given database, we would increment and cache the corresponding range offset, so that **requesting the next page would fetch the next ranged result set**.
    - I found this challenge interesting due to implementing an algorithm from scratch for a complex use case which was not contemplated by the frameworks we were using.
- We wanted to **manage an application's lifecycle** with the service manager `systemd`. When the process was stopped with our service, some **subprocesses did not perform a clean shutdown**, while stopping the application manually resulted in all subprocesses successfully shutting down.
    - The root cause was found while comparing the system calls between the two shutdown procedures. The service sent a kill signal to the parent process and each child, while the manual stop only sent a kill to the parent process, which in turn sent network requests to each subprocess containing a command to gracefully shutdown. After reconfiguring the service to **only send a kill signal to the parent process**, the issue was solved.
    - I found this challenge interesting due to requiring low-level analysis, since there were no evidences for this behaviour in typical indicators such as application logs.
- We wanted to **run an application in a separate sub-network**, although it did not have support for this scenario. An endpoint of this application (`A`) returned an address for another application in the sub-network (`B`). This address was consumed by both `A` and an external application in a VPN network (`C`). Setting a sub-network address couldn't be resolved by host `C`, while setting a VPN network address couldn't be resolved by host `A`.
    - The solution I applied was to add a **NAT OUTPUT rule in the firewall of the endpoint host**, causing locally-generated packets to a given IP and port in the VPN network range to be sent to a sub-network IP and port instead. This allowed `A` to communicate with `B`, while setting an address reachable by `C`.
    - I found this challenge interesting due to requiring cross-cutting knowledge in networking, allowing us to continue using our applications in the scenario we needed.

## Source code

Available in a [git repository](https://github.com/nevesnunes/blog/tree/gh-pages). Feel free to open an issue if you want to leave a comment.
