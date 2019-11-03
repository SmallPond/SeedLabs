网络安全课上接触到SeedProject，强调动手做安全实验，拒绝纸上谈兵 -> `talk is cheap, Show me the code`；拒绝脚本小子，做到知其然，知其所以然。在这边向大家推荐一波，毕竟这么好的平台不能一个人独享（hhhh...）。

市面上很多网络安全书籍都是互相"借鉴"，同时也只是在原理上描述了现存攻击的方式与原理。但我认为网络与计算机安全方面的内容，如果只是枯燥的阅读书籍是很容易遗忘而且不能即时获得一种成就感。雪城大学Wenliang Du教授认识到这一点，推出[SeedProject](https://seedsecuritylabs.org/index.html)。这个网站提供了一个预建的Ubuntu16.04虚拟机映像，很多实验环境都已经预装好了。[这里有教你怎么配置实验环境](https://seedsecuritylabs.org/lab_env.html)。


这里不仅仅只有关于网络安全的实验，还有系统安全（我觉得这个最有意思）、软件安全甚至还有安卓安全等等。

这个平台很大的一个亮点是，它提供了一个比较详细的实验文档，对于简单难度的Lab基本跟着文档就能在明白原理的前提下过完整个Lab，大家可以先try一下简单的Lab。不定期更新（逃...。

- 网络安全
    - Packet Sniffing and Spoofing Lab（包嗅探与欺骗）
    - ARP Cache Poisoning Attack Lab （ARP缓存攻击）
    - TCP/IP Attack Lab （利用 TCP/IP 缺陷攻击）
    - Heartbleed Attack Lab
    - Local DNS Attack Lab （本地DNS攻击，相对简单）
    - Remote DNS Attack Lab （远端DNS攻击，相对难度高一点）
    - Linux Firewall Exploration Lab
    - Firewall-VPN Lab -- Bypassing Firewalls using VPN
    - Virtual Private Network (VPN) Lab（这个实验难度很大）
- 系统安全
    - Meltdown Attack Lab（利用CPU的漏洞，乱序执行，Cache特性，个人感觉十分有意思）
    - Spectre Attack Lab