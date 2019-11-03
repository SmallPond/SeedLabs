#!/bin/bin/python
#Author	Alexey Titov
#version 1.2

from scapy.all import *

a = IP()
a.dst = '8.8.8.8'
b = ICMP()
flag = True
ttl = 1
hops = []
#traceroute
while flag:
	a.ttl = ttl
	ans, unans = sr(a/b)
	#checking for ICMP echo-reply
	if ans.res[0][1].type == 0:
		flag = False
	#storing the src ip from ICMP error message
	else:
		hops.append(ans.res[0][1].src)
		ttl+=1
i = 1
for hop in hops:
	print i," " + hop
	i+=1
