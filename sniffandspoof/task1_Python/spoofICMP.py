from scapy.all import *

a = IP()
a.dst = "10.0.2.129"
a.src = "192.168.0.1"
b = ICMP()

p = a/b

send(p)

