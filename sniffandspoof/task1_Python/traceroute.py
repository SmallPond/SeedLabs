
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
    
    print ans, unans
    
    if ans.res[0][1].type == 0:
	isGetDis = True
    else:
        i += 1
        mTTL += 1
print ('Get The Distance from VM to ip:%s ,%d '%(ip_dst, i))
