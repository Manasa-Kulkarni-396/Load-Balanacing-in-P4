#!/usr/bin/env python
import sys
import struct

from scapy.utils import *
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
i=0

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def handle_pkt(pkt):
    global i
    i+=1
    print "got a packet:" + str(i)
    pkt.show2()
    sys.stdout.flush()

def main():
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
