#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.utils import *
from scapy.all import *
import readline


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

def main():
    if len(sys.argv)<2:
        print 'pass 2 arguments: <destination>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print "sending on interface %s to %s" % (iface, str(addr))
    k=1
    while k<20:
        print
        data = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + struct.pack('!I', k)
        pkt =  Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:02')
        data = "\x01" + "\x00\x00\x00\x00\x00" + data
        a=Raw(load=data)
        pkt = pkt / IP(dst=addr) / UDP(dport=4321, sport=1234)/a
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
        k+=1
        print "send out:" + str(k) + "th packet"

if __name__ == '__main__':
    main()
