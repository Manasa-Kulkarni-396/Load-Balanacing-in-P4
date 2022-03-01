#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink

def topology():
    "Create a network."
    net = Mininet()
    print "*** Creating nodes"
    h1 = net.addHost( 'h1', mac='00:00:00:00:00:01', ip='192.168.10.1/24')
    h2 = net.addHost( 'h2', mac='00:00:00:00:00:02', ip='192.168.20.1/24' )
    h3 = net.addHost( 'h3', mac='00:00:00:00:00:03')
    h4 = net.addHost( 'h4', mac='00:00:00:00:00:04')
    h5 = net.addHost( 'h5', mac='00:00:00:00:00:05')

    print "*** Creating links"
    Link(h1, h3, intfName1='h1-eth0', intfName2='h3-eth0')
    Link(h2, h5, intfName1='h2-eth0', intfName2='h5-eth0')
    Link(h3, h4, intfName1='h3-eth1', intfName2='h4-eth0')
    Link(h4, h5, intfName1='h4-eth1', intfName2='h5-eth1')
    net.build()

    h3.cmd("sudo ifconfig h3-eth0 0")
    h3.cmd("sudo ifconfig h3-eth1 0")
    h4.cmd("sudo ifconfig h4-eth0 0")
    h4.cmd("sudo ifconfig h4-eth1 0")
    h5.cmd("sudo ifconfig h5-eth0 0")
    h5.cmd("sudo ifconfig h5-eth1 0")
    h3.cmd("sudo echo 1 > /proc/sys/net/ipv4/ip_forward")
    h4.cmd("sudo echo 1 > /proc/sys/net/ipv4/ip_forward")
    h5.cmd("sudo echo 1 > /proc/sys/net/ipv4/ip_forward")
    h3.cmd("sudo ifconfig h3-eth0 192.168.10.254 netmask 255.255.255.0")
    h5.cmd("sudo ifconfig h5-eth0 192.168.20.254 netmask 255.255.255.0")
    h3.cmd("sudo ifconfig h3-eth1 34.1.1.3 netmask 255.255.255.0")
    h4.cmd("sudo ifconfig h4-eth0 34.1.1.4 netmask 255.255.255.0")
    h4.cmd("sudo ifconfig h4-eth1 45.1.1.4 netmask 255.255.255.0")
    h5.cmd("sudo ifconfig h5-eth1 45.1.1.5 netmask 255.255.255.0")
 
    #configure gre tunnel
    h3.cmd("sudo ip tunnel add netb mode gre remote 45.1.1.5 local 34.1.1.3 ttl 255")
    h3.cmd("sudo ip addr add 12.1.1.1/24 dev netb")
    h3.cmd("sudo ifconfig netb up")
    h3.cmd("sudo ip route add 192.168.20.0/24 via 12.1.1.1")
    h5.cmd("sudo ip tunnel add neta mode gre remote 34.1.1.3 local 45.1.1.5 ttl 255")
    h5.cmd("sudo ip addr add 12.1.1.2/24 dev neta")
    h5.cmd("sudo ifconfig neta up")

    h5.cmd("sudo ip route add 192.168.10.0/24 via 12.1.1.2")
    h1.cmd("sudo ip route add default via 192.168.10.254")
    h2.cmd("sudo ip route add default via 192.168.20.254")
    h3.cmd("sudo ip route add default via 34.1.1.4")
    h5.cmd("sudo ip route add default via 45.1.1.4")

    print "*** Running CLI"
    CLI( net )

    print "*** Stopping network"
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
