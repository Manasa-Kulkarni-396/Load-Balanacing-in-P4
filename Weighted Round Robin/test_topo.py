import os
from mininet.net import  Containernet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import Docker
from p4_mininet import P4Switch, P4Host
from mininet.link import TCLink

import argparse
from time import sleep
parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required=False, default='simple_switch' )
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--num-hosts', help='Number of hosts to connect to switch',
                    type=int, action="store", default=2)
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)
args = parser.parse_args()

def main():
    net = Containernet(host = P4Host, controller = None, link=TCLink)
    switch1 = net.addSwitch('s1', sw_path = args.behavioral_exe, json_path = args.json, thrift_port = args.thrift_port, cls = P4Switch, pcap_dump = args.pcap_dump)
    host1 = net.addHost('h1', mac = '00:00:00:00:01:01', ip="10.0.1.1/24")
    host2 = net.addHost('h2', mac = '00:00:00:00:02:02', ip="10.0.2.2/24")
    host3 = net.addHost('h3', mac = '00:00:00:00:03:03', ip="10.0.3.3/24")

    net.addLink(host1, switch1, port1 = 0, port2 = 1)
    net.addLink(host2, switch1, port1 = 0, port2 = 2)
    net.addLink(host3, switch1, port1 = 0, port2 = 3)

    net.start()
    h1,h2,h3=net.get('h1','h2','h3')
    h1.cmd("arp -s 10.0.1.254 00:00:00:01:01:01")
    h1.cmd("ip route add default via 10.0.1.254")
    h1.cmd("ethtool -K eth0 tx off rx off")

    h2.cmd("arp -s 10.0.2.254 00:00:00:02:02:02")
    h2.cmd("ip route del default")
    h2.cmd("ip route add default via 10.0.2.254")
    h2.cmd("ethtool -K h2-eth0 tx off rx off")
    h2.cmd("/etc/init.d/php7.2-fpm start")
    h2.cmd("mysqld_safe --skip-grant-tables &")
    h2.cmd("/etc/init.d/apache2 start")

    h3.cmd("arp -s 10.0.3.254 00:00:00:03:03:03")
    h3.cmd("ip route del default")
    h3.cmd("ip route add default via 10.0.3.254")
    h3.cmd("ethtool -K h3-eth0 tx off rx off")
    h3.cmd("/etc/init.d/php7.2-fpm start")
    h3.cmd("mysqld_safe --skip-grant-tables &")
    h3.cmd("/etc/init.d/apache2 start")

    sleep(1)
    print('\033[0;32m'),
    print "Gotcha!"
    print('\033[0m')
    CLI(net)
    try:
        net.stop()
    except:
        print('\033[0;31m'),
        print('Stop error! Trying sudo mn -c')
        print('\033[0m')
        os.system('sudo mn -c')
        print('\033[0;32m'),
        print ('Stop successfully!')
        print('\033[0m')

if __name__ == '__main__':
    setLogLevel('info')
    main()
