import os
from mininet.net import Containernet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.node import RemoteController
from mininet.node import Docker
from p4_mininet import P4Switch, P4Host
 
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
    net = Containernet(host = P4Host, link=TCLink, controller = None)
    switch1 = net.addSwitch('s1', sw_path = args.behavioral_exe, json_path = args.json, thrift_port = args.thrift_port, cls = P4Switch, pcap_dump = args.pcap_dump)                  
    host1 = net.addHost('h1', mac = '00:00:00:00:01:01',  ip="10.0.1.1/24")
    host2 = net.addDocker('h2', mac = '00:00:00:00:02:02', ip="10.0.2.2/24", dimage="apache-php-mysql:v7",cpu_period=50000, cpu_quota=1000)
    host3 = net.addDocker('h3', mac = '00:00:00:00:03:03', ip="10.0.3.3/24", dimage="apache-php-mysql:v7",cpu_period=50000, cpu_quota=1000)
    host4 = net.addDocker('h4', mac = '00:00:00:00:04:04', ip="10.0.4.4/24", dimage="apache-php-mysql:v7",cpu_period=50000, cpu_quota=1000)
    host5 = net.addDocker('h5', mac = '00:00:00:00:05:05', ip="10.0.5.5/24", dimage="apache-php-mysql:v7",cpu_period=50000, cpu_quota=1000)
    net.addLink(host1, switch1, port1 = 0, port2 = 1, cls=TCLink, bw=10)
    net.addLink(host2, switch1, port1 = 0, port2 = 2, cls=TCLink, bw=10)
    net.addLink(host3, switch1, port1 = 0, port2 = 3, cls=TCLink, bw=10)
    net.addLink(host4, switch1, port1 = 0, port2 = 4, cls=TCLink, bw=10)
    net.addLink(host5, switch1, port1 = 0, port2 = 5, cls=TCLink, bw=10)        
    net.start()
    h1,h2,h3,h4,h5=net.get('h1','h2','h3','h4','h5')
    h1.cmd("arp -s 10.0.1.254 00:00:00:01:01:01")
    h1.cmd("ip route add default via 10.0.1.254")
    h2.cmd("arp -s 10.0.2.254 00:00:00:02:02:02")
    h2.cmd("ip route del default")
    h2.cmd("ip route add default via 10.0.2.254")
    h2.cmd("cd /var/www/html; echo h2 > a.htm ; python -m SimpleHTTPServer 80 &")
    h3.cmd("arp -s 10.0.3.254 00:00:00:03:03:03")
    h3.cmd("ip route del default")
    h3.cmd("ip route add default via 10.0.3.254")
    h3.cmd("cd /var/www/html; echo h3 > a.htm ; python -m SimpleHTTPServer 80 &")
    h4.cmd("arp -s 10.0.4.254 00:00:00:04:04:04")
    h4.cmd("ip route del default")
    h4.cmd("ip route add default via 10.0.4.254")
    h4.cmd("cd /var/www/html; echo h4 > a.htm; python -m SimpleHTTPServer 80 &")
    h5.cmd("arp -s 10.0.5.254 00:00:00:05:05:05")
    h5.cmd("ip route del default")
    h5.cmd("ip route add default via 10.0.5.254")
    h5.cmd("ethtool -K h5-eth0 tx off rx off")

    #Assume h5 is down
    #h5.cmd("cd /var/www/html; echo h5 > a.htm; python -m SimpleHTTPServer 80 &")
    sleep(1)
    os.system('sudo /home/vagrant/behavioral-model/targets/simple_switch/simple_switch_CLI --thrift-port=9090 < cmd.txt')
    #disable health check, enable health check: remove #
    #os.system("sudo /home/p4/mytest/p4-ConnectionHash/check_server.sh &>/dev/null &")

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
        os.system("kill `cat check_server.pid`")
        print('\033[0;32m'),
        print ('Stop successfully!')
        print('\033[0m')

if __name__ == '__main__':
    setLogLevel('info')
    main()
