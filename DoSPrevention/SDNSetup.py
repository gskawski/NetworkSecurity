# cnetlab3v1.py

from mininet.net import Containernet
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel

setLogLevel('info')

# Glenn Skawski: Mininet topology

net = Containernet(controller=RemoteController, switch=OVSSwitch)
info('*** Adding controller\n')
net.addController('c0', ip='127.0.0.1', port=6655)

info('*** Adding docker containers\n')
h1 = net.addHost('h1', ip='192.168.2.10/24', mac='00:00:00:00:00:01', dimage="ubuntu:trusty")
h2 = net.addHost('h2', ip='192.168.2.20/24', mac='00:00:00:00:00:02', dimage="ubuntu:trusty")
h3 = net.addHost('h3', ip='192.168.2.30/24', mac='00:00:00:00:00:03', dimage="ubuntu:trusty")
h4 = net.addHost('h4', ip='192.168.2.40/24', mac='00:00:00:00:00:04', dimage="ubuntu:trusty")


info('*** Adding switches\n')
s1 = net.addSwitch('s1')

info('*** Creating links\n')
net.addLink(h1, s1)
net.addLink(h2, s1)
net.addLink(h3, s1)
net.addLink(h4, s1)

info('*** Starting network\n')
net.start()
'''
info('*** Testing connectivity\n')
net.ping([d1, d2])
'''
CLI(net)
'''
info('*** Stopping network')
net.stop()
'''
