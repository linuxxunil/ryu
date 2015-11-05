#!/usr/bin/env python

import sys

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.node import OVSSwitch
from oslo.config import cfg
from ryu import version

def myNet():
    CONTROLLER1_IP='127.0.0.1'

    net = Mininet(switch=OVSSwitch, controller=RemoteController)

    s1 = net.addSwitch('s1')

    net.addLink(node1=s1, port1=1, node2=s1, port2=2)
    net.addLink(node1=s1, port1=3, node2=s1, port2=4)
    net.addLink(node1=s1, port1=5, node2=s1, port2=6)

    c0 = net.addController('c0', controller=RemoteController, ip=CONTROLLER1_IP, port=6633)

    net.build()
    c0.start()
    s1.start([c0])

    #if conf.switch in ['ovs', 'ovs13']:
    s1.cmd('ovs-vsctl set Bridge s1 protocols=OpenFlow13')

    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()
