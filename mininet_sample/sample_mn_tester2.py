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
    net = Mininet(switch=OVSSwitch, controller=RemoteController)

    c0 = net.addController('c0')

    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')

    net.addLink(s1, s2)
    net.addLink(s1, s2)
    net.addLink(s1, s2)

    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])

    #if conf.switch in ['ovs', 'ovs13']:
    s1.cmd('ovs-vsctl set Bridge s1 protocols=OpenFlow13')
    s2.cmd('ovs-vsctl set Bridge s2 protocols=OpenFlow13')

    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()
