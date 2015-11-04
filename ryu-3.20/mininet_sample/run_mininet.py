#!/usr/bin/env python

import sys

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.node import OVSSwitch

if '__main__' == __name__:
    CONTROLLER_IP='127.0.0.1'
    net = Mininet(switch=OVSSwitch, controller=RemoteController)

    c0 = net.addController('c0', controller=RemoteController, ip=CONTROLLER_IP)

    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')

    net.addLink(s1, s2)
    net.addLink(s1, s2)
    net.addLink(s1, s2)

    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])

    s1.cmd('ovs-vsctl set Bridge s1 protocols=OpenFlow13')
    s2.cmd('ovs-vsctl set Bridge s2 protocols=OpenFlow13')

    CLI(net)

    net.stop()
