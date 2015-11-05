#!/usr/bin/env python
""" Required test network:

       +-----+                  +-----+
       | PC1 |                  | PC2 |     
       +-----+                  +-----+                     
          |                        |
    +------------+           +------------+
    |  Network A |           |  Network B |     
    +------------+           +------------+                     
         |       \          /        |   
    +----+      +------------+       +----+
    |DHCP|      |   switch   |       |DHCP|
    +----+      +------------+       +----+
                 /          \  
    +------------+           +------------+
    |  Staff     |           |  Customer  |     
    +------------+           +------------+

"""
import sys
import os

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
    
    net1 = net.addSwitch('net1')
    net2 = net.addSwitch('net2')
    net1_dhcp = net.addHost( 'net1_dhcp', ip='192.168.1.2/16' )
    net1_h1 = net.addHost( 'net1_h1', ip='10.0.0.2/24' )
    net2_dhcp = net.addHost( 'net2_dhcp', ip='192.168.2.2/16' )
    net2_h1 = net.addHost( 'net2_h1', ip='11.0.0.2/24' )
    
    stf1 = net.addHost( 'stf1', mac='00:00:00:00:03:00')
    cus1 = net.addHost( 'cus1', mac='00:00:00:00:04:00' )
   
    net.addLink(net1, net1_dhcp)
    net.addLink(net1, net1_h1)
    net.addLink(net2, net2_dhcp)
    net.addLink(net2, net2_h1)
    net.addLink(net1, s1, addr1="00:00:00:00:01:00")
    net.addLink(net2, s1, addr1="00:00:00:00:02:00")
    net.addLink(stf1, s1)
    net.addLink(cus1, s1)

    c0 = net.addController('c0', controller=RemoteController, ip=CONTROLLER1_IP, port=6633)
    c1 = net.addController('c1', controller=RemoteController, ip=CONTROLLER1_IP, port=6644)

    net.build()
    s1.start([c0])
    net1.start([c1])
    net2.start([c1])


    #if conf.switch in ['ovs', 'ovs13']:
    s1.cmd('ovs-vsctl set Bridge s1 protocols=OpenFlow13')
    net1.cmd('ovs-vsctl set Bridge s1 protocols=OpenFlow13')
    net2.cmd('ovs-vsctl set Bridge s1 protocols=OpenFlow13')

    net1_dhcp.cmd('route add default gw 192.168.1.1 ; dhcpd -cf /etc/dhcpd.conf --no-pid')
    net1_h1.cmd('route add default gw 10.0.0.1')
    net2_dhcp.cmd('route add default gw 192.168.2.1 ; dhcpd -cf /etc/dhcp/dhcpd.conf --no-pid')
    net2_h1.cmd('route add default gw 11.0.0.1')

    s1.cmdPrint('./sample_rest_cust_net_switch.sh')

    cus1.cmd('ip addr flush dev cus1-eth0')
    stf1.cmd('ip addr flush dev stf1-eth0')
    CLI(net)

    net.stop()

    os.system('killall dhcpd ')
    os.system('killall dhclient ')
if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()
