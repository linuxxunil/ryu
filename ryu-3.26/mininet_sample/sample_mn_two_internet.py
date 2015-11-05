#!/usr/bin/env python
import os
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import Intf
from mininet.log import setLogLevel, info
 
def myNetwork():

    CONTROLLER1_IP='127.0.0.1'
 
    net = Mininet( topo=None, build=False)
 
    info( '*** Add hosts\n')
    h1 = net.addHost('h1', ip='192.168.11.1')
    h2 = net.addHost('h2', ip='192.168.11.2')
 
    s1 = net.addSwitch('s1')
    Intf( 'eth0', node=s1 )
    
    info( '*** Add links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    
    c0 = net.addController( 'c0', controller=RemoteController, ip=CONTROLLER1_IP, port=6633)

    net.build()
    s1.start([c0])

    CLI( net )
    net.stop()
 
if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
