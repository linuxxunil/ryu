#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def myNet():
    #OpenDayLight controller
    CONTROLLER1_IP='127.0.0.1'

    #Floodlight controller

    net = Mininet( topo=None, build=False)

    # Create nodes
    h1 = net.addHost( 'h1', mac='00:01:02:03:04:05', ip='192.168.0.1/24' )
    h2 = net.addHost( 'h2', mac='00:01:02:03:04:06', ip='192.168.0.2/24' )

    # Create switches
    s1 = net.addSwitch( 's1', listenPort=6634, mac='00:00:00:00:00:01' )
    
    print "*** Creating links"
    net.addLink(h1, s1 )
    net.addLink(h2, s1 )
  

    # Add Controllers
    c0 = net.addController( 'c0', controller=RemoteController, ip=CONTROLLER1_IP, port=6633)

    net.build()

    # Connect each switch to a different controller
    s1.start([c0])

    s1.cmdPrint('ovs-vsctl show')
    
    h1.cmd('vconfig add h1-eth0 100;ip addr add 192.168.1.1/24 dev h1-eth0.100; ifconfig h1-eth0.100 up')
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()

