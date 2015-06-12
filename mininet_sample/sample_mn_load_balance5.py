#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def myNet():
    CONTROLLER1_IP='127.0.0.1'
    
    CONTROLLER2_IP='127.0.0.1'

    net = Mininet( topo=None, build=False)

    # Create server
    sr1 = net.addHost( 'sr1', mac='01:00:00:00:01:00', ip='192.168.2.10/24' )
    sr2 = net.addHost( 'sr2', mac='01:00:00:00:02:00', ip='192.168.2.11/24' )
    #server3 = net.addHost( 'server3', mac='01:00:00:00:03:00', ip='192.168.1.12/24' )
    
    # Create office
    of1 = net.addHost( 'of1', mac='01:00:00:00:04:00', ip='192.168.1.10/24' )
    of2 = net.addHost( 'of2', mac='01:00:00:00:05:00', ip='192.168.3.10/24' )
    of3 = net.addHost( 'of3', mac='01:00:00:00:06:00', ip='192.168.4.10/24' )
    # Create router
    router1 = net.addSwitch( 's1', listenPort=6634, mac='00:00:00:00:00:01' )
    router2 = net.addSwitch( 's2', listenPort=6644, mac='00:00:00:00:00:02' )

    print "*** Creating links"
    net.addLink(sr1, router2 )
    net.addLink(sr2, router2 )   
    net.addLink(of1, router1 )   
    net.addLink(of2, router1 )   
    net.addLink(of3, router1 )   
    net.addLink(router1, router2)   

    # Add Controllers
    c0 = net.addController( 'c0', controller=RemoteController, ip=CONTROLLER1_IP, port=6633)
    c1 = net.addController( 'c1', controller=RemoteController, ip=CONTROLLER2_IP, port=6643)

    net.build()

    # Connect each switch to a different controller
    router1.start([c1])
    router1.cmdPrint('ovs-vsctl set Bridge s1 protocols=OpenFlow13')
    
    router2.start([c0])
    router2.cmdPrint('ovs-vsctl set Bridge s1 protocols=OpenFlow13')

    sr1.cmd('route add default gw 192.168.2.1')
    sr2.cmd('route add default gw 192.168.2.1')
    of1.cmd('route add default gw 192.168.1.1')
    of2.cmd('route add default gw 192.168.3.1')
    of3.cmd('route add default gw 192.168.4.1')

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()

